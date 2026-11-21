// Package libexec puts the embedded anchor pair on disk so it can be run.
//
// The directory is content-addressed: <state>/bin/<setID>/, where setID names both
// binaries and the platform. That one decision removes four separate problems at
// once. An upgraded conflux writes a new directory instead of over the file a
// running anchord has open, so there is no ETXTBSY on Unix and no sharing violation
// on Windows. Two conflux processes racing produce the same path. A stale set is
// identifiable and sweepable. And "is it already extracted" is two stats rather
// than a read of tens of megabytes on every invocation: setID is stamped at build time
// (anchor.Digests).
//
// It is emphatically not os.TempDir(), which fails four ways for a service: systemd's
// PrivateTmp= gives the service a different /tmp than the CLI, so each extracts a
// copy the other cannot see; /tmp is noexec on hardened hosts; systemd-tmpfiles
// deletes it under a running daemon; and a LocalSystem service's %TEMP% is
// C:\Windows\Temp.
package libexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths"
)

// smokeTimeout bounds the one-off check that the extracted binary actually runs.
const smokeTimeout = 10 * time.Second

// lockWait bounds how long Remake waits for bin's lock, which an extraction in progress holds: as long as
// that may smoke-run its set. A variable so a test can wait less.
var lockWait = smokeTimeout

// Tools are the extracted pair.
type Tools struct {
	Dir       string
	Anchord   string
	Anchorctl string
	SetID     string
}

// Extract extracts this build's pair under d if it is not already there, and returns the paths,
// for a caller that has made d's roots already (EnsureAll), the bin directory with them -- the
// supervisor and an ephemeral run as they start, wintun's, which puts its DLL beside the anchord it
// extracts, and the wait of a command that has just started the service. It makes neither a root nor
// the bin directory, only the set in it (extractIn). Idempotent, atomic, and safe against another
// conflux doing the same thing; where the pair is there, two stats and nothing more.
func Extract(d paths.Dirs) (*Tools, error) {
	t, err := Extracted(d)
	if !errors.Is(err, ErrNotExtracted) {
		return t, err
	}

	return extractIn(d)
}

// Remake empties d's bin directory -- every set, this build's among them, whatever a crashed
// extraction left staged, and anything else put there -- and extracts this build's pair afresh
// (Extract), for an update, with nothing running from any of them: so that nothing an earlier
// conflux made there, nor anything put among it, is kept or run. Under bin's lock, which an
// extraction in progress holds, and which it waits for, up to lockWait: a reader's extraction, the
// first after an upgrade, takes tens of milliseconds. On Windows, which removes no file anybody has
// open, the lock is then removed too where nothing has opened it since, so it is made again as well;
// on Unix it is kept, since a lock is taken on the file its name led to when it was opened, and one
// waited for on a file removed meanwhile would be held beside one taken on the file made again at its
// name. d's roots are made already (EnsureAll), the bin directory with them, which stays. It is the
// paths of what it removed from bin, however far it got (paths.ClearExcept).
func Remake(d paths.Dirs) ([]string, error) {
	if !anchor.Supported {
		return nil, errUnsupported
	}

	root := d.Libexec()
	lock := filepath.Join(root, ".lock")

	unlock, ok, err := flock.TryAcquire(lock)
	for deadline := time.Now().Add(lockWait); err == nil && !ok && time.Now().Before(deadline); {
		unlock, ok, err = flock.TryAcquire(lock)
	}

	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("another conflux is extracting the anchor binaries in %s, and has not finished in %v; run "+
			"this again once it has", root, lockWait)
	}

	removed, err := paths.ClearExcept(root, lock)

	unlock()

	if err != nil {
		return removed, fmt.Errorf("empty %s: %w", root, err)
	}

	// Let go of first, since Windows will not delete a file that is open: a lock somebody opened
	// meanwhile stays, which Extract then takes as it is.
	flock.Drop(lock)

	_, err = Extract(d)

	return removed, err
}

// extractIn is Extract once a look found no whole extraction under d: the set directory made in the bin
// directory, under bin's lock, and nothing else. A bin directory not there -- one uninstall removed
// meanwhile, with its root -- is an error, and is not made again.
func extractIn(d paths.Dirs) (*Tools, error) {
	t := toolsIn(d)

	unlock, err := flock.Acquire(filepath.Join(d.Libexec(), ".lock"))
	if err != nil {
		return nil, err
	}
	defer unlock()

	// Another process may have finished while we waited for the lock.
	if t.complete() {
		return t, nil
	}

	if err := extract(t); err != nil {
		return nil, err
	}

	return t, nil
}

// toolsIn is where this build's pair is, or would be, extracted under d.
func toolsIn(d paths.Dirs) *Tools {
	setID := anchor.SetID()

	return toolsAt(filepath.Join(d.Libexec(), setID), setID)
}

// toolsAt is set setID's pair laid out in dir: its set directory, or the staging directory a
// set is written in before it takes that name.
func toolsAt(dir, setID string) *Tools {
	return &Tools{
		Dir:       dir,
		Anchord:   filepath.Join(dir, exeName("anchord")),
		Anchorctl: filepath.Join(dir, exeName("anchorctl")),
		SetID:     setID,
	}
}

// ErrNotExtracted is a pair Extracted did not find whole.
var ErrNotExtracted = errors.New("the anchor binaries are not extracted there")

// errUnsupported is a build that carries no anchor pair, as a placeholder build does.
var errUnsupported = errors.New(
	"this conflux was built for " + runtime.GOOS + "/" + runtime.GOARCH + " and carries no anchor binaries for it")

// Extracted is this build's pair under d when a whole extraction of it is there, and
// writes nothing: for a root another process owns -- an ephemeral run's -- which a reader
// must not fill while its owner may be clearing it.
func Extracted(d paths.Dirs) (*Tools, error) {
	if !anchor.Supported {
		return nil, errUnsupported
	}

	t := toolsIn(d)
	if !t.complete() {
		return nil, ErrNotExtracted
	}

	return t, nil
}

// ForUsage is the anchorctl a reader runs -- help, a status, a renew, a pass-through -- and done, which
// removes it where it is a temporary copy, and is nil where it is not. checked is the readers' check of
// the installation's roots d (paths.Dirs.Check), which the caller holds, before anything in them is read
// by its name. Where it passed, this build's pair extracted there is used (Extracted), as found: nobody
// else can put anything in a root as conflux makes one. Where it is not extracted yet -- as once an
// upgrade has put a newer conflux in place -- it is extracted there (extractIn), into the bin directory,
// provided that folder is there and as conflux makes it (paths.Dirs.OursFolder): that adds a set and
// removes none, so a service still running an older one keeps it, and makes neither a root nor the bin
// directory. Anything else -- no installation, roots the check refused, a bin directory not there or not
// as conflux makes it, an extraction that fails -- runs a copy in a private temporary directory
// (temporary), with nothing in d read.
func ForUsage(d paths.Dirs, checked error) (bin string, done func(), err error) {
	if checked == nil {
		t, err := Extracted(d)
		if errors.Is(err, ErrNotExtracted) && d.OursFolder(d.Libexec()) == nil {
			t, err = extractIn(d)
		}

		if err == nil {
			return t.Anchorctl, nil, nil
		}
	}

	return temporary()
}

// temporary is a copy of this build's anchorctl in a private temporary directory, with nothing of any
// root's read, which done removes, the directory with it: made where temporaryDir makes it -- for an
// elevated process on Windows a folder of its own in %ProgramData%, and otherwise in the user's temporary
// directory (usersTemporaryDir) -- and restricted as it says. Never a root of conflux's, nor a folder in
// one. Making them for help remade, after an uninstall, what it had removed, with tens of megabytes in
// it; and on Windows, asked by an account that is not an administrator, it left %ProgramData%\conflux
// owned by that account, which every later install then refused.
func temporary() (bin string, done func(), err error) {
	if !anchor.Supported {
		return "", nil, errUnsupported
	}

	dir, restrict, err := temporaryDir()
	if err != nil {
		return "", nil, err
	}

	bin = filepath.Join(dir, exeName("anchorctl"))
	if err := writeExecutable(bin, anchor.Anchorctl(), true, restrict); err != nil {
		_ = os.RemoveAll(dir)

		return "", nil, err
	}

	return bin, func() { _ = os.RemoveAll(dir) }, nil
}

// temporaryPrefix begins the name of the directory temporary makes.
const temporaryPrefix = "conflux-usage-"

// usersTemporaryDir makes the directory temporary writes in, as the account running conflux: in the
// system's temporary directory, or, where that one is mounted noexec as /tmp is on a hardened host, in
// the user's cache directory, made if it is not there yet. No other directory is made.
func usersTemporaryDir() (string, error) {
	candidates := []string{os.TempDir()}

	cache, err := os.UserCacheDir()
	if err == nil {
		candidates = append(candidates, cache)
	}

	parent, err := paths.FirstExecutable(candidates, nil)
	if errors.Is(err, paths.ErrNoExec) {
		return "", fmt.Errorf("every temporary directory is on a filesystem mounted noexec, so the anchorctl "+
			"conflux runs could not run from it: %v.\n  Set TMPDIR to a directory on one that is not", candidates)
	}

	if err != nil {
		return "", err
	}

	// The user's cache directory is the user's own, and one a fresh account has not made yet is
	// made. The system's temporary directory is not conflux's to make: one that is missing is
	// an error, as it is to everything else that writes there.
	if parent == cache {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return "", err
		}
	}

	return os.MkdirTemp(parent, temporaryPrefix+"*")
}

// complete reports whether the directory holds a finished extraction of exactly this
// pair: both binaries, each at its size.
//
// Their presence is enough because a set directory only ever appears whole: extract
// renames it in from a staging directory once both binaries in it were written, synced
// and run. The sizes catch a binary truncated or replaced since, and a name a power cut
// lost from the directory, whose own entries are not synced. One that fails is extracted
// again. Who wrote them is not asked: every caller has made d's roots (EnsureAll) or held
// them to the readers' check (Dirs.Check) first -- ForUsage, and an ephemeral run's reader,
// which checks the run's root before it takes the pair there -- and nobody else can put
// anything in a root as conflux makes one.
func (t *Tools) complete() bool {
	return whole(t.Anchord, len(anchor.Anchord())) && whole(t.Anchorctl, len(anchor.Anchorctl()))
}

func whole(path string, size int) bool {
	fi, err := os.Stat(path)

	return err == nil && fi.Size() == int64(size)
}

// stagingPrefix begins the name of every staging directory makeStaging makes, which Sweep tells
// from a set by it.
const stagingPrefix = ".staging-"

// extract writes t's pair into a staging directory beside its set directory, runs it there,
// and only then renames it into place.
func extract(t *Tools) error {
	root, target := filepath.Dir(t.Dir), t.Dir

	staging, err := makeStaging(root, stagingPrefix)
	if err != nil {
		return fmt.Errorf("create a staging directory in %s: %w", root, err)
	}

	defer os.RemoveAll(staging) // no-op once the rename has moved it

	// The set directory under another name: the same binaries, modes, owner and DACL,
	// quarantine cleared, which the rename keeps.
	staged := toolsAt(staging, t.SetID)

	// Side by side: each is its own file and its own fsync, and on a real disk the
	// fsync is most of what an extraction costs.
	var (
		wg     sync.WaitGroup
		ctlErr error
	)

	wg.Go(func() {
		ctlErr = writeExecutable(staged.Anchorctl, anchor.Anchorctl(), false, paths.Restrict)
	})

	err = writeExecutable(staged.Anchord, anchor.Anchord(), false, paths.Restrict)

	wg.Wait()

	if err := errors.Join(err, ctlErr); err != nil {
		return err
	}

	// Run before it takes its name, and so only once: whatever finds a set under its name takes
	// it as whole and never runs it, so one that will not run -- or whose run was interrupted --
	// would otherwise fail every start with a bare "permission denied", where this says why.
	if err := smokeRun(staged); err != nil {
		return err
	}

	if err := os.Rename(staging, target); err != nil {
		// Another conflux won the race between our lock check and here, which is
		// possible across a network filesystem where the lock is advisory only.
		if t.complete() {
			return nil
		}

		// Or the target exists and is incomplete: a binary truncated or removed since,
		// one another account owns on Windows, or a power cut that kept the rename and
		// lost a name inside the directory. Rename will not replace a non-empty
		// directory, so the debris has to go first. Safe here because we hold the lock,
		// and because an incomplete set is by definition one nothing is running from.
		if _, statErr := os.Stat(target); statErr == nil {
			if rmErr := os.RemoveAll(target); rmErr != nil {
				return fmt.Errorf("replace the incomplete extraction at %s: %w", target, rmErr)
			}

			if err := os.Rename(staging, target); err != nil {
				return fmt.Errorf("install %s: %w", target, err)
			}

			return nil
		}

		return fmt.Errorf("install %s: %w", target, err)
	}

	return nil
}

// writeExecutable writes one binary, restricts it with restrict, and closes it before anyone can
// exec it: one of a set's, or, oneRun, the copy temporary makes to run once and remove.
//
// The Close is not tidiness. On Linux, exec of a file that is still open for writing
// anywhere in the system fails with ETXTBSY, and a deferred Close inside a loop is
// exactly how that bug is usually written.
func writeExecutable(path string, content []byte, oneRun bool, restrict func(string, bool) error) error {
	prefault(content)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}

	if _, err := f.Write(content); err != nil {
		f.Close()

		return fmt.Errorf("write %s: %w", path, err)
	}

	// A set outlives this process, so it is on disk before it is renamed into place. The
	// copy for one run is gone before anything could need it to survive a power cut.
	if !oneRun {
		if err := f.Sync(); err != nil {
			f.Close()

			return fmt.Errorf("sync %s: %w", path, err)
		}
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}

	// Only Windows restricts a file; elsewhere it is a no-op. A set's binaries are the machine's,
	// SYSTEM's and the Administrators', as everything under the root is (paths.Restrict); a copy for
	// one run is restricted as temporaryDir says.
	if err := restrict(path, false); err != nil {
		return fmt.Errorf("restrict %s: %w", path, err)
	}

	// macOS marks files written by a quarantined process, and an inherited
	// quarantine on a binary a daemon execs is a dialog nobody will ever see.
	clearQuarantine(path)

	return nil
}

// prefault reads one byte of every page of b, so the embedded binary is mapped in before
// the write that copies it out.
//
// The pair is part of this executable and is paged in on first touch. Touched here, in a
// pass of reads, the kernel maps the pages in batches around each fault; touched by the
// write instead, it takes them one at a time inside the copy, which made a cold extraction
// about half as slow again once nothing read the pair beforehand.
func prefault(b []byte) {
	var x byte

	for i := 0; i < len(b); i += pageSize {
		x ^= b[i]
	}

	touched.Store(uint32(x)) // kept, so the reads cannot be compiled away
}

var (
	pageSize = os.Getpagesize()
	touched  atomic.Uint32
)

// smokeRun is smoke, a variable only so a test can stand in for it.
var smokeRun = smoke

// smoke runs the extracted anchorctl once, in its staging directory, so that a filesystem
// which will not execute it says so here rather than at the point a daemon fails to start.
//
// What it says names the directory every set is extracted beneath, not the staging directory,
// which is gone once this fails: what stops a binary running there -- the filesystem's mount, a
// policy's label, a scanner's exclusion -- is that directory's.
func smoke(t *Tools) error {
	ctx, cancel := context.WithTimeout(context.Background(), smokeTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, t.Anchorctl, "help").CombinedOutput()
	if err == nil {
		return nil
	}

	bin := filepath.Dir(t.Dir)

	// A bare "permission denied" on a 0700 file owned by the caller is the most
	// confusing failure in this whole design, so name the two things that cause it.
	if errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "permission denied") {
		return fmt.Errorf("%s\n%s", cannotExecute(bin), strings.TrimSpace(string(out)))
	}

	return fmt.Errorf("the anchorctl extracted beneath %s did not run: %w\n%s",
		bin, err, strings.TrimSpace(string(out)))
}

// Sweep removes the sets other than t, and the debris of an extraction that crashed.
//
// Only the supervisor calls it, once it holds its own set. Any other conflux extracting
// a set of its own -- the first `status` after an upgrade -- may be standing beside a
// supervisor that still runs an older conflux and execs that one's anchorctl for every
// renewal and every check; the service restarting onto the new set is what ends its use
// of the old. Best-effort throughout: a directory that will not go is probably in use.
func Sweep(t *Tools) {
	root, keep := filepath.Dir(t.Dir), t.SetID

	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}

	cutoff := time.Now().Add(-24 * time.Hour)

	for _, e := range entries {
		if !e.IsDir() || e.Name() == keep {
			continue
		}

		info, err := e.Info()
		if err != nil {
			continue
		}

		// A staging directory older than an hour is the debris of a crash.
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			if info.ModTime().Before(time.Now().Add(-time.Hour)) {
				os.RemoveAll(filepath.Join(root, e.Name()))
			}

			continue
		}

		if info.ModTime().Before(cutoff) {
			os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}

func exeName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}

	return base
}
