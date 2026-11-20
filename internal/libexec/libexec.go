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

// Tools are the extracted pair.
type Tools struct {
	Dir       string
	Anchord   string
	Anchorctl string
	SetID     string
}

// Ensure extracts this build's pair if it is not already there, and returns the
// paths. Idempotent, atomic, and safe against another conflux doing the same thing.
func Ensure(d paths.Dirs) (*Tools, error) {
	if !anchor.Supported {
		return nil, errUnsupported
	}

	root := d.Libexec()
	t := toolsIn(d)

	// The hot path: every conflux invocation reaches here, including a bare
	// pass-through, so it is two stats and nothing more.
	if t.complete() {
		return t, nil
	}

	// The directories every other conflux command makes, secured as they are made: on
	// Windows the root takes %ProgramData%'s DACL, which lets Users create folders in it,
	// until something gives it its own, and a pass-through or a status may be the first
	// conflux to run here.
	if err := d.EnsureAll(); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", root, err)
	}

	unlock, err := flock.Acquire(filepath.Join(root, ".lock"))
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

// ForUsage is an anchorctl to ask what a command takes, for help that must leave nothing
// behind: this build's, extracted under d, where a whole extraction is there and readable,
// and otherwise a copy in a private temporary directory, which done removes -- in the
// system's temporary directory, or, where that one is mounted noexec as /tmp is on a hardened
// host, in the user's cache directory, made if it is not there yet. No other directory is
// made, and never d's own. Making them for help remade, after an uninstall, what it had
// removed, with tens of megabytes in it; and on Windows, asked by an account that is not an
// administrator, it left %ProgramData%\conflux owned by that account, which every later
// install then refused.
func ForUsage(d paths.Dirs) (bin string, done func(), err error) {
	switch t, err := Extracted(d); {
	case err == nil:
		return t.Anchorctl, func() {}, nil
	case !errors.Is(err, ErrNotExtracted):
		return "", nil, err
	}

	candidates := []string{os.TempDir()}

	cache, err := os.UserCacheDir()
	if err == nil {
		candidates = append(candidates, cache)
	}

	parent, err := paths.FirstExecutable(candidates, nil)
	if errors.Is(err, paths.ErrNoExec) {
		return "", nil, fmt.Errorf("every temporary directory is on a filesystem mounted noexec, so the anchorctl "+
			"help runs could not run from it: %v.\n  Set TMPDIR to a directory on one that is not", candidates)
	}

	if err != nil {
		return "", nil, err
	}

	// The user's cache directory is the user's own, and one a fresh account has not made yet is
	// made. The system's temporary directory is not conflux's to make: one that is missing is
	// an error, as it is to everything else that writes there.
	if parent == cache {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return "", nil, err
		}
	}

	dir, err := os.MkdirTemp(parent, "conflux-usage-")
	if err != nil {
		return "", nil, err
	}

	bin = filepath.Join(dir, exeName("anchorctl"))
	if err := writeExecutable(bin, anchor.Anchorctl(), true); err != nil {
		_ = os.RemoveAll(dir)

		return "", nil, err
	}

	return bin, func() { _ = os.RemoveAll(dir) }, nil
}

// complete reports whether the directory holds a finished extraction of exactly this
// pair: both binaries, each at its size.
//
// Their presence is enough because a set directory only ever appears whole: extract
// renames it in from a staging directory once both binaries in it were written, synced
// and run. The sizes catch a binary truncated or replaced since, and a name a power cut
// lost from the directory, whose own entries are not synced.
//
// And on Windows, that a trusted owner wrote them -- this account, SYSTEM or the
// Administrators -- since a set directory is named for content anybody can compute, and
// one another account made first, sizes and all, would otherwise be run as SYSTEM. One
// that fails any of this is extracted again.
func (t *Tools) complete() bool {
	return ours(t.Anchord, len(anchor.Anchord())) && ours(t.Anchorctl, len(anchor.Anchorctl()))
}

func ours(path string, size int) bool {
	fi, err := os.Stat(path)

	return err == nil && fi.Size() == int64(size) && paths.Trusted(path)
}

// extract writes t's pair into a staging directory beside its set directory, runs it there,
// and only then renames it into place.
func extract(t *Tools) error {
	root, target := filepath.Dir(t.Dir), t.Dir

	staging, err := os.MkdirTemp(root, ".staging-*")
	if err != nil {
		return fmt.Errorf("create a staging directory in %s: %w", root, err)
	}

	defer os.RemoveAll(staging) // no-op once the rename has moved it

	if err := paths.Restrict(staging, true); err != nil {
		return fmt.Errorf("restrict %s: %w", staging, err)
	}

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
		ctlErr = writeExecutable(staged.Anchorctl, anchor.Anchorctl(), false)
	})

	err = writeExecutable(staged.Anchord, anchor.Anchord(), false)

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

// writeExecutable writes one binary and closes it before anyone can exec it: one of a set's,
// or, oneRun, the copy ForUsage runs once and removes.
//
// The Close is not tidiness. On Linux, exec of a file that is still open for writing
// anywhere in the system fails with ETXTBSY, and a deferred Close inside a loop is
// exactly how that bug is usually written.
func writeExecutable(path string, content []byte, oneRun bool) error {
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

	// Only Windows restricts a file; elsewhere both are no-ops. A set's binaries are the
	// machine's, SYSTEM's and the Administrators', as everything under the root is. A copy for
	// one run is the account running it as well: help may be asked by one that is not an
	// administrator, which Restrict's DACL would not let execute what it had just written.
	restrict := paths.Restrict
	if oneRun {
		restrict = paths.RestrictToOwner
	}

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
		if strings.HasPrefix(e.Name(), ".staging-") {
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
