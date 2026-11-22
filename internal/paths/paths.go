// Package paths is every filesystem path conflux uses, decided in one place.
//
// conflux is system-scoped: one configuration per machine, root-owned, with no
// home directory anywhere in it. That is a decision rather than an oversight. The
// boot service runs as root or LocalSystem, so a path under $HOME is a path the
// service cannot read, and a home directory is wrong under a unit with User=, wrong
// under ProtectHome=, and wrong for anyone who ran conflux with sudo -H.
//
// One folder, DirName, holds all of it, on every platform, in the system's data folder
// (SystemData): the root (Dirs.Root). What the operator asked for and what conflux derived, the
// identity among it, are files in the root itself; inside it, the run directory (RunDir) holds the
// socket, the token and the readiness marker, which the supervisor clears of what a run before it left
// as it starts, and the log directory (LogDir) the boot service's output, on the platforms where it goes
// to a file.
package paths

import (
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
)

// Dirs is where conflux keeps everything: one root, and every path derived from it. Get one from
// Default, or an ephemeral run's from EphemeralDirs.
type Dirs struct {
	// Root is the one folder conflux keeps everything in, DirName.
	Root string

	// ephemeral is whether these are an ephemeral run's (EphemeralDirs), which runs as whoever starts
	// it and no service ever serves; every other Dirs is an installation's, whose root the boot
	// service serves, so it is judged for it (ours).
	ephemeral bool

	// serving is whether EnsureServing is making these, for the supervisor that serves them, which leaves
	// the copy of conflux it runs from alone.
	serving bool
}

// RuntimeFolder is the folder this account's ephemeral run keeps its root in, or why there is none:
// Linux's alone (ephemeral_linux.go), the one platform that runs one, and nil elsewhere. A variable so a
// test can keep it in a folder of its own (pathstest).
var RuntimeFolder func() (string, error)

// IsEphemeral reports whether d are an ephemeral run's (EphemeralDirs, on Linux).
func (d Dirs) IsEphemeral() bool { return d.ephemeral }

// Default is where conflux keeps them: DirName, in the system's data folder (SystemData).
func Default() Dirs { return rootedAt(filepath.Join(SystemData(), DirName)) }

// SystemData is the folder the installation's root, DirName, is in (systemData): /var/lib on Linux,
// /var/db on the BSDs, /Library/Application Support on macOS, %ProgramData% on Windows, which is the
// system's, never changed and never judged. A variable so a test can keep an installation in a folder of
// its own (pathstest).
var SystemData = systemData

// DirName is the folder conflux makes in the system's data folder and keeps all of its own in: the
// configuration and the state, and its run and log directories inside it.
const DirName = ".conflux"

// rootedAt is the Dirs of an installation rooted in the one directory root.
func rootedAt(root string) Dirs { return Dirs{Root: root} }

// RunDir is the run directory, inside the root: the socket, the token and the readiness marker, which the
// supervisor clears of what a run before it left as it starts.
func (d Dirs) RunDir() string { return filepath.Join(d.Root, "run") }

// LogDir is where the boot service's output goes, inside the root, on the platforms where it goes to a
// file (logsToFile): "" where journald or syslog keeps it, as nothing would write there, and for an
// ephemeral run, whose output goes to the terminal it runs in.
func (d Dirs) LogDir() string {
	if !logsToFile || d.ephemeral {
		return ""
	}

	return filepath.Join(d.Root, "logs")
}

// socketName is anchord's control socket, an AF_UNIX socket on every platform, inside a
// directory of anchord's own (DaemonRun). Short, since sun_path is 104 bytes on macOS and a
// test's root under /var/folders is already most of that.
const socketName = "sock"

// ConfigFile holds the operator's intent: mode, taints, addresses, proxies.
func (d Dirs) ConfigFile() string { return filepath.Join(d.Root, "conflux.json") }

// StateFile holds what conflux derived: the AnchorID, the credential window, which
// extracted binary set is live. Most of it is re-learned at the next start; see
// config.State for the one case that is not.
func (d Dirs) StateFile() string { return filepath.Join(d.Root, "state.json") }

// ManifestFile holds the base64 anchor manifest, which contains the identity seed.
//
// This is the one file that cannot be recovered. Enrolment stores nothing on the
// server and hands back the only copy, so losing this loses the machine's AnchorID
// and its overlay address for good. 0600, and the directory around it 0700.
func (d Dirs) ManifestFile() string { return filepath.Join(d.Root, "manifest.b64") }

// DaemonConfigFile is anchord's own -config, rendered from conflux.json on every
// start so the daemon comes back believing what this machine's configuration says.
//
// Under State rather than Config, and derived rather than edited: it is written by
// the supervisor, overwritten on every spawn, and nothing reads it back. An
// operator who edits it has their edit discarded at the next restart, which is the
// right way round -- conflux.json is the file with the operator's intent in it.
//
// It carries the export headers, which are credentials, so it is 0600 and belongs to
// whoever anchord runs as, in the directory beside the manifest rather than anywhere a
// config file would normally live. anchord warns about exactly this.
func (d Dirs) DaemonConfigFile() string { return filepath.Join(d.Root, "anchord.json") }

// AnchorDir is the anchor's -dir, which `anchorctl start` names, when anchord runs as its
// own unprivileged account: the bootstrap cache, the realm-link cache, and what the realm's
// orders leave there (a Subnets order's list, a Taints order's grant, the blocks in force).
// That account owns it, and can write anything in it.
//
// Not optional. An anchor without it that adopts a renewed delegation and then
// restarts falls back to a chain whose delegation has since lapsed -- cut off, and
// unable to recover in band. Every conflux anchor sits under a delegated realm, so
// that is exactly the case anchor's warning is about.
func (d Dirs) AnchorDir() string { return filepath.Join(d.Root, "anchor") }

// RootAnchorDir is the -dir of an anchord that runs as root (SYSTEM on Windows): a TUN on
// macOS or the BSDs, a host whose firewall answers only root, a supervisor that cannot
// drop. Its own, because anchor follows a symlink in its directory, and one the account
// planted in AnchorDir would otherwise lead root's writes wherever it pointed. What the
// anchor keeps there is copied across when the identity anchord runs as changes.
func (d Dirs) RootAnchorDir() string { return filepath.Join(d.Root, "anchor.root") }

// SubnetsOrderFile is where an anchor with dir as its -dir keeps a list a member's Subnets
// order set, which it serves in place of the configured one from every start until the file
// is removed (anchor's served.go, subnetsFile).
func SubnetsOrderFile(dir string) string { return filepath.Join(dir, "subnets.json") }

// ServiceExecutable is the copy of conflux the boot service runs: inside the state
// directory, which only root (Administrators and SYSTEM on Windows) can write, rather
// than wherever conflux happened to be run from. See service.PlaceAfresh.
func (d Dirs) ServiceExecutable() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(d.Root, "conflux.exe")
	}

	return filepath.Join(d.Root, "conflux")
}

// Libexec is where the embedded pair is extracted, one directory per content hash.
func (d Dirs) Libexec() string { return filepath.Join(d.Root, "bin") }

// DaemonRun is anchord's own run directory, which holds its control socket and the lock
// anchor keeps beside it, and belongs to whoever anchord runs as: anchord has to create
// the socket, and the run directory around it must stay root's, because the pid record
// in it is what the next supervisor kills by. The supervisor makes it afresh before
// every start.
func (d Dirs) DaemonRun() string { return filepath.Join(d.RunDir(), "anchord") }

// Socket is anchord's control socket. anchord creates it 0600; the 0700 directory
// around it is the first gate and the bearer token is the second.
func (d Dirs) Socket() string { return filepath.Join(d.DaemonRun(), socketName) }

// TokenFile holds the bearer token anchorctl authenticates with. Regenerated on
// every supervisor start, so a token left by a crashed run authenticates nothing.
// Root's alone: anchord is handed the token in its environment instead.
func (d Dirs) TokenFile() string { return filepath.Join(d.RunDir(), "token") }

// PrivilegeFile records who the last anchord started runs as, with what, why, and which of
// the two anchor directories it was given, for `conflux status` and for the supervisor that
// starts the next one: when the next is given the other directory, what the anchor kept is
// copied across. Root's alone, beside the state, because it has to outlive a reboot.
func (d Dirs) PrivilegeFile() string { return filepath.Join(d.Root, "anchord.priv") }

// LockFile serialises everything that rewrites the manifest or the state: a bring-up,
// the renewal timer, `conflux renew`, `conflux enrol`, and the uplink watcher's count.
//
// Beside the state rather than in Run, which an update empties (tidy): a `conflux renew` that
// spanned it would hold the old file's lock while the new supervisor took the new one's, and the
// two would renew at once.
func (d Dirs) LockFile() string { return filepath.Join(d.Root, "conflux.lock") }

// ServeLockFile is held by the one supervisor serving this root for as long as it runs.
//
// One per root, because the supervisor stops whatever anchord the last one left
// running, and two supervisors would each take the other's for an orphan. Beside the
// state for the reason LockFile is.
func (d Dirs) ServeLockFile() string { return filepath.Join(d.Root, "serve.lock") }

// DaemonPIDFile names the anchord the supervisor started -- its pid and its executable --
// for as long as it runs, so a supervisor that died without stopping it can be followed
// by one that does. In Run, which no anchord outlives except by that kind of death.
func (d Dirs) DaemonPIDFile() string { return filepath.Join(d.RunDir(), "anchord.pid") }

// LogFile is the boot service's output, or "" where the service manager keeps it.
func (d Dirs) LogFile() string {
	if d.LogDir() == "" {
		return ""
	}

	return filepath.Join(d.LogDir(), "conflux.log")
}

// ReadyFile is written by the supervisor once an anchor is up, and removed when it goes.
// It is what lets `conflux up` learn the anchor is up the moment it happens; see
// internal/daemon/ready.go.
//
// In Run rather than State, because a marker must not outlive the thing it describes. The
// run directory survives a reboot, inside the root on disk, so the supervisor clears the
// marker on the way up rather than relying on the directory's lifetime.
func (d Dirs) ReadyFile() string { return filepath.Join(d.RunDir(), "ready") }

// EnsureAll makes the root, a folder conflux's by its name, as conflux makes it: 0700, and on Windows
// the Administrators' under a protected DACL granting SYSTEM and the Administrators alone, which what is
// made in it inherits.
//
// A root not there is made in the folder it is in -- the system's data folder, or an ephemeral run's
// runtime folder -- which is the system's, and refused where that is not there, nothing made. Whatever is at a root's
// name and is not as conflux makes a root -- a link, a file, a folder another account owns or may write
// (ours) -- is removed as itself from the folder it is in, and the root made afresh: a root is conflux's
// whole, and nothing in it is kept for anybody. Each folder conflux keeps in a root (folders) is judged
// as the root is, and made afresh alike; and each file it keeps there (files) -- the configuration, the
// state, the identity, the lock files, the copy of conflux the boot service runs -- is judged so too, and
// removed where it is not as conflux makes it, for what writes it to make afresh. The folder a root is
// in, and every folder above it, is never changed and never judged.
func (d Dirs) EnsureAll() error {
	if err := d.makeRoot(); err != nil {
		return fmt.Errorf("create %s: %w", d.Root, err)
	}

	return nil
}

// EnsureServing is EnsureAll for the supervisor that serves d, which runs from the copy of conflux the boot
// service names in the root (ServiceExecutable): everything is judged and made as EnsureAll judges
// and makes it but that copy, which is neither judged nor removed -- Windows will not remove a running
// image, and one removed on Unix would leave the service nothing to start the next time; the supervisor
// places one not there, or not as conflux makes it, afresh itself, from its own image (service.OwnCopy).
func (d Dirs) EnsureServing() error {
	d.serving = true

	return d.EnsureAll()
}

// makeRoot makes the root and the folders conflux keeps in it (folders): the folder the root is in held
// (openFolder), and refused where it is not there; then the root made in it as conflux makes a folder of
// its own (ownFolder), and each of its folders in that, held.
func (d Dirs) makeRoot() error {
	parent, err := openFolder(filepath.Dir(d.Root))
	if err != nil {
		return err
	}
	defer parent.close()

	root, err := ownFolder(parent, d.Root, true)
	if err != nil {
		return err
	}
	defer root.close()

	// Each folder conflux keeps in the root is judged as the root is (ours). The anchor directory of an
	// anchord that runs as its own account (AnchorDir) is not among them: that account owns it, as the
	// supervisor makes it, so ours would remove it, and the anchor's state with it, at every start; the
	// supervisor holds it to that account instead (daemon's anchorDirFor), and makes it afresh otherwise.
	for sub, create := range d.folders() {
		s, err := ownFolder(root, sub, create)

		switch {
		case errors.Is(err, fs.ErrNotExist) && !create:
		case err != nil:
			return err
		default:
			s.close()
		}
	}

	for _, f := range d.files() {
		if err := ownFile(root, f); err != nil {
			return err
		}
	}

	return nil
}

// ownFile holds what is at p's name, in the folder parent holds, to what conflux makes there, a file of
// its own: looked up there and nowhere else, never followed (lookAt), and a file as conflux makes one
// (ours) kept; anything else there -- a link, a folder, a file another account owns or may change -- is
// removed as itself through parent (removeFrom), and nothing made in its place: whatever writes the file
// makes it. One that cannot be removed is refused, saying why it is not conflux's. Nothing at the name is
// nothing to do.
func ownFile(parent step, p string) error {
	name := filepath.Base(p)

	looking(p)

	s, k, err := lookAt(parent, name)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("read %s: %w", p, err)
	}

	why := k.not(isFile)
	if k == isFile {
		why, err = ours(p, s)
	}

	s.close()

	if err != nil || why == "" {
		return err
	}

	if _, err := removeFrom(parent, name, p); err != nil {
		return fmt.Errorf("%s is not as conflux makes a file of its own (%s), and could not be removed: %w", p, why,
			err)
	}

	return nil
}

// files is each file conflux keeps directly in its root, by its name: the configuration, the state, the
// identity, the record of the anchord last started, the two lock files, and the copy of conflux the boot
// service runs, but for the supervisor serving d, which runs from it (EnsureServing). anchord's own configuration
// (DaemonConfigFile) is none of these: it is the account anchord runs as's, as the supervisor writes it
// at every start, so ours would remove it each time.
func (d Dirs) files() []string {
	files := []string{d.ConfigFile(), d.StateFile(), d.ManifestFile(), d.PrivilegeFile(), d.LockFile(),
		d.ServeLockFile()}

	if !d.serving {
		files = append(files, d.ServiceExecutable())
	}

	return files
}

// ownFolder is the folder p, in the folder parent holds, made as conflux makes a folder of its own, and
// held: p's name is looked up in parent and nowhere else (lookUp), and a directory there that is as
// conflux makes one (ours) is kept; anything else there -- a link, a file, a folder another account owns
// or may write -- is removed as itself through parent (removeFrom), a link never followed, whatever it
// holds, and the folder made afresh in its place (makeStep); one that cannot be is refused, saying why it
// is not conflux's. Where nothing is there it is made where create is, and is otherwise an error that is
// fs.ErrNotExist.
func ownFolder(parent step, p string, create bool) (step, error) {
	name := filepath.Base(p)

	looking(p)

	s, link, err := lookUp(parent, name)

	why := ""

	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !create {
			return step{}, &os.PathError{Op: "open", Path: p, Err: err}
		}
	case err == nil:
		why = "a link"
		if !link {
			why, err = ours(p, s)
		}

		if err == nil && why == "" {
			return s, nil
		}

		s.close()

		if err != nil {
			return step{}, err
		}
	default:
		why = err.Error()
	}

	if why != "" {
		if _, err := removeFrom(parent, name, p); err != nil {
			return step{}, fmt.Errorf("%s is not as conflux makes a folder of its own (%s), and could not be removed "+
				"to be made afresh: %w", p, why, err)
		}
	}

	s, err = makeStep(parent, name)
	if err != nil {
		return step{}, &os.PathError{Op: "mkdir", Path: p, Err: err}
	}

	return s, nil
}

// folders is each folder conflux keeps in its root, by its name, and whether EnsureAll makes it where it
// is not there: the run and log directories, and the directory the pairs are extracted to (Libexec),
// which it makes -- an extraction makes nothing but its set in it -- and, for an installation, the anchor
// directory of an anchord that runs as root (RootAnchorDir), which what uses it makes. The anchor directory of an anchord that runs as its own
// account (AnchorDir) is that account's, as the supervisor makes it and holds it to be (daemon's
// anchorDir), and is none of these.
func (d Dirs) folders() iter.Seq2[string, bool] {
	return func(yield func(string, bool) bool) {
		for _, sub := range []string{d.RunDir(), d.LogDir(), d.Libexec()} {
			if sub != "" && !yield(sub, true) {
				return
			}
		}

		if !d.ephemeral {
			yield(d.RootAnchorDir(), false)
		}
	}
}

// above reports whether dir is a folder strictly above path, by their names (filepath.Rel), neither
// taken through a link: the one test of whether a path is inside another.
func above(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)

	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// RemoveRoot removes the root dir, a folder conflux's by its name, with everything in it, and says
// whether anything was at its name: from the folder it is in, held (openFolder), and everything below it
// removed through the folder holding it, never by its name, a link anywhere in it, dir's own name
// included, removed as itself, and where it leads never touched. Where nothing is at dir's name, or the
// folder it is in is not there, nothing is removed.
func RemoveRoot(dir string) (bool, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}

	parent, err := openFolder(filepath.Dir(dir))

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, err
	}
	defer parent.close()

	return removeFrom(parent, filepath.Base(dir), dir)
}

// rootHold is a root held open: the folder it is in, and the directory at its name.
type rootHold struct {
	parent step
	dir    step
}

func (r *rootHold) close() {
	r.dir.close()
	r.parent.close()
}

// holdRoot holds the root dir, an installation's or an ephemeral run's: the folder it is in held
// (openFolder), and the directory at dir's name in that folder, looked up there and nowhere else (lookUp);
// and is why that is not as conflux makes a root (ours), or "". A link or anything else at the name that is
// no directory is not held, and nothing in it is read. Where the folder dir is in, or its name, is not
// there, it is an error that is fs.ErrNotExist.
func holdRoot(dir string) (*rootHold, string, error) {
	parent, err := openFolder(filepath.Dir(dir))
	if err != nil {
		return nil, "", err
	}

	s, link, err := lookUp(parent, filepath.Base(dir))

	why := ""

	switch {
	case errors.Is(err, fs.ErrNotExist):
		err = &os.PathError{Op: "open", Path: dir, Err: err}
	case errors.Is(err, errNotDir):
		why, err = "not a directory", nil
	case err != nil:
		err = fmt.Errorf("read %s: %w", dir, err)
	case link:
		s.close()

		why = "a link"
	default:
		if why, err = ours(dir, s); err == nil {
			return &rootHold{parent: parent, dir: s}, why, nil
		}

		s.close()
	}

	parent.close()

	return nil, why, err
}

// notOurs is the refusal of the root dir, an ephemeral run's where ephemeral is, for why, what holdRoot
// found at its name: nothing of conflux's to read, which the next EnsureAll makes afresh -- an
// installation's at the next command that makes its root, an ephemeral run's at the next ephemeral run.
func notOurs(dir, why string, ephemeral bool) error {
	next := "the next up, proxy, install or start"
	if ephemeral {
		next = "the next up --ephemeral or proxy --ephemeral"
	}

	return fmt.Errorf("%s is not as conflux makes a folder of its own (%s), so conflux will not use what is in it: "+
		"%s removes it and makes it afresh", dir, why, next)
}

// OpenIn opens path, a file directly in d's root, to read, through that root held (holdRoot) and never by
// its name: the root's own name looked up in the folder it is in, and path's name looked up in the root and
// nowhere else, never followed. A root that is not as conflux makes one is
// none of conflux's, and is taken as not there. Where the root, or path's name in it, is not there, it is
// an error that is fs.ErrNotExist.
func (d Dirs) OpenIn(path string) (*os.File, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(path)

	if dir != d.Root {
		return nil, fmt.Errorf("%s is not directly in a root of conflux's", path)
	}

	r, why, err := holdRoot(dir)
	if err != nil {
		return nil, err
	}

	if r == nil || why != "" {
		if r != nil {
			r.close()
		}

		return nil, &os.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	defer r.close()

	return openIn(r.dir, filepath.Base(path), path)
}

// Ours holds path, a file in d's root or in a folder conflux keeps beneath one, to what a command
// needs of it before it runs it: the root held as Check holds it (holdRoot), each folder from there to
// the file looked up in the one before and nowhere else, never followed (lookUp), and each of them, and
// the file (lookAt), as conflux makes it (ours). Nil where all are; an error that is fs.ErrNotExist
// where the root, a folder on the way or the file is not there; and otherwise why one is not as conflux
// makes it. It changes nothing.
func (d Dirs) Ours(path string) error { return d.oursAs(path, isFile) }

// OursFolder is Ours for a folder in d's root or beneath it, such as the bin directory a reader
// extracts into (libexec's ForUsage): the folder judged as each one on the way to it is.
func (d Dirs) OursFolder(path string) error { return d.oursAs(path, isFolder) }

// oursAs is Ours of path, what is there taken as conflux's only where it is of kind want.
func (d Dirs) oursAs(path string, want kind) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	root := d.Root
	if !above(root, path) {
		return fmt.Errorf("%s is not in a root of conflux's", path)
	}

	r, why, err := holdRoot(root)

	switch {
	case err != nil:
		return err
	case why != "":
		if r != nil {
			r.close()
		}

		return notOurs(root, why, d.ephemeral)
	}
	defer r.close()

	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}

	names := strings.Split(rel, string(filepath.Separator))
	at, p := r.dir, root

	for _, name := range names[:len(names)-1] {
		p = filepath.Join(p, name)

		s, link, err := lookUp(at, name)

		switch {
		case err != nil:
			return &os.PathError{Op: "open", Path: p, Err: err}
		case link:
			why = "a link"
		default:
			why, err = ours(p, s)
		}

		if err != nil || why != "" {
			s.close()

			return notOursHere(p, why, err)
		}

		defer s.close()

		at = s
	}

	s, k, err := lookAt(at, names[len(names)-1])
	if err == nil {
		why = k.not(want)
		if k == want {
			why, err = ours(path, s)
		}

		s.close()
	}

	if err != nil && errors.Is(err, fs.ErrNotExist) {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}

	return notOursHere(path, why, err)
}

// notOursHere is Ours's answer for p: err where it is given, why p is not as conflux makes it where that
// is, and otherwise nil.
func notOursHere(p, why string, err error) error {
	switch {
	case err != nil:
		return err
	case why != "":
		return fmt.Errorf("%s is not as conflux makes it (%s)", p, why)
	}

	return nil
}

// kind is what lookAt finds at a name: a file, a folder, a link (on Windows a junction or a link), or
// anything else.
type kind uint8

const (
	isFile kind = iota
	isFolder
	isLink
	isOther
)

// not is why what lookAt found, of kind k, is not the kind want conflux keeps at its name -- a file or a
// folder -- or "" where it is.
func (k kind) not(want kind) string {
	switch {
	case k == want:
		return ""
	case k == isLink:
		return aLink
	case want == isFolder:
		return "not a directory"
	}

	return "not a file"
}

// errNotDir is lookUp's refusal of what is at a name that is neither a directory nor a link, by the type
// the system read of it rather than the error an open of it failed with; it is syscall.ENOTDIR to
// errors.Is.
var errNotDir = fmt.Errorf("%w", syscall.ENOTDIR)

// Check holds d's root, where it is there, to what a command needs of it before it reads, runs or
// signals anything in it by its name (holdRoot): the directory at the root's name as conflux makes a
// root (ours) -- not a link, owned by root or the account running conflux, and written by nobody else; on
// Windows owned by SYSTEM, the Administrators or TrustedInstaller, and granting nobody else anything
// (machineAccount). Nothing else can have put anything in such a root, so what it holds is not judged, and
// nothing above it is. It changes nothing: a root that fails is refused, saying why.
//
// Where the root is not there, nothing of conflux's is installed, and Check is an error that is
// fs.ErrNotExist: each caller then takes its own way for that, reading nothing.
func (d Dirs) Check() error {
	r, why, err := holdRoot(d.Root)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("conflux is not installed in %s: %w", d.Root, fs.ErrNotExist)
	case err != nil:
		return err
	case r != nil:
		r.close()
	}

	if why != "" {
		return notOurs(d.Root, why, d.ephemeral)
	}

	return nil
}

// looking is called with the path of each name before makeRoot looks it up: nothing, but where a test
// makes something at the name meanwhile.
var looking = func(string) {}

// ClearExcept removes everything in dir but keep, following nothing in it (os.RemoveAll), and is the
// paths of what it removed, however far it got: what a run killed before it could clean up left in
// its root, which the next run starts without, and what supervisors and extractions before an update
// left in the run and bin directories.
func ClearExcept(dir string, keep ...string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var removed []string

	for _, e := range entries {
		if p := filepath.Join(dir, e.Name()); !slices.Contains(keep, p) {
			if err := os.RemoveAll(p); err != nil {
				return removed, fmt.Errorf("clear %s: %w", p, err)
			}

			removed = append(removed, p)
		}
	}

	return removed, nil
}

// RemovePrefixed removes, by remove, each entry in dir whose name begins with prefix, and is the paths of
// those it removed: what conflux leaves under a name of its own beside what it keeps -- a reader's temporary
// copy, a copy or a download that never went in place, a write that never did. dir is read by its name as
// it is, never as a pattern, which one holding a [ would be, reaching into another folder the pattern
// matches. A dir that cannot be read holds nothing to remove.
func RemovePrefixed(dir, prefix string, remove func(string) error) []string {
	entries, _ := os.ReadDir(dir)

	var removed []string

	for _, e := range entries {
		if p := filepath.Join(dir, e.Name()); strings.HasPrefix(e.Name(), prefix) && remove(p) == nil {
			removed = append(removed, p)
		}
	}

	return removed
}

// SyncDir makes a name just placed in dir durable, as far as the platform lets it: what an
// atomic write calls after its rename or link. Best effort, since the file is already in
// place, and some filesystems refuse to fsync a directory -- and NTFS orders its metadata
// itself -- which is not worth losing the write over.
func SyncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		_ = f.Sync()
		f.Close()
	}
}
