// Package paths is every filesystem path conflux uses, decided in one place.
//
// conflux is system-scoped: one configuration per machine, root-owned, with no
// home directory anywhere in it. That is a decision rather than an oversight. The
// boot service runs as root or LocalSystem, so a path under $HOME is a path the
// service cannot read, and a home directory is wrong under a unit with User=, wrong
// under ProtectHome=, and wrong for anyone who ran conflux with sudo -H.
//
// Four roots, because they have four lifetimes:
//
//   - Config  what the operator asked for. Survives everything but uninstall.
//   - State   what conflux derived, plus the identity. Survives a reboot.
//   - Run     the socket, the token and the readiness marker. Emptied by the system at
//     boot on most platforms, and by systemd whenever the service stops.
//   - Log     where the boot service's output goes, on the platforms where it goes to a
//     file: empty where the service manager keeps it (journald, syslog).
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

// Dirs are the four roots. Get one from Default, or an ephemeral run's from EphemeralDirs.
type Dirs struct {
	Config string
	State  string
	Run    string
	Log    string

	// ephemeral is whether these are an ephemeral run's (EphemeralDirs), which runs as whoever starts
	// it and no service ever serves; every other Dirs is an installation's, whose roots the boot
	// service serves, so EnsureAll holds a CONFLUX_DIR's way to the service's rule (wayRule).
	ephemeral bool

	// serving is whether EnsureServing is making these, for the supervisor that serves them, which leaves
	// the copy of conflux it runs from alone.
	serving bool
}

// Default is where this platform keeps them.
//
// CONFLUX_DIR overrides all four at once, rooting them in one directory, DirName, which conflux
// makes inside it. That is what the tests use, and what a second installation beside the machine's
// own is rooted in, its boot service included; see Root. It changes where conflux keeps things and
// not what it needs: the verbs that change anything still need root.
func Default() Dirs {
	if root := Root(); root != "" {
		return rootedAt(filepath.Join(root, DirName))
	}

	return platformDirs()
}

// DirName is the folder conflux makes inside a CONFLUX_DIR and keeps all of its own in: the
// configuration and the state, and its run and log directories inside it. The CONFLUX_DIR itself is
// never changed, so a folder of the user's -- their home, say -- can be one.
const DirName = ".conflux"

// rootedAt is the Dirs of an installation rooted in the one directory root, as a CONFLUX_DIR's is: the
// configuration and the state in it, and the run and log directories inside it -- a log directory of its
// own only where the platform writes the service's output to a file at all: where journald or syslog keeps
// it, nothing would write there.
func rootedAt(root string) Dirs {
	log := ""
	if platformDirs().Log != "" {
		log = filepath.Join(root, "logs")
	}

	return Dirs{
		Config: root,
		State:  root,
		Run:    filepath.Join(root, runName),
		Log:    log,
	}
}

// runName is the run directory's name inside a root that holds it: a CONFLUX_DIR's, an
// ephemeral run's, and Windows's own.
const runName = "run"

// sharedLog is the system's own log directory, which macOS and FreeBSD put the service's
// log file in. conflux writes a file there and never creates, narrows or claims the
// directory itself. A variable so a test can stand one in.
var sharedLog = "/var/log"

// socketName is anchord's control socket, an AF_UNIX socket on every platform, inside a
// directory of anchord's own (DaemonRun). Four letters, so the path is exactly as long as
// the <run>/anchord.sock it replaced: sun_path is 104 bytes on macOS, and a test root
// under /var/folders is already most of that.
const socketName = "sock"

// Root is the CONFLUX_DIR override, or "" when this is an ordinary system install.
//
// Exported because the boot service has to know. A run rooted somewhere else is a
// separate installation of conflux, not the machine's own, and registering it under
// the machine's own service name would replace a real node with a test one -- so the
// service package names itself after this, and passes it on to the supervisor it
// registers, which would otherwise come back at boot reading /etc/conflux.
//
// Absolute and clean, whatever was typed: it is written into the service definition as
// the --dir the supervisor comes back with, and hashed into the service's name, so
// "run/x" or a trailing slash would otherwise register a service that runs from / and
// that the same root, spelled differently, could not find to remove.
func Root() string {
	root := os.Getenv("CONFLUX_DIR")
	if root == "" {
		return ""
	}

	if abs, err := filepath.Abs(root); err == nil {
		return abs
	}

	return filepath.Clean(root)
}

// ConfigFile holds the operator's intent: mode, taints, addresses, proxies.
func (d Dirs) ConfigFile() string { return filepath.Join(d.Config, "conflux.json") }

// StateFile holds what conflux derived: the AnchorID, the credential window, which
// extracted binary set is live. Most of it is re-learned at the next start; see
// config.State for the one case that is not.
func (d Dirs) StateFile() string { return filepath.Join(d.State, "state.json") }

// ManifestFile holds the base64 anchor manifest, which contains the identity seed.
//
// This is the one file that cannot be recovered. Enrolment stores nothing on the
// server and hands back the only copy, so losing this loses the machine's AnchorID
// and its overlay address for good. 0600, and the directory around it 0700.
func (d Dirs) ManifestFile() string { return filepath.Join(d.State, "manifest.b64") }

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
func (d Dirs) DaemonConfigFile() string { return filepath.Join(d.State, "anchord.json") }

// AnchorDir is the anchor's -dir, which `anchorctl start` names, when anchord runs as its
// own unprivileged account: the bootstrap cache, the realm-link cache, and what the realm's
// orders leave there (a Subnets order's list, a Taints order's grant, the blocks in force).
// That account owns it, and can write anything in it.
//
// Not optional. An anchor without it that adopts a renewed delegation and then
// restarts falls back to a chain whose delegation has since lapsed -- cut off, and
// unable to recover in band. Every conflux anchor sits under a delegated realm, so
// that is exactly the case anchor's warning is about.
func (d Dirs) AnchorDir() string { return filepath.Join(d.State, "anchor") }

// RootAnchorDir is the -dir of an anchord that runs as root (SYSTEM on Windows): a TUN on
// macOS or the BSDs, a host whose firewall answers only root, a supervisor that cannot
// drop. Its own, because anchor follows a symlink in its directory, and one the account
// planted in AnchorDir would otherwise lead root's writes wherever it pointed. What the
// anchor keeps there is copied across when the identity anchord runs as changes.
func (d Dirs) RootAnchorDir() string { return filepath.Join(d.State, "anchor.root") }

// SubnetsOrderFile is where an anchor with dir as its -dir keeps a list a member's Subnets
// order set, which it serves in place of the configured one from every start until the file
// is removed (anchor's served.go, subnetsFile).
func SubnetsOrderFile(dir string) string { return filepath.Join(dir, "subnets.json") }

// ServiceExecutable is the copy of conflux the boot service runs: inside the state
// directory, which only root (Administrators and SYSTEM on Windows) can write, rather
// than wherever conflux happened to be run from. See service.PlaceAfresh.
func (d Dirs) ServiceExecutable() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(d.State, "conflux.exe")
	}

	return filepath.Join(d.State, "conflux")
}

// Libexec is where the embedded pair is extracted, one directory per content hash.
func (d Dirs) Libexec() string { return filepath.Join(d.State, "bin") }

// DaemonRun is anchord's own run directory, which holds its control socket and the lock
// anchor keeps beside it, and belongs to whoever anchord runs as: anchord has to create
// the socket, and the run directory around it must stay root's, because the pid record
// in it is what the next supervisor kills by. The supervisor makes it afresh before
// every start.
func (d Dirs) DaemonRun() string { return filepath.Join(d.Run, "anchord") }

// Socket is anchord's control socket. anchord creates it 0600; the 0700 directory
// around it is the first gate and the bearer token is the second.
func (d Dirs) Socket() string { return filepath.Join(d.DaemonRun(), socketName) }

// TokenFile holds the bearer token anchorctl authenticates with. Regenerated on
// every supervisor start, so a token left by a crashed run authenticates nothing.
// Root's alone: anchord is handed the token in its environment instead.
func (d Dirs) TokenFile() string { return filepath.Join(d.Run, "token") }

// PrivilegeFile records who the last anchord started runs as, with what, why, and which of
// the two anchor directories it was given, for `conflux status` and for the supervisor that
// starts the next one: when the next is given the other directory, what the anchor kept is
// copied across. Root's alone, beside the state, because it has to outlive a reboot.
func (d Dirs) PrivilegeFile() string { return filepath.Join(d.State, "anchord.priv") }

// LockFile serialises everything that rewrites the manifest or the state: a bring-up,
// the renewal timer, `conflux renew`, `conflux enrol`, and the uplink watcher's count.
//
// Beside the state rather than in Run, which systemd removes and makes again whenever the
// service stops and starts: a `conflux renew` that spanned a restart would hold the old
// file's lock while the new supervisor took the new one's, and the two would renew at once.
func (d Dirs) LockFile() string { return filepath.Join(d.State, "conflux.lock") }

// ServeLockFile is held by the one supervisor serving this root for as long as it runs.
//
// One per root, because the supervisor stops whatever anchord the last one left
// running, and two supervisors would each take the other's for an orphan. Beside the
// state for the reason LockFile is.
func (d Dirs) ServeLockFile() string { return filepath.Join(d.State, "serve.lock") }

// DaemonPIDFile names the anchord the supervisor started -- its pid and its executable --
// for as long as it runs, so a supervisor that died without stopping it can be followed
// by one that does. In Run, which no anchord outlives except by that kind of death.
func (d Dirs) DaemonPIDFile() string { return filepath.Join(d.Run, "anchord.pid") }

// LogFile is the boot service's output, or "" where the service manager keeps it.
func (d Dirs) LogFile() string {
	if d.Log == "" {
		return ""
	}

	return filepath.Join(d.Log, "conflux.log")
}

// ReadyFile is written by the supervisor once an anchor is up, and removed when it goes.
// It is what lets `conflux up` learn the anchor is up the moment it happens; see
// internal/daemon/ready.go.
//
// In Run rather than State, because a marker must not outlive the thing it describes.
// systemd's RuntimeDirectory= clears it on stop and the BSDs and macOS clear /var/run at
// boot -- %ProgramData%\conflux\run on Windows survives both, which is why the
// supervisor also clears it on the way up rather than relying on the directory's
// lifetime alone.
func (d Dirs) ReadyFile() string { return filepath.Join(d.Run, "ready") }

// EnsureAll makes the four roots, each a folder conflux's by its name, as conflux makes them: 0700,
// and on Windows the Administrators' under a protected DACL granting SYSTEM and the Administrators
// alone, which what is made in it inherits.
//
// A root not there is made, with each folder missing on the way to it, and those on a CONFLUX_DIR's way
// (chosenWay) recorded in the state root (recordWay) for uninstall, or an ephemeral run as it ends, to
// remove whole (Way, RemoveWay). Any other folder made on the way -- one a platform's root, or an
// ephemeral run's, is made in, such as a user's cache or runtime directory, or a home -- is the
// system's, which other programs fill too, and is not recorded. Whatever is at a root's
// name and is not as conflux makes a root -- a link, a file, a folder another account owns or may write
// (ours) -- is removed as itself from the folder it is in, and the root made afresh: a root is conflux's
// whole, and nothing in it is kept for anybody. Each folder conflux keeps in a root (folders) is judged
// as the root is, and made afresh alike; and each file it keeps there (files) -- the configuration, the
// state, the identity, the lock files, the copy of conflux the boot service runs -- is judged so too, and
// removed where it is not as conflux makes it, for what writes it to make afresh. A CONFLUX_DIR itself,
// and everything above a root, is never changed: a CONFLUX_DIR's way, the CONFLUX_DIR included, is held
// to the rule of whoever the root is for (wayRule) before anything is made. The system's shared log directory,
// which macOS and FreeBSD keep the service's log in, is not conflux's, and is left alone.
func (d Dirs) EnsureAll() error {
	var made []string

	state := false

	err := func() error {
		for _, dir := range d.Outer() {
			m, err := d.makeRoot(dir)
			if made = append(made, slices.DeleteFunc(m, func(p string) bool { return !chosenWay(p) })...); err != nil {
				return fmt.Errorf("create %s: %w", dir, err)
			}

			state = state || dir == d.State
		}

		return nil
	}()

	if len(made) > 0 && state {
		if recorded := d.recordWay(made); err == nil {
			err = recorded
		}
	}

	return err
}

// EnsureServing is EnsureAll for the supervisor that serves d, which runs from the copy of conflux the boot
// service names in the state root (ServiceExecutable): everything is judged and made as EnsureAll judges
// and makes it but that copy, which is neither judged nor removed -- Windows will not remove a running
// image, and one removed on Unix would leave the service nothing to start the next time; the supervisor
// places one not as conflux makes it afresh itself, from its own image (daemon's ownCopy).
func (d Dirs) EnsureServing() error {
	d.serving = true

	return d.EnsureAll()
}

// makeRoot makes the root dir, one of d's not inside another, and the folders conflux keeps in it
// (folders), and is the folders it made on the way to it. The way to the folder dir is in is walked
// from the top of its volume and held (walk), a CONFLUX_DIR's held to rule, the CONFLUX_DIR included,
// and what is missing of it made (makeWay); then the root is made in that folder as conflux makes a
// folder of its own (ownFolder), and each of its folders in it, held.
func (d Dirs) makeRoot(dir string) ([]string, error) {
	rule := d.wayRule(dir)

	judge := judgement(nil)
	if chosen(dir) {
		judge = rule
	}

	w, err := walk(filepath.Dir(dir), judge)
	if err != nil {
		return nil, err
	}
	defer w.close()

	made, err := makeWay(dir, w, rule)
	if err != nil {
		return made, err
	}

	at := w.last()

	if judge != nil {
		if err := judge(at.path, at.step, false); err != nil {
			return made, err
		}
	}

	root, err := ownFolder(at.step, dir, !d.ephemeral, true)
	if err != nil {
		return made, err
	}
	defer root.close()

	// Each folder conflux keeps in the root is judged as the root is (ours). The anchor directory of an
	// anchord that runs as its own account (AnchorDir) is not among them: that account owns it, as the
	// supervisor makes it, so ours would remove it, and the anchor's state with it, at every start; the
	// supervisor holds it to that account instead (daemon's anchorDirFor), and makes it afresh otherwise.
	for sub, create := range d.folders(dir) {
		s, err := ownFolder(root, sub, !d.ephemeral, create)

		switch {
		case errors.Is(err, fs.ErrNotExist) && !create:
		case err != nil:
			return made, err
		default:
			s.close()
		}
	}

	for _, f := range d.files(dir) {
		if err := ownFile(root, f, !d.ephemeral); err != nil {
			return made, err
		}
	}

	return made, nil
}

// ownFile holds what is at p's name, in the folder parent holds, to what conflux makes there, a file of
// its own: looked up there and nowhere else, never followed (lookAt), and a file as conflux makes one
// (ours) kept; anything else there -- a link, a folder, a file another account owns or may change -- is
// removed as itself through parent (removeFrom), and nothing made in its place: whatever writes the file
// makes it. One that cannot be removed is refused, saying why it is not conflux's. Nothing at the name is
// nothing to do.
func ownFile(parent step, p string, installation bool) error {
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
		why, err = ours(p, s, installation)
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

// files is each file conflux keeps directly in its root dir, by its name: in the configuration root the
// configuration, and in the state root the state, the identity, the record of the anchord last started
// and of the way, the two lock files, and the copy of conflux the boot service runs, but for the
// supervisor serving d, which runs from it (EnsureServing). anchord's own configuration
// (DaemonConfigFile) is none of these: it is the account anchord runs as's, as the supervisor writes it
// at every start, so ours would remove it each time.
func (d Dirs) files(dir string) []string {
	var files []string

	if dir == d.Config {
		files = append(files, d.ConfigFile())
	}

	if dir == d.State {
		files = append(files, d.StateFile(), d.ManifestFile(), d.PrivilegeFile(), d.WayFile(), d.LockFile(),
			d.ServeLockFile())

		if !d.serving {
			files = append(files, d.ServiceExecutable())
		}
	}

	return files
}

// ownFolder is the folder p, in the folder parent holds, made as conflux makes a folder of its own, and
// held: p's name is looked up in parent and nowhere else (lookUp), and a directory there that is as
// conflux makes one (ours) is kept; anything else there -- a link, a file, a folder another account owns
// or may write -- is removed as itself through parent (removeFrom), a link never followed, whatever it
// holds, and the folder made afresh in its place (makeStep); one that cannot be is refused, saying why it
// is not conflux's. Where nothing is there it is made where create is, and is otherwise an error that is
// fs.ErrNotExist. A folder made, where makeStep holds nothing of it, is looked up again to be held, and a
// link put at its name meanwhile is refused, never followed, as makeWay refuses one.
func ownFolder(parent step, p string, installation, create bool) (step, error) {
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
			why, err = ours(p, s, installation)
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

	s, held, err := makeStep(parent, name)
	if err != nil {
		return step{}, &os.PathError{Op: "mkdir", Path: p, Err: err}
	}

	if held {
		return s, nil
	}

	looking(p)

	switch s, link, err = lookUp(parent, name); {
	case err != nil:
		return step{}, &os.PathError{Op: "open", Path: p, Err: err}
	case link:
		s.close()

		return step{}, fmt.Errorf("%s, %s, was made while conflux made it, which conflux will not follow.\n"+
			"  Remove it, then run this again", p, aLink)
	}

	return s, nil
}

// folders is each folder conflux keeps in its root dir, by its name, and whether EnsureAll makes it where
// it is not there: the run and log directories where they are in that root, which it makes, and in the
// state root the directory the pairs are extracted to (Libexec) and, for an installation, the anchor
// directory of an anchord that runs as root (RootAnchorDir), which what uses them makes. The anchor
// directory of an anchord that runs as its own account (AnchorDir) is that account's, as the supervisor
// makes it and holds it to be (daemon's anchorDir), and is none of these.
func (d Dirs) folders(dir string) iter.Seq2[string, bool] {
	return func(yield func(string, bool) bool) {
		for sub, inside := range d.roots() {
			if inside && filepath.Dir(sub) == dir && !yield(sub, true) {
				return
			}
		}

		if dir != d.State || !yield(d.Libexec(), false) {
			return
		}

		if !d.ephemeral {
			yield(d.RootAnchorDir(), false)
		}
	}
}

// wayName is the record, in a state root, of the folders conflux made on the way to its roots -- an
// installation's, or an ephemeral run's: one absolute path a line.
const wayName = "way"

// WayFile is the record in d's state root of the folders conflux made on the way to d's roots (Way).
func (d Dirs) WayFile() string { return filepath.Join(d.State, wayName) }

// recordWay adds made, folders makeRoot made on the way to d's roots, to the record in d's state root:
// what it held kept, each once, written atomically (WriteAtomic).
func (d Dirs) recordWay(made []string) error {
	record := d.WayFile()

	way, err := d.readWay()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	for _, p := range made {
		if !slices.Contains(way, p) {
			way = append(way, p)
		}
	}

	if err := WriteAtomic(record, 0o600, -1, -1, []byte(strings.Join(way, "\n")+"\n")); err != nil {
		return fmt.Errorf("record the way to %s: %w", d.State, err)
	}

	return nil
}

// readWay is the record in d's state root, a line a folder, at most wayMax bytes of it, opened through
// the root held (OpenIn), and only from a root as conflux makes one: the record in a root that is not is
// none of conflux's either, and taken as not there. It is read as a file another account may have put
// there all the same (readUntrusted).
func (d Dirs) readWay() ([]string, error) {
	path := d.WayFile()

	f, err := d.OpenIn(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b, err := readUntrusted(f, path, wayMax)
	if err != nil {
		return nil, err
	}

	return strings.Fields(string(b)), nil
}

// wayMax is as much of the way record as is read: far more than any way conflux makes.
const wayMax = 64 << 10

// Way is the record of the folders conflux made on the way to d's roots (EnsureAll), deepest first, for
// uninstall, or an ephemeral run as it ends, to read before it removes the roots, the state root holding
// the record among them, and to hand to RemoveWay after: only folders above one of d's roots, and none
// at the top of a volume, are taken from it. Nil where there is no record, or no state root, or a link or
// a file at its name.
func (d Dirs) Way() ([]string, error) {
	recorded, err := d.readWay()

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	}

	var way []string

	for _, p := range recorded {
		if filepath.IsAbs(p) && filepath.Clean(p) == p && filepath.Dir(p) != p && !slices.Contains(way, p) &&
			d.aboveRoot(p) {
			way = append(way, p)
		}
	}

	return deepestFirst(way), nil
}

// RemoveWay removes each folder of way, folders conflux made on the way to its roots (Way), whole,
// whatever it holds, deepest first, and is those it removed: each removed from the folder it is in, as
// the walk to that holds it (toParent), never by its name and never following a link, the way to one
// on a CONFLUX_DIR's way (chosenWay) held to parents' rule, and what it holds removed through it as a
// root is (removeFrom). A folder conflux made is conflux's whole, so what anybody put in it goes with
// it, another installation among it. One that is not there, or is no longer a folder -- a link or a file
// put at its name -- is left, and so is one that is, or holds, the installation's root holding anything
// (holdsRoot): a root uninstall could not remove, or, as an ephemeral run under a CONFLUX_DIR ends, the
// .conflux it made, where anything is in it once the run's root is gone -- an installation made there
// since, say -- stays with the folders that hold it.
func RemoveWay(way []string) ([]string, error) {
	var (
		removed []string
		errs    []error
	)

	for _, dir := range deepestFirst(slices.Clone(way)) {
		if holdsRoot(dir) {
			continue
		}

		judge := judgement(nil)
		if chosenWay(dir) {
			judge = parentsRule(dir)
		}

		gone, err := removeWayFolder(dir, judge)
		if err != nil {
			errs = append(errs, err)
		}

		if gone {
			removed = append(removed, dir)
		}
	}

	return removed, errors.Join(errs...)
}

// removeWayFolder is RemoveWay's removal of dir, a folder, whole, from the folder it is in, held as the
// walk judged by judge reaches it (toParent), and whether it removed it; a link or anything else at its
// name that is no folder is left.
func removeWayFolder(dir string, judge judgement) (bool, error) {
	w, err := toParent(dir, judge)
	if err != nil || w == nil {
		return false, err
	}
	defer w.close()

	at, name := w.last().step, filepath.Base(dir)

	s, link, err := lookUp(at, name)

	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, errNotDir):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("read %s: %w", dir, err)
	}

	s.close()

	if link {
		return false, nil
	}

	return removeFrom(at, name, dir)
}

// holdsRoot reports whether dir is, or holds, one of the installation's roots (Default) that holds
// anything, by its name. An ephemeral run's root is only ever recorded under a CONFLUX_DIR, inside the
// installation's.
func holdsRoot(dir string) bool {
	for _, root := range Default().Outer() {
		if (dir == root || above(dir, root)) && holdsAnything(root) {
			return true
		}
	}

	return false
}

// holdsAnything reports whether the directory dir lists anything.
func holdsAnything(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer f.Close()

	names, _ := f.Readdirnames(1)

	return len(names) > 0
}

// chosenWay reports whether dir is on the way to a CONFLUX_DIR's root: the CONFLUX_DIR, a folder above
// it, or one inside it (chosen) -- of which conflux makes, on the way to a root, only the .conflux an
// ephemeral run's root is made in. The folders made on the way that EnsureAll records, and those whose
// way RemoveWay holds to parents' rule.
func chosenWay(dir string) bool {
	root := Root()

	return chosen(dir) || root != "" && above(dir, root)
}

// above reports whether dir is a folder strictly above path, by their names (filepath.Rel), neither
// taken through a link: the one test of whether a path is inside another.
func above(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)

	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// aboveRoot reports whether dir is a folder strictly above one of d's roots (roots), the system's
// shared log directory not among them.
func (d Dirs) aboveRoot(dir string) bool {
	for root := range d.roots() {
		if above(dir, root) {
			return true
		}
	}

	return false
}

// deepestFirst sorts way, folders, those with the most names first, and is it.
func deepestFirst(way []string) []string {
	depth := func(p string) int { return strings.Count(filepath.Clean(p), string(filepath.Separator)) }

	slices.SortStableFunc(way, func(a, b string) int { return depth(b) - depth(a) })

	return way
}

// RemoveRoot removes the root dir, a folder conflux's by its name, with everything in it, and says
// whether anything was at its name: from the folder it is in, held as the walk to it holds it
// (toParent), a CONFLUX_DIR's way held to parents' rule as a reader holds it, since a way another
// account may change could lead the removal elsewhere; and everything below it removed through the
// folder holding it, never by its name, a link anywhere in it, dir's own name included, removed as
// itself, and where it leads never touched. Where nothing is at dir's name, or on the way to it,
// nothing is removed.
func RemoveRoot(dir string) (bool, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}

	w, err := toParent(dir, readersRule(dir))
	if err != nil || w == nil {
		return false, err
	}
	defer w.close()

	return removeFrom(w.last().step, filepath.Base(dir), dir)
}

// readersRule is the rule a command that reads or removes what is at the root dir, rather than making
// it, holds dir's way to: parents' rule, for the account running conflux, where dir is in a CONFLUX_DIR
// (chosen), each refusal an ErrWayRefused; none for a platform root's way, the system's own, as
// makeRoot does not judge it either.
func readersRule(dir string) judgement {
	if !chosen(dir) {
		return nil
	}

	rule := parentsRule(dir)

	return func(p string, s step, link bool) error {
		if err := rule(p, s, link); err != nil {
			return refusal{err}
		}

		return nil
	}
}

// toParent is the way to the directory dir is in, walked from the top of its volume and held open
// (walk), held to judge where it is given -- that directory included, since whoever may change it could
// put another dir in its place, and no name is looked up in it on the walk -- or nil where a name on it
// is not there.
func toParent(dir string, judge judgement) (*way, error) {
	w, err := walk(filepath.Dir(dir), judge)
	if err != nil {
		return nil, err
	}

	if w.missing != nil {
		w.close()

		return nil, nil
	}

	if at := w.last(); judge != nil {
		if err := judge(at.path, at.step, false); err != nil {
			w.close()

			return nil, err
		}
	}

	return w, nil
}

// JudgeWays refuses d's roots where the way to one cannot be walked, or is a CONFLUX_DIR's that another
// account may change (ErrWayRefused), the CONFLUX_DIR included, since that could lead what is done
// there elsewhere: so that a command about to remove them -- uninstall -- refuses up front, with nothing
// done. Nil where every way passes, and where a name on one is not there; a platform root's way, the
// system's own, is not judged.
func (d Dirs) JudgeWays() error {
	for _, dir := range d.Outer() {
		w, err := toParent(dir, readersRule(dir))
		if err != nil {
			return err
		}

		if w != nil {
			w.close()
		}
	}

	return nil
}

// ErrWayRefused is JudgeWays's refusal of a way to a root that another account may change, which
// errors.Is tells apart in what it returns from a way that cannot be walked.
var ErrWayRefused = errors.New("a way to a root another account may change")

// refusal is err, which says why, refused as ErrWayRefused.
type refusal struct{ err error }

func (r refusal) Error() string   { return r.err.Error() }
func (r refusal) Unwrap() []error { return []error{ErrWayRefused, r.err} }

// rootHold is a root held open: the way to the folder it is in, and the directory at its name.
type rootHold struct {
	parent *way
	dir    step
}

func (r *rootHold) close() {
	r.dir.close()
	r.parent.close()
}

// holdRoot holds the root dir, one of an installation's where installation is, or an ephemeral run's:
// the way to the folder it is in walked and held as a reader holds it (toParent, readersRule), and the
// directory at dir's name in that folder, looked up there and nowhere else (lookUp); and is why that is
// not as conflux makes a root (ours), or "". A link or anything else at the name that is no directory is
// not held, and nothing in it is read. Where the way to dir, or its name, is not there, it is an error
// that is fs.ErrNotExist.
func holdRoot(dir string, installation bool) (*rootHold, string, error) {
	w, err := toParent(dir, readersRule(dir))

	switch {
	case err != nil:
		return nil, "", err
	case w == nil:
		return nil, "", &os.PathError{Op: "open", Path: dir, Err: fs.ErrNotExist}
	}

	s, link, err := lookUp(w.last().step, filepath.Base(dir))

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
		if why, err = ours(dir, s, installation); err == nil {
			return &rootHold{parent: w, dir: s}, why, nil
		}

		s.close()
	}

	w.close()

	return nil, why, err
}

// notOurs is the refusal of the root dir, an ephemeral run's where ephemeral is, for why, what holdRoot
// found at its name: nothing of conflux's to read, which the next EnsureAll makes afresh -- an
// installation's at the next command that makes its roots, an ephemeral run's at the next ephemeral run.
func notOurs(dir, why string, ephemeral bool) error {
	next := "the next up, proxy, install or start"
	if ephemeral {
		next = "the next up --ephemeral or proxy --ephemeral"
	}

	return fmt.Errorf("%s is not as conflux makes a folder of its own (%s), so conflux will not use what is in it: "+
		"%s removes it and makes it afresh", dir, why, next)
}

// OpenIn opens path, a file directly in one of d's roots that is not inside another, to read, through
// that root held (holdRoot) and never by its name: the way to the root walked from the top of its volume,
// a CONFLUX_DIR's held to parents' rule, the root's own name looked up in the folder it is in, and path's
// name looked up in the root and nowhere else, never followed. A root that is not as conflux makes one is
// none of conflux's, and is taken as not there. Where the root, or path's name in it, is not there, it is
// an error that is fs.ErrNotExist.
func (d Dirs) OpenIn(path string) (*os.File, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(path)

	if !slices.Contains(d.Outer(), dir) {
		return nil, fmt.Errorf("%s is not directly in a root of conflux's", path)
	}

	r, why, err := holdRoot(dir, !d.ephemeral)
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

	opening(dir)

	return openIn(r.dir, filepath.Base(path), path)
}

// Ours holds path, a file in one of d's roots or in a folder conflux keeps beneath one, to what a command
// needs of it before it runs it: the root held as Check holds it (holdRoot), each folder from there to
// the file looked up in the one before and nowhere else, never followed (lookUp), and each of them, and
// the file (lookAt), as conflux makes it (ours). Nil where all are; an error that is fs.ErrNotExist
// where the root, a folder on the way or the file is not there; and otherwise why one is not as conflux
// makes it. It changes nothing.
func (d Dirs) Ours(path string) error { return d.oursAs(path, isFile) }

// OursFolder is Ours for a folder in one of d's roots or beneath one, such as the bin directory a reader
// extracts into (libexec's ForUsage): the folder judged as each one on the way to it is.
func (d Dirs) OursFolder(path string) error { return d.oursAs(path, isFolder) }

// oursAs is Ours of path, what is there taken as conflux's only where it is of kind want.
func (d Dirs) oursAs(path string, want kind) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	i := slices.IndexFunc(d.Outer(), func(root string) bool { return above(root, path) })
	if i < 0 {
		return fmt.Errorf("%s is not in a root of conflux's", path)
	}

	root := d.Outer()[i]
	installation := !d.ephemeral

	r, why, err := holdRoot(root, installation)

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
			why, err = ours(p, s, installation)
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
			why, err = ours(path, s, installation)
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
// errors.Is, as the walk's refusals say.
var errNotDir = fmt.Errorf("%w", syscall.ENOTDIR)

// opening is called once OpenIn holds the root dir, before it opens anything in it: nothing, but where
// a test puts another root at the name meanwhile.
var opening = func(string) {}

// wayRule is the rule the way to d's root dir is held to as EnsureAll makes it: the boot service's
// (serviceRule) for an installation's root, which the service runs from at every start and judges
// the way to as it starts, so that a command making it refuses up front what the service would
// refuse; parents' for the account running conflux (parentsRule) for an ephemeral run's.
func (d Dirs) wayRule(dir string) judgement {
	if d.ephemeral {
		return parentsRule(dir)
	}

	return serviceRule(dir)
}

// Outer is each of d's roots that sits inside no other (roots), once: the ones conflux makes, judges
// and removes, taking those inside with them -- run and logs on Windows and in a CONFLUX_DIR. The
// system's shared log directory, which macOS and FreeBSD keep the service's log in, is never one.
func (d Dirs) Outer() []string {
	var outer []string

	for dir, inside := range d.roots() {
		if !inside {
			outer = append(outer, dir)
		}
	}

	return outer
}

// Inside reports whether dir sits strictly inside one of d's roots (roots, above): an ephemeral run's
// root inside a CONFLUX_DIR's, or a log directory inside the state root, which goes with it.
func (d Dirs) Inside(dir string) bool {
	for root := range d.roots() {
		if above(root, dir) {
			return true
		}
	}

	return false
}

// roots is each of d's directories that is conflux's, once: every one set but the system's shared
// log directory -- Config and State are one directory on macOS, Windows and under CONFLUX_DIR --
// and whether it sits inside another of them, which holds it.
func (d Dirs) roots() iter.Seq2[string, bool] {
	return func(yield func(string, bool) bool) {
		dirs := []string{d.Config, d.State, d.Run, d.Log}

		for i, dir := range dirs {
			if dir == "" || dir == sharedLog || slices.Contains(dirs[:i], dir) {
				continue
			}

			if !yield(dir, within(dir, dirs)) {
				return
			}
		}
	}
}

// Check holds each of d's roots that is there to what a command needs of it before it reads, runs or
// signals anything in it by its name (holdRoot): the way to a CONFLUX_DIR's held to parents' rule, the
// CONFLUX_DIR included, and the directory at each root's name as conflux makes a root (ours) -- not a
// link, owned by root or the account running conflux, and written by nobody else; on Windows owned by
// SYSTEM, the Administrators or TrustedInstaller, and granting nobody else anything (judgedFor). Nothing
// else can have put anything in such a root, so what it holds is not judged. It changes nothing: a root
// that fails is refused, saying why.
//
// Where none of d's roots is there, nothing of conflux's is installed, and Check is an error that is
// fs.ErrNotExist: each caller then takes its own way for that, reading nothing.
func (d Dirs) Check() error {
	there := false

	for _, dir := range d.Outer() {
		r, why, err := holdRoot(dir, !d.ephemeral)

		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return err
		case r != nil:
			r.close()
		}

		if why != "" {
			return notOurs(dir, why, d.ephemeral)
		}

		there = true
	}

	if !there {
		return fmt.Errorf("conflux is not installed in %s: %w", d.State, fs.ErrNotExist)
	}

	return nil
}

// looking is called with the path of each name before a walk looks it up, and before makeWay and
// makeRoot make it or look it up: nothing, but where a test makes something at the name meanwhile.
var looking = func(string) {}

// chosen reports whether dir is the CONFLUX_DIR or inside it: a directory whoever set the variable
// chose, rather than one of the platform's, so makeRoot and the readers hold the directories above it
// to account too.
func chosen(dir string) bool {
	root := Root()

	return root != "" && (filepath.Clean(dir) == root || above(root, dir))
}

// judgement is what a walk holds the way to a directory to: each directory it looks a name up in,
// and each link it follows, which s holds open as itself and p names, through no link -- a link by
// the directory it is in and its name; nil, or why the way is refused.
type judgement func(p string, s step, link bool) error

// place is a directory a walk holds open, and its path, through no link.
type place struct {
	step
	path string
}

// way is where a walk ended: the directories it holds open, the top of the volume first and the one
// it ended in last -- the directory walked to, where that is there. Where one of the directory's own
// names was not there, left is it and the names after it, and missing why.
type way struct {
	places  []place
	left    []string
	missing error
}

// last is the directory the way ends in.
func (w *way) last() place { return w.places[len(w.places)-1] }

func (w *way) push(s step, path string) { w.places = append(w.places, place{s, path}) }

// back goes to the directory the last one is in, as ".." leads: the one held before it, but at the
// top of the volume, whose ".." is itself.
func (w *way) back() {
	if n := len(w.places); n > 1 {
		w.places[n-1].close()
		w.places = w.places[:n-1]
	}
}

// top lets every directory go, and holds the top of the volume vol (openTop).
func (w *way) top(vol string) error {
	w.close()

	s, err := openTop(vol)
	if err != nil {
		return err
	}

	w.push(s, vol+string(filepath.Separator))

	return nil
}

// close lets every directory the way holds go.
func (w *way) close() {
	for _, p := range w.places {
		p.close()
	}

	w.places = nil
}

// walk is the way to dir, walked a name at a time from the top of its volume and held open as it
// goes: each name looked up in the directory held before it and nowhere else, never following what
// is there (lookUp). A directory is held, and gone on from; a link is read as itself (readLink) and
// gone on from where it leads -- the top of the volume it names, the top of this one, or the
// directory it is in -- up to 255 links. Where judge is given, each directory is held to it before a
// name is looked up in it, and each link before it is followed, each path once: every directory a
// lookup of dir looks a name up in, and every link it follows. That is all whoever may change it
// could put another directory where dir leads by: each directory above dir as it is spelled, and for
// each link on the way the directory it is in, the link itself -- an account that owns one can point
// it elsewhere -- and the directories above where it leads, where the next link may be. The directory
// dir leads to is held, not judged.
//
// At one of dir's own names that is not there the walk ends, holding the directory it was to be
// looked up in, with the names left. Anything else refuses dir: a link that leads nowhere -- to a
// name not there, which is no directory dir could be made in, nor one that is not there -- or that
// cannot be read -- on Windows, one that may lead off this machine (windowsLinkTarget), which nothing
// then follows -- a name that is not a directory, more than 255 links, or a lookup the system
// refuses.
func walk(dir string, judge judgement) (*way, error) {
	w := &way{}
	if err := w.walk(dir, judge); err != nil {
		w.close()

		return nil, err
	}

	return w, nil
}

// walk is walk, ending in w.
func (w *way) walk(dir string, judge judgement) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}

	return w.resolve(dir, judge)
}

// resolve is walk of dir, an absolute path, as it is spelled rather than cleaned: a ".." in it goes back
// to the directory held before, as the system resolves one after a link, so that where a link leads is
// walked exactly as a lookup of it would go.
func (w *way) resolve(dir string, judge judgement) error {
	vol := filepath.VolumeName(dir)
	if err := w.top(vol); err != nil {
		return err
	}

	judged := map[string]bool{}

	// What is left to look up ends in what is left of dir's own names, plain long, after what the
	// links followed put before it: while any is, via is the first of those links.
	rest := dir[len(vol):]
	plain, via := len(rest), ""

	for links := 0; ; {
		var name string
		if name, rest = nextName(rest); name == "" {
			return nil
		}

		own := len(rest) < plain
		if own {
			plain, via = len(rest), ""
		}

		switch name {
		case ".":
			continue
		case "..":
			w.back()

			continue
		}

		at := w.last()
		if judge != nil && !judged[at.path] {
			if err := judge(at.path, at.step, false); err != nil {
				return err
			}

			judged[at.path] = true
		}

		p := filepath.Join(at.path, name)
		looking(p)

		s, link, err := lookUp(at.step, name)

		switch {
		case errors.Is(err, fs.ErrNotExist) && !own:
			return fmt.Errorf("resolve %s: %s is a link conflux cannot follow: %v", dir, via,
				&os.PathError{Op: "open", Path: p, Err: err})
		case errors.Is(err, fs.ErrNotExist):
			w.left, w.missing = []string{name}, &os.PathError{Op: "open", Path: p, Err: err}
			for name, rest = nextName(rest); name != ""; name, rest = nextName(rest) {
				w.left = append(w.left, name)
			}

			return nil
		case err != nil:
			return fmt.Errorf("resolve %s: %w", dir, &os.PathError{Op: "open", Path: p, Err: err})
		case !link:
			w.push(s, p)

			continue
		}

		if links++; links > 255 {
			s.close()

			return fmt.Errorf("resolve %s: more than 255 links", dir)
		}

		target, err := readLink(s)

		switch {
		case err != nil:
			err = fmt.Errorf("resolve %s: %s is a link conflux cannot follow: %v", dir, p, err)
		case judge != nil && !judged[p]:
			err, judged[p] = judge(p, s, true), true
		}

		s.close()

		if err != nil {
			return err
		}

		if own {
			via = p
		}

		// What the link names goes before what was left, looked up from the directory the link is
		// in, or from the top of the volume it names.
		rest = target + string(filepath.Separator) + rest

		switch v := filepath.VolumeName(target); {
		case v != "":
			rest = rest[len(v):]

			if err := w.top(v); err != nil {
				return err
			}
		case target != "" && os.IsPathSeparator(target[0]):
			for len(w.places) > 1 {
				w.back()
			}
		}
	}
}

// makeWay makes the names w was left with, the folders missing on the way to the root dir, each in the
// directory held before it and nowhere else (makeStep), and holds each open as itself, never by its
// name: a link or a directory somebody else made at the name meanwhile would answer for that -- a sticky
// directory such as /tmp, and C:\, let anybody make a name not taken yet, and the owner of a directory
// on the way may make anything in it. A link at a name, there by the time conflux makes it or once it
// has, is refused; each folder on the way that it goes into, made by conflux or taken, is held to rule
// before anything is made in it, as the folder it was made in was. It is the folders it made, which
// EnsureAll records (recordWay), those made before a refusal among them: each as dir, an absolute path,
// spells it, rather than as the walk reached it through a link on the way, since that is how Way and
// RemoveWay know them -- by the folders above the roots as d spells them.
func makeWay(dir string, w *way, rule judgement) ([]string, error) {
	var made []string

	// The names left are the last of the folder dir is in, as dir spells it.
	spelled := filepath.Dir(dir)
	for range w.left {
		spelled = filepath.Dir(spelled)
	}

	for _, name := range w.left {
		at := w.last()
		p := filepath.Join(at.path, name)
		spelled = filepath.Join(spelled, name)

		looking(p)

		s, held, err := makeStep(at.step, name)

		taken := errors.Is(err, fs.ErrExist)
		if err != nil && !taken {
			return made, &os.PathError{Op: "mkdir", Path: p, Err: err}
		}

		if err == nil {
			made = append(made, spelled)
		}

		if !held {
			looking(p)

			var link bool

			switch s, link, err = lookUp(at.step, name); {
			case err != nil && taken:
				return made, fmt.Errorf("%s was made by somebody else while conflux made the way to %s, and is not a "+
					"directory conflux can go into (%v).\n  Remove it, then run this again", p, dir, err)
			case err != nil:
				return made, &os.PathError{Op: "open", Path: p, Err: err}
			case link:
				s.close()

				return made, fmt.Errorf("%s, %s, was made while conflux made the way to %s, which conflux will not "+
					"follow.\n  Remove it, then run this again", p, aLink, dir)
			}
		}

		if err := rule(p, s, false); err != nil {
			s.close()

			return made, err
		}

		w.push(s, p)
	}

	w.left, w.missing = nil, nil

	return made, nil
}

// nextName is the first name in path and what follows it, separators around it dropped: "" when
// none is left.
func nextName(path string) (name, rest string) {
	i := 0
	for i < len(path) && os.IsPathSeparator(path[i]) {
		i++
	}

	j := i
	for j < len(path) && !os.IsPathSeparator(path[j]) {
		j++
	}

	return path[i:j], path[j:]
}

// within reports whether dir sits strictly inside another of dirs (above).
func within(dir string, dirs []string) bool {
	return slices.ContainsFunc(dirs, func(other string) bool { return other != "" && above(other, dir) })
}

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

// CheckSocketLen refuses a run directory that would produce a socket path the
// kernel cannot bind.
//
// A sockaddr_un holds 104 bytes of path on macOS and the BSDs and 108 on Linux,
// and anchord refuses a longer one. The defaults are far inside that; CONFLUX_DIR
// can break it. The error belongs here, with the remedy in it, rather than
// arriving from a child process as a number.
func (d Dirs) CheckSocketLen() error {
	sock := d.Socket()
	if len(sock) < sockPathMax {
		return nil
	}

	return fmt.Errorf(
		"the control socket path is %d bytes and the kernel allows %d:\n  %s\nset CONFLUX_DIR to something shorter",
		len(sock), sockPathMax-1, sock)
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
