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
	"io"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
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
}

// Default is where this platform keeps them.
//
// CONFLUX_DIR overrides all four at once, rooting them in one directory. That is
// what the tests use, and what a second installation beside the machine's own is
// rooted in, its boot service included; see Root. It changes where conflux keeps
// things and not what it needs: the verbs that change anything still need root.
func Default() Dirs {
	d := platformDirs()

	if root := Root(); root != "" {
		// A log directory of its own only where the platform writes the service's output
		// to a file at all: where journald or syslog keeps it, nothing would write there.
		log := ""
		if d.Log != "" {
			log = filepath.Join(root, "logs")
		}

		return Dirs{
			Config: root,
			State:  root,
			Run:    filepath.Join(root, runName),
			Log:    log,
		}
	}

	return d
}

// runName is the run directory's name inside a root that holds it: a CONFLUX_DIR's, an
// ephemeral run's, and Windows's own. On Windows secure makes it as it secures any root, so the
// root holds something (fill).
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
// than wherever conflux happened to be run from. See service.Place.
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

// EnsureAll creates the four roots at the modes they need.
//
// 0700, including Config: it sits beside nothing that another user has any business
// reading, and a 0600 file in a traversable directory is one rename away from being
// replaced. A root that already exists is held to the same: one another account owns is
// refused, and one of conflux's own that is wider is narrowed -- except a root's 0710,
// which is how the supervisor lets anchord's own account pass through the state and run
// directories to the few things in them that anchord needs, and which lists nothing and
// lets that account create nothing. On
// Windows, where a mode means nothing, each root that is not inside another is made
// SYSTEM's and Administrators' instead, as it is created where it is not there yet
// (makeRoot), and what is created beneath it inherits that; a root inside another, made here
// by its name, is the Administrators' too, as everything an elevated conflux makes is
// (ElevatedDefaultOwner). A CONFLUX_DIR's way is held to the
// rule of whoever the root is for (wayRule). The system's shared log directory is not
// conflux's, and is left alone. An installation's state root keeps a record of each folder makeRoot
// made on the way to a root, once that root is secured (recordWay), for uninstall to remove (Way,
// RemoveWay); one made by an EnsureAll that failed before its state root was secured is not recorded.
func (d Dirs) EnsureAll() error {
	var made []string

	state := false

	err := func() error {
		for dir, inside := range d.roots() {
			if inside {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					return fmt.Errorf("create %s: %w", dir, err)
				}

				continue
			}

			m, err := makeRoot(dir, d.wayRule(dir))
			if made = append(made, m...); err != nil {
				return fmt.Errorf("create %s: %w", dir, err)
			}

			if err := secure(dir, !d.ephemeral); err != nil {
				return err
			}

			state = state || dir == d.State
		}

		return nil
	}()

	if len(made) > 0 && state && !d.ephemeral {
		if recorded := d.recordWay(made); err == nil {
			err = recorded
		}
	}

	return err
}

// wayName is the record, in an installation's state root, of the folders conflux made on the way to
// its roots: one absolute path a line.
const wayName = "way"

// recordWay adds made, folders makeRoot made on the way to d's roots, to the record in d's state root,
// which EnsureAll has secured: what it held kept, each once, written to a file beside it and renamed
// over it.
func (d Dirs) recordWay(made []string) error {
	record := filepath.Join(d.State, wayName)

	way, err := d.readWay()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	for _, p := range made {
		if !slices.Contains(way, p) {
			way = append(way, p)
		}
	}

	tmp, err := os.CreateTemp(d.State, ".tmp-way-*")
	if err != nil {
		return fmt.Errorf("record the way to %s: %w", d.State, err)
	}

	_, err = tmp.WriteString(strings.Join(way, "\n") + "\n")
	if err == nil {
		err = tmp.Sync()
	}

	if cerr := tmp.Close(); err == nil {
		err = cerr
	}

	if err == nil {
		err = os.Rename(tmp.Name(), record)
	}

	if err != nil {
		os.Remove(tmp.Name())

		return fmt.Errorf("record the way to %s: %w", d.State, err)
	}

	SyncDir(d.State)

	return nil
}

// readWay is the record in d's state root, a line a folder, at most wayMax bytes of it: opened through
// the root held (OpenIn), as a file another account may have put there is, and refused unless it is a
// plain file (PlainFile).
func (d Dirs) readWay() ([]string, error) {
	path := filepath.Join(d.State, wayName)

	f, err := d.OpenIn(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if fi, err := f.Stat(); err != nil || !PlainFile(fi, wayMax) {
		return nil, fmt.Errorf("%s is not a plain file of at most %d bytes, so it is not read as the record of "+
			"the way conflux made", path, wayMax)
	}

	b, err := io.ReadAll(io.LimitReader(f, wayMax))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return strings.Fields(string(b)), nil
}

// wayMax is as much of the way record as is read: far more than any way conflux makes.
const wayMax = 64 << 10

// Way is the record of the folders conflux made on the way to d's roots (EnsureAll), deepest first,
// for uninstall to read before it removes the roots, the state root holding the record among them,
// and to hand to RemoveWay after. It is read whatever the readers' check says of what the state root
// holds, so that uninstall leaves nothing conflux made even there, since all it can lead to is
// removing: only folders above one of d's roots are taken from it, and RemoveWay removes nothing
// anywhere else, only a folder that is empty, and only through handles, never through a link. The
// record is read through the state root held as OpenIn holds it, a CONFLUX_DIR's way held to parents'
// rule and a link at the root's name followed only where conflux would follow it, since a way or a link
// another account may change could lead the read elsewhere, and as a file another account may have put
// there (readWay). Nil where there is no record, or no state root, and for an ephemeral run's roots,
// which keep none.
func (d Dirs) Way() ([]string, error) {
	if d.ephemeral {
		return nil, nil
	}

	recorded, err := d.readWay()

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	}

	var way []string

	for _, p := range recorded {
		if filepath.IsAbs(p) && filepath.Clean(p) == p && !slices.Contains(way, p) &&
			slices.ContainsFunc([]string{d.Config, d.State, d.Run, d.Log}, func(root string) bool {
				return root != "" && above(p, root)
			}) {
			way = append(way, p)
		}
	}

	return deepestFirst(way), nil
}

// RemoveWay removes each folder of way, folders conflux made on the way to its roots (Way), that is
// empty, deepest first, and is those it removed: each removed from the folder it is in, as the walk
// to that holds it (walk), never by its name and never following a link, a folder above a CONFLUX_DIR
// on a way held to parents' rule, as RemoveRoot holds a CONFLUX_DIR's, and one on a platform root's
// way not judged. A folder that holds anything, is not there, or is no longer a folder -- a link put at
// its name among them -- is left.
func RemoveWay(way []string) ([]string, error) {
	var (
		removed []string
		errs    []error
	)

	for _, dir := range deepestFirst(slices.Clone(way)) {
		judge := judgement(nil)
		if root := Root(); root != "" && above(dir, root) {
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

// removeWayFolder is RemoveWay's removal of dir, an empty folder, from the folder it is in, held as
// the walk judged by judge reaches it, and whether it removed it.
func removeWayFolder(dir string, judge judgement) (bool, error) {
	w, err := walk(filepath.Dir(dir), judge)
	if err != nil {
		return false, err
	}
	defer w.close()

	if w.missing != nil {
		return false, nil
	}

	if at := w.last(); judge != nil {
		if err := judge(at.path, at.step, false); err != nil {
			return false, err
		}
	}

	return removeEmpty(w.last().step, filepath.Base(dir), dir)
}

// above reports whether dir is a folder strictly above path.
func above(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)

	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// deepestFirst sorts way, folders, those with the most names first, and is it.
func deepestFirst(way []string) []string {
	depth := func(p string) int { return strings.Count(filepath.Clean(p), string(filepath.Separator)) }

	slices.SortStableFunc(way, func(a, b string) int { return depth(b) - depth(a) })

	return way
}

// wayRule is the rule the way to d's root dir is held to

// RemakeOld removes from an installation's roots what conflux makes again there by its name and
// finds not meeting the rule secure holds what a root holds to for the boot service -- owned by an
// account other than SYSTEM and the Administrators, the administrator running conflux among them, or
// granting such an account a right that rule refuses, as an older conflux on a Windows client, or an
// administrator by hand, may have left it -- and is what it removed, for the caller to make again
// fresh: EnsureAll, the extraction, the service's copy of conflux and the lock files each make theirs
// where it is not there. A handle opened while that account could change such a thing keeps its
// rights whoever owns it after, so it is made again rather than taken over. Each is removed through
// handles held on the root and on what it holds, never by its name and never through a link, a folder
// with all it holds. Anything else not meeting the rule -- what conflux does not make again, the
// identity, configuration and state among it, or what is deeper in a folder that meets it -- is
// refused, naming it, and left as it is; so is a root another account owns or may move what is in.
// What conflux makes again is in use while a supervisor runs from the root, so the caller stops it
// first: what cannot be removed is refused, naming it. An ephemeral run's roots, which no service
// runs from, and Unix's, where nothing conflux made fails that rule, hold nothing to remove.
func (d Dirs) RemakeOld() ([]string, error) {
	if d.ephemeral {
		return nil, nil
	}

	var removed []string

	for dir, inside := range d.roots() {
		if inside {
			continue
		}

		r, err := remakeOld(d, dir)
		if removed = append(removed, r...); err != nil {
			return removed, err
		}
	}

	return removed, nil
}

// RemoveRoot removes the root dir and everything in it, and says whether anything was at its name,
// following nothing: the way to dir walked from the top of its volume and held open a directory at a
// time (toParent), and dir removed from the directory it is in, as that walk holds it, each thing below
// opened through the directory holding it and never by its name, a link or a junction anywhere --
// at dir's own name included -- removed as itself, and what it leads to never touched. Nothing in
// the root is read or judged first, so a root the readers' check refuses is removed as safely as one
// it takes. A CONFLUX_DIR's way is held to parents' rule, for the account running conflux, as the
// readers' check holds it, the directory dir is in included, since a way another account may change
// could lead the removal elsewhere; a platform root's way, the system's own, is not, as it is not
// when the root is made (makeRoot). Where nothing is at dir's name, or on the way to it, nothing is
// removed.
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

// readersRule is the rule a command that reads or removes what is at the root dir, rather than
// making it, holds dir's way to: parents' rule, for the account running conflux, where dir is the
// CONFLUX_DIR root or inside it (chosen), as the readers' check holds it; none for a platform root's
// way, the system's own, as makeRoot does not judge it either.
func readersRule(dir string) judgement {
	if chosen(dir) {
		return parentsRule(dir)
	}

	return nil
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

// JudgeWays holds the way to each of d's roots not inside another, as RemoveRoot and OpenIn walk it
// (toParent), to the rule a reader holds it to (readersRule): a CONFLUX_DIR's to parents' rule, for
// the account running conflux, the directory the root is in included, refused where another account
// may change it, since that could lead what is done there elsewhere. Nothing at the roots' names is
// looked up or read. Nil where every way passes, where a name on one is not there, and for the
// platform roots, whose ways are the system's own and not judged.
func (d Dirs) JudgeWays() error {
	for dir, inside := range d.roots() {
		judge := readersRule(dir)
		if inside || judge == nil {
			continue
		}

		w, err := toParent(dir, judge)
		if err != nil {
			return err
		}

		if w != nil {
			w.close()
		}
	}

	return nil
}

// OpenIn opens path, a file directly in one of d's roots that is not inside another, to read, as
// OpenUntrusted opens a file, through that root held open first (holdRoot), and never by its name: the
// way to the root walked from the top of its volume, a CONFLUX_DIR's held to parents' rule; the root's
// own name looked up in the directory it is in, a link there followed only where conflux would follow
// it in daily use, to a directory conflux's alone (follow); the root's owner root, SYSTEM, the
// Administrators or the account running conflux; and path's name looked up in the root and nowhere
// else, never followed. A lookup by name of path would follow whatever is at each name on the way, the
// root's own among them, before anything had judged it: to a directory another account controls, or,
// on Windows, a share that signs this machine in. A file another account may have put there is still
// the caller's to judge (PlainFile). Where the root, or path's name in it, is not there, it is an error
// that is fs.ErrNotExist.
func (d Dirs) OpenIn(path string) (*os.File, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(path)

	outer := false
	for root, inside := range d.roots() {
		outer = outer || !inside && root == dir
	}

	if !outer {
		return nil, fmt.Errorf("%s is not directly in a root of conflux's", path)
	}

	r, err := holdRoot(dir)
	if err != nil {
		return nil, err
	}
	defer r.close()

	if err := r.usable(dir); err != nil {
		return nil, err
	}

	return openIn(r.dir, filepath.Base(path), path)
}

// rootHold is a root held open as a directory, through no link: the way to the directory its name is
// in, which holds that directory last; its name there; the directory it is, what is at the name or,
// where that is a link (link), where it leads, and led, the way the link led along, which holds it then;
// and refused, where the name is a link conflux does not follow, or anything else that is not a
// directory, why.
type rootHold struct {
	parent  *way
	name    string
	dir     step
	link    bool
	led     *way
	refused error
}

// close lets the root go, and every directory held on the way to it.
func (r *rootHold) close() {
	switch {
	case r.led != nil:
		r.led.close()
	case !r.link && r.refused == nil:
		r.dir.close()
	}

	r.parent.close()
}

// usable refuses the root dir, as r holds it, where nothing in it is to be read or changed: a name
// that is a link conflux does not follow, or that is not a directory (refused), or a directory at the
// name itself that an account other than root, SYSTEM, the Administrators and the account running
// conflux owns (rootOwner). A directory a link leads to is judged as the link is followed (follow).
func (r *rootHold) usable(dir string) error {
	switch {
	case r.refused != nil:
		return r.refused
	case !r.link:
		return rootOwner(dir, r.dir)
	}

	return nil
}

// holdRoot holds the root dir open as a directory, through no link: the way to the directory it is in
// walked from the top of its volume and held, as a reader holds it (toParent, readersRule), and dir's
// own name looked up in that directory and nowhere else (lookUp). A directory there is the root,
// judged by nothing yet (usable); a link there is followed only where conflux would follow it (follow),
// and is otherwise refused, as anything else at the name is, unfollowed and left for the caller to
// remove as itself or refuse. Where the way to dir, or its name, is not there, it is an error that is
// fs.ErrNotExist.
func holdRoot(dir string) (*rootHold, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	judge := readersRule(dir)

	w, err := toParent(dir, judge)

	switch {
	case err != nil:
		return nil, err
	case w == nil:
		return nil, &os.PathError{Op: "open", Path: dir, Err: fs.ErrNotExist}
	}

	r := &rootHold{parent: w, name: filepath.Base(dir)}

	s, link, err := lookUp(w.last().step, r.name)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		w.close()

		return nil, &os.PathError{Op: "open", Path: dir, Err: err}
	case err != nil:
		r.refused = fmt.Errorf("%s is no directory conflux can hold, so conflux will not use it: %v", dir,
			&os.PathError{Op: "open", Path: dir, Err: err})
	case link:
		r.link = true
		r.refused = r.follow(dir, s, judge)
	default:
		r.dir = s
	}

	return r, nil
}

// follow holds the directory the link s, at the root dir's name, leads to as r.dir, and is nil, or
// refuses it, saying why, as conflux refuses to follow such a link in daily use: one the walk cannot
// follow (readLink) -- on Windows one that may lead off this machine, which nothing then follows --
// or one another account may point elsewhere (heldLink); where it leads walked as walk resolves a
// link, from the directory the link is in or the top of the volume it names, held to judge, the rule
// dir's way is held to; and the directory it leads to held to the readers' check (ledRoot): its owner,
// and nobody else may write it. A link to nothing, or to the directory it is in or one above it, is
// refused too. s is let go of either way.
func (r *rootHold) follow(dir string, s step, judge judgement) error {
	target, err := readLink(s)
	if err != nil {
		err = fmt.Errorf("%s is a link conflux cannot follow, so conflux will not use it: %v", dir, err)
	} else {
		err = heldLinkRule(dir, s)
	}

	s.close()

	if err != nil {
		return err
	}

	in := r.parent.last().path

	led := target
	if filepath.VolumeName(target) == "" {
		if target != "" && os.IsPathSeparator(target[0]) {
			led = filepath.VolumeName(in) + target
		} else {
			led = in + string(filepath.Separator) + target
		}
	}

	r.led = &way{}
	if err := r.led.resolve(led, judge); err != nil {
		r.led.close()
		r.led = nil

		return err
	}

	if r.led.missing != nil {
		return fmt.Errorf("%s is a link to %s, which is not there, so conflux will not use it: %v", dir, target,
			r.led.missing)
	}

	at := r.led.last()

	for _, above := range r.parent.places {
		if sameStep(above.step, at.step) {
			return fmt.Errorf("%s is a link to %s, the directory it is in or one above it, so conflux will not "+
				"follow it", dir, at.path)
		}
	}

	if err := ledRoot(dir, at.path, at.step); err != nil {
		return err
	}

	r.dir = at.step

	return nil
}

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

// Check holds each of d's roots that is there -- each EnsureAll secures, which holds the rest -- to
// what a command needs of it before it reads, runs or removes anything in it by its name: a
// lookup by name follows whatever is at the name, and whoever could plant a configuration, a pid
// record, a token or a binary there would have this conflux act on theirs. It is lighter than
// EnsureAll, and changes nothing: a root that fails is refused, saying why, and none is made or
// narrowed. Each is held, as itself where it is a link, to its owner, which must be root, SYSTEM,
// the Administrators or the account running conflux, and to who else may retarget or write it,
// which must be nobody -- on Windows by the DACL a secured root keeps (secure), which grants nobody
// else anything, a link at its name that leads off this machine refused; on Unix by its mode and its
// ACL as found, the sticky bit letting nothing through. A CONFLUX_DIR is held to its parents too, by
// the rule EnsureAll makes its way by, for the account running conflux (parentsRule), a link
// anywhere on its way that leads off this machine refused on Windows (walk). What
// a root holds is not judged: EnsureAll goes into it, and Foreign, which is this and that, and
// this does not.
//
// Where none of d's roots is there, nothing of conflux's is installed, and Check is an error that
// is fs.ErrNotExist: each caller then takes its own way for that, reading nothing, since what a
// lookup by name would find at a name that was not there a moment ago is whoever made it first's.
func (d Dirs) Check() error {
	there := false

	for dir, inside := range d.roots() {
		if inside {
			continue
		}

		switch err := checkRoot(dir); {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return err
		default:
			there = true
		}
	}

	if !there {
		return fmt.Errorf("conflux is not installed in %s: %w", d.State, fs.ErrNotExist)
	}

	return nil
}

// Foreign is what a reader of a root another process keeps -- an ephemeral run's, which
// %ProgramData% or /tmp lets anybody make first -- refuses it with, before it reads, runs or
// signals anything in it, or nil where it passes: the root held as Check holds every root
// (checkRoot), and anything in it another account could have put there or may change (contents),
// since a root's own owner, mode and DACL are not the whole of that: on Windows an entry keeps the
// owner and DACL it was made with, and on Unix narrowing a root takes nothing out of it. A
// directory another account made, or could have planted something in, is none of conflux's to
// use, and nothing is run from one. Where dir is not there it is an
// error that is fs.ErrNotExist, which a reader takes as no root, reading nothing at its name: what
// is there by the time it looks again is whoever made it first's.
func Foreign(dir string) error {
	return foreign(dir)
}

// looking is called with the path of each name before a walk looks it up, and before makeWay makes
// it or looks it up: nothing, but where a test makes something at the name meanwhile.
var looking = func(string) {}

// chosen reports whether dir is the CONFLUX_DIR root or inside it: a directory whoever set
// the variable chose, rather than one of the platform's, so makeRoot and the readers' check
// hold the directories above it to account too.
func chosen(dir string) bool {
	root := Root()
	if root == "" {
		return false
	}

	rel, err := filepath.Rel(root, dir)

	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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

// judgeWay holds the way to dir to rule, as walk does, and refuses dir where a name on it is not
// there.
func judgeWay(dir string, rule judgement) error {
	w, err := walk(dir, rule)
	if err != nil {
		return err
	}

	w.close()

	if w.missing != nil {
		return fmt.Errorf("resolve %s: %w", dir, w.missing)
	}

	return nil
}

// makeRoot creates the root dir where it is not there yet, and each directory missing on the way to
// it, from the last directory there that the walk to it holds open (makeWay). A CONFLUX_DIR's way is
// held to rule, parents' rule for whoever the root is for (wayRule), as far as it is there, before
// anything is made, and makeWay holds the rest to it as it goes: every directory a lookup of dir looks a name up in, and every link
// it follows, is judged once, here and nowhere else: secure, which EnsureAll calls after it, judges
// the root and what it holds, and not its way. Anything already at the root's name is secure's; and a link that leads nowhere is
// refused by the walk, with nothing made where it leads.
func makeRoot(dir string, rule judgement) ([]string, error) {
	judge := judgement(nil)
	if chosen(dir) {
		judge = rule
	}

	w, err := walk(dir, judge)
	if err != nil {
		return nil, err
	}
	defer w.close()

	if w.missing == nil {
		return nil, nil
	}

	return makeWay(dir, w, rule)
}

// makeWay makes the names w was left with, the root dir last, each in the directory held before it
// and nowhere else (makeStep), and holds each open as itself, never by its name: a link or a
// directory somebody else made at the name meanwhile would answer for that -- a sticky directory such
// as /tmp, and C:\, let anybody make a name not taken yet, and the owner of a directory on the way
// may make anything in it. A link at a name, there by the time conflux makes it or once it has, is
// refused; each directory on the way that it goes into, made by conflux or taken, is held to rule
// before anything is made in it, as the directory it was made in was; and the one at the root's own
// name is the root, which secure judges as it judges any root found there. It is the folders on the
// way it made, the root aside, which EnsureAll records (recordWay), those made before a refusal
// among them.
func makeWay(dir string, w *way, rule judgement) ([]string, error) {
	var made []string

	for i, name := range w.left {
		at := w.last()
		p, root := filepath.Join(at.path, name), i == len(w.left)-1

		looking(p)

		s, held, err := makeStep(at.step, name)

		taken := errors.Is(err, fs.ErrExist)
		if err != nil && !taken {
			return made, &os.PathError{Op: "mkdir", Path: p, Err: err}
		}

		if err == nil && !root {
			made = append(made, p)
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

		if root {
			s.close()

			return made, nil
		}

		if err := rule(p, s, false); err != nil {
			s.close()

			return made, err
		}

		w.push(s, p)
	}

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

// within reports whether dir sits strictly inside another of dirs.
func within(dir string, dirs []string) bool {
	for _, other := range dirs {
		if other == "" || other == dir {
			continue
		}

		if rel, err := filepath.Rel(other, dir); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			return true
		}
	}

	return false
}

// ClearExcept removes everything in dir but keep, following nothing in it (os.RemoveAll), and is the
// paths of what it removed, however far it got: what a run killed before it could clean up left in
// its root, which the next run starts without, and what supervisors and extractions before an update
// left in the run and bin directories.
func ClearExcept(dir, keep string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var removed []string

	for _, e := range entries {
		if p := filepath.Join(dir, e.Name()); p != keep {
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
