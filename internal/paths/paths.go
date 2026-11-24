// Package paths is every filesystem path conflux uses, decided in one place.
//
// conflux is system-scoped: one configuration per machine, root-owned, with no
// home directory anywhere in it. That is a decision rather than an oversight. The
// boot service runs as root or LocalSystem, so a path under $HOME is a path the
// service cannot read, and a home directory is wrong under a unit with User=, wrong
// under ProtectHome=, and wrong for anyone who ran conflux with sudo -H.
//
// Everything conflux keeps on the machine is in one directory, .conflux, in the place
// each platform keeps a system service's data: what the operator asked for, the
// identity, what conflux derived, the extracted anchor pair, the copy of conflux the
// boot service runs, and, in run/, the socket, the token and the readiness marker. One
// directory, so that the supervisor can keep it exactly as it should be and uninstall
// can take all of it. It is fixed: nothing a person sets moves it.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// Dirs is a conflux root: the machine's .conflux, or an ephemeral run's. Get the
// machine's from Default.
type Dirs struct {
	Root string
}

// platform is the platform's own root, worked out the first time Default is asked for it
// rather than as the package is initialised: on Windows that is a call into shell32, which
// version, cert, and every other command that never reads the root, need not load.
var platform = sync.OnceValue(platformRoot)

// root is a test's root, which Default gives in place of the platform's once UseRoot has set
// rooted, with an ephemeral run kept beside it.
var (
	root   string
	rooted bool
)

// Default is where this platform keeps conflux.
func Default() Dirs {
	if rooted {
		return Dirs{Root: root}
	}

	return Dirs{Root: platform()}
}

// UseRoot roots Default in dir, and an ephemeral run beside it in dir+"-ephemeral", until
// restore is called. It is for tests alone: nothing in conflux calls it, and no flag or
// environment variable reaches it, so where a release keeps things is the platform's place
// and nowhere else.
func UseRoot(dir string) (restore func()) {
	was, wasRooted := root, rooted
	root, rooted = dir, true

	return func() { root, rooted = was, wasRooted }
}

// socketName is anchord's control socket, an AF_UNIX socket on every platform, inside a
// directory of anchord's own (DaemonRun). Four letters: sun_path is 104 bytes on macOS,
// and an ephemeral root under a user's $TMPDIR there is already most of that.
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
// Derived rather than edited: it is written by the supervisor, overwritten on every
// spawn, and nothing reads it back. An operator who edits it has their edit discarded
// at the next restart, which is the right way round -- conflux.json is the file with the
// operator's intent in it.
//
// It carries the export headers, which are credentials, so it is 0600 and belongs to
// whoever anchord runs as, in the directory beside the manifest. anchord warns about
// exactly this.
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

// ServiceExecutable is the copy of conflux the boot service runs: inside the root,
// which only root (Administrators and SYSTEM on Windows) can write, rather than wherever
// conflux happened to be run from. See service.Place.
func (d Dirs) ServiceExecutable() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(d.Root, "conflux.exe")
	}

	return filepath.Join(d.Root, "conflux")
}

// Libexec is where the embedded pair is extracted, one directory per content hash.
func (d Dirs) Libexec() string { return filepath.Join(d.Root, "bin") }

// RunDir holds what lasts as long as one supervisor: the socket's directory, the token,
// the record of the anchord it started and the readiness marker. On disk with the rest,
// so the supervisor empties it as it starts rather than relying on a reboot to.
func (d Dirs) RunDir() string { return filepath.Join(d.Root, "run") }

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
// copied across. Root's alone, beside the state, because it has to outlive a supervisor.
func (d Dirs) PrivilegeFile() string { return filepath.Join(d.Root, "anchord.priv") }

// LockFile serialises everything that rewrites the configuration, the manifest or the state:
// `up`, `proxy` and `observe` writing conflux.json, a start rewriting it and state.json in
// conflux's form, a bring-up, the renewal timer, `conflux renew`, `conflux enrol`, and the
// uplink watcher's count.
//
// Beside the state rather than in RunDir, which the supervisor empties as it starts: a
// `conflux renew` that spanned a restart would hold the old file's lock while the new
// supervisor took the new one's, and the two would renew at once.
func (d Dirs) LockFile() string { return filepath.Join(d.Root, "conflux.lock") }

// ServeLockFile is held by the one supervisor serving this root for as long as it runs.
//
// One per root, because the supervisor stops whatever anchord the last one left
// running, and two supervisors would each take the other's for an orphan. Beside the
// state for the reason LockFile is.
func (d Dirs) ServeLockFile() string { return filepath.Join(d.Root, "serve.lock") }

// DaemonPIDFile names the anchord the supervisor started -- its pid and its executable --
// for as long as it runs, so a supervisor that died without stopping it can be followed
// by one that does. In RunDir, which no anchord outlives except by that kind of death, and
// read by the next supervisor before it empties the rest.
func (d Dirs) DaemonPIDFile() string { return filepath.Join(d.RunDir(), "anchord.pid") }

// RCPidFile is the supervisor's pid, as FreeBSD's daemon(8) records it for rc.subr to
// stop it by: beside the state rather than in RunDir, which the supervisor empties as it
// starts, after daemon(8) has written this.
func (d Dirs) RCPidFile() string { return filepath.Join(d.Root, "rc.pid") }

// ReadyFile is written by the supervisor once an anchor is up, and removed when it goes.
// It is what lets `conflux up` learn the anchor is up the moment it happens; see
// internal/daemon/ready.go.
//
// In RunDir rather than beside the state, because a marker must not outlive the thing it
// describes: the supervisor empties RunDir as it starts, and clears the marker on the way
// down.
func (d Dirs) ReadyFile() string { return filepath.Join(d.RunDir(), "ready") }

// EnsureAll creates the root, and RunDir inside it, at the modes they need.
//
// 0700: it sits beside nothing that another user has any business reading, and a 0600
// file in a traversable directory is one rename away from being replaced. A root that
// already exists is held to the same: one another account owns is refused, and one of
// conflux's own that is wider is narrowed -- except a root's 0710, which is how the
// supervisor lets anchord's own account pass through to the few things in it that anchord
// needs, and which lists nothing and lets that account create nothing. On Windows, where a
// mode means nothing, the root is made SYSTEM's and Administrators' instead, and what is
// created beneath it inherits that.
func (d Dirs) EnsureAll() error {
	if err := os.MkdirAll(d.Root, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", d.Root, err)
	}

	if err := secure(d.Root); err != nil {
		return err
	}

	if err := os.MkdirAll(d.RunDir(), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", d.RunDir(), err)
	}

	return nil
}

// CheckSocketLen refuses a root that would produce a socket path the kernel cannot bind.
//
// A sockaddr_un holds 104 bytes of path on macOS and the BSDs and 108 on Linux,
// and anchord refuses a longer one. The machine's root is far inside that; an ephemeral
// run's, under a user's $XDG_RUNTIME_DIR or $TMPDIR, can break it. The error belongs here,
// with the remedy in it, rather than arriving from a child process as a number.
func (d Dirs) CheckSocketLen() error {
	sock := d.Socket()
	if len(sock) < sockPathMax {
		return nil
	}

	return fmt.Errorf(
		"the control socket path is %d bytes and the kernel allows %d:\n  %s\n"+
			"an ephemeral run keeps it under $XDG_RUNTIME_DIR, or $TMPDIR where that is unset: point it at a shorter directory",
		len(sock), sockPathMax-1, sock)
}
