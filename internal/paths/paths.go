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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// Dirs are the four roots. Get one from Default.
type Dirs struct {
	Config string
	State  string
	Run    string
	Log    string
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
			Run:    filepath.Join(root, "run"),
			Log:    log,
		}
	}

	return d
}

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

// LegacySocket is where conflux 1.0.0 put the socket, directly in the run directory, which
// an upgrade finds a daemon -- or the lock anchor leaves -- still holding.
func (d Dirs) LegacySocket() string { return filepath.Join(d.Run, "anchord.sock") }

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
// SYSTEM's and Administrators' instead, and what is created beneath it inherits that.
// The system's shared log directory is not conflux's, and is left alone.
func (d Dirs) EnsureAll() error {
	dirs := []string{d.Config, d.State, d.Run, d.Log}

	for i, dir := range dirs {
		// Config and State are one directory on macOS, Windows and under CONFLUX_DIR.
		if dir == "" || dir == sharedLog || slices.Contains(dirs[:i], dir) {
			continue
		}

		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}

		if !within(dir, dirs) {
			if err := secure(dir); err != nil {
				return err
			}
		}
	}

	return nil
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
