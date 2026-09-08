// Package paths is every filesystem path conflux uses, decided in one place.
//
// conflux is system-scoped: one configuration per machine, root-owned, with no
// home directory anywhere in it. That is a decision rather than an oversight. The
// boot service runs as root or LocalSystem, so a path under $HOME is a path the
// service cannot read -- and the previous conflux hard-coded /root/.config/conflux,
// which is wrong under a unit with User=, wrong under ProtectHome=, and wrong for
// anyone who ran it with sudo -H.
//
// Four roots, because they have four lifetimes:
//
//   - Config  what the operator asked for. Survives everything but uninstall.
//   - State   what conflux derived, plus the identity. Survives a reboot.
//   - Run     the socket and the token. Recreated on every daemon start.
//   - Log     where the platform wants logs, on the platforms that want a file.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
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
// what the tests use, and what lets someone run conflux without root at all --
// with the standing caveat that a boot service registered against a directory only
// one user can read is a boot service that will not start.
func Default() Dirs {
	if root := Root(); root != "" {
		return Dirs{
			Config: root,
			State:  root,
			Run:    filepath.Join(root, "run"),
			Log:    filepath.Join(root, "logs"),
		}
	}

	return platformDirs()
}

// Root is the CONFLUX_DIR override, or "" when this is an ordinary system install.
//
// Exported because the boot service has to know. A run rooted somewhere else is a
// separate installation of conflux, not the machine's own, and registering it under
// the machine's own service name would replace a real node with a test one -- so the
// service package names itself after this, and passes it on to the supervisor it
// registers, which would otherwise come back at boot reading /etc/conflux.
func Root() string { return os.Getenv("CONFLUX_DIR") }

// ConfigFile holds the operator's intent: mode, taints, addresses, proxies.
func (d Dirs) ConfigFile() string { return filepath.Join(d.Config, "conflux.json") }

// StateFile holds what conflux derived: the AnchorID, the credential window, which
// extracted binary set is live. Deleting it costs a status line and a lookup.
func (d Dirs) StateFile() string { return filepath.Join(d.State, "state.json") }

// ManifestFile holds the base64 anchor manifest, which contains the identity seed.
//
// This is the one file that cannot be recovered. Enrolment stores nothing on the
// server and hands back the only copy, so losing this loses the machine's AnchorID
// and its overlay address for good. 0600, and the directory around it 0700.
func (d Dirs) ManifestFile() string { return filepath.Join(d.State, "manifest.b64") }

// AnchorDir is anchord's own -dir: the bootstrap cache and the realm-link cache.
//
// Not optional. An anchor without it that adopts a renewed delegation and then
// restarts falls back to a chain whose delegation has since lapsed -- cut off, and
// unable to recover in band. Every conflux anchor sits under a delegated realm, so
// that is exactly the case anchor's warning is about.
func (d Dirs) AnchorDir() string { return filepath.Join(d.State, "anchor") }

// Libexec is where the embedded pair is extracted, one directory per content hash.
func (d Dirs) Libexec() string { return filepath.Join(d.State, "bin") }

// Socket is anchord's control socket. anchord creates it 0600; the 0700 directory
// around it is the first gate and the bearer token is the second.
func (d Dirs) Socket() string { return filepath.Join(d.Run, socketName) }

// TokenFile holds the bearer token anchorctl authenticates with. Regenerated on
// every supervisor start, so a token left by a crashed run authenticates nothing.
func (d Dirs) TokenFile() string { return filepath.Join(d.Run, "token") }

// LockFile serialises the state-changing commands against each other and against
// the supervisor. Two conflux up runs at boot -- the unit and an impatient
// operator -- is the realistic case.
func (d Dirs) LockFile() string { return filepath.Join(d.Run, "conflux.lock") }

// EnsureAll creates the four roots at the modes they need.
//
// 0700 throughout, including Config: it sits beside nothing that another user has
// any business reading, and a 0600 file in a traversable directory is one rename
// away from being replaced.
func (d Dirs) EnsureAll() error {
	for _, dir := range []string{d.Config, d.State, d.Run, d.Log} {
		if dir == "" {
			continue
		}

		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	return nil
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
