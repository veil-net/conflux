//go:build !windows

package daemon

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/veil-net/conflux/internal/account"
	"github.com/veil-net/conflux/internal/config"
	"golang.org/x/sys/unix"
)

// openUntrusted opens a file in a directory the account can write: never through a
// symlink, and never blocking on a FIFO the name was made into.
const openUntrusted = os.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK

// dropState is what the platform keeps between starts: the grants anchord -h has run under.
type dropState struct {
	smoked map[string]bool
}

// workDir is where anchord runs: nowhere of anybody's, so a relative path resolves to
// nothing private.
const workDir = "/"

// dropTo settles whether the supervisor can hand anchord to the account, and fills in
// which account that is. "" is yes; anything else is why not.
func (s *Supervisor) dropTo(p *Privilege) string {
	if os.Geteuid() != 0 {
		return "the supervisor is not root, so there is no other account it could give anchord"
	}

	if why := canGive(p); why != "" {
		return why
	}

	a, err := account.Ensure()
	if err != nil {
		s.report().Warn("%v", err)

		return "the account it runs as could not be used: " + firstLine(err)
	}

	p.As, p.UID, p.GID = a.Name, a.UID, a.GID

	if err := s.grantTraverse(*p); err != nil {
		s.report().Warn("%v", err)

		return "could not let " + a.Name + " reach anchord: " + firstLine(err)
	}

	if err := s.smoke(*p); err != nil {
		s.report().Warn("%v", err)

		return a.Name + " cannot run anchord on this host: " + firstLine(err)
	}

	// Last, once the account is known to run anchord, so a drop that fails above leaves the
	// devices as they were.
	if p.BPF == BPFOwn {
		if err := grantBPF(a.GID); err != nil {
			s.report().Warn("could not give %s read access to /dev/bpf*: %v", a.Name, err)

			return "could not give " + a.Name + " read access to /dev/bpf*, which observing needs: " + firstLine(err)
		}
	}

	return ""
}

// grantTraverse lets the account pass through the state and run directories, which list
// nothing to it, to the one binary in them it runs. Every one is root's and sits in a
// directory only root can write, so each is changed by its name.
func (s *Supervisor) grantTraverse(p Privilege) error {
	for _, dir := range []string{s.Dirs.State, s.Dirs.Libexec(), s.tools.Dir, s.Dirs.Run} {
		if err := ownAs(dir, 0, p.GID, 0o710); err != nil {
			return err
		}
	}

	return ownAs(s.tools.Anchord, 0, p.GID, 0o750)
}

// ownAs gives path to uid and gid at mode, changing only what differs.
func ownAs(path string, uid, gid int, mode fs.FileMode) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}

	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != uid || int(st.Gid) != gid {
		if err := os.Lchown(path, uid, gid); err != nil {
			return err
		}
	}

	if fi.Mode().Perm() != mode {
		return os.Chmod(path, mode)
	}

	return nil
}

// smoke runs anchord -h as the account once for each set and each grant, so that a host
// that will not let the account run it -- a root it cannot pass through, a filesystem
// mounted noexec for it, a user namespace with no uid for it, a policy -- says so before
// the start that depends on it, and anchord runs as the supervisor instead.
func (s *Supervisor) smoke(p Privilege) error {
	key := fmt.Sprint(s.tools.SetID, p.UID, p.GID, p.Groups, p.Caps, p.NoNewPrivs)
	if s.drop.smoked[key] {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), smokeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.tools.Anchord, "-h")
	cmd.SysProcAttr = s.procAttrFor(p)
	cmd.Env = anchordEnv(p, "")
	cmd.Dir = workDir

	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out

	err := startProcess(cmd, p)
	if err == nil {
		err = cmd.Wait()
	}

	if err != nil {
		if blocker := unsearchable(s.tools.Anchord, p); blocker != "" {
			return fmt.Errorf("%s cannot pass through %s to run anchord: %w", p.As, blocker, err)
		}

		return fmt.Errorf("anchord -h as %s: %w\n%s", p.As, err, strings.TrimSpace(out.String()))
	}

	if s.drop.smoked == nil {
		s.drop.smoked = map[string]bool{}
	}

	s.drop.smoked[key] = true

	return nil
}

// smokeTimeout bounds smoke.
const smokeTimeout = 10 * time.Second

// unsearchable is the first directory above path the account may not pass through, or "".
func unsearchable(path string, p Privilege) string {
	dirs := []string{}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		dirs = append(dirs, dir)
		if dir == filepath.Dir(dir) {
			break
		}
	}

	slices.Reverse(dirs)

	for _, dir := range dirs {
		fi, err := os.Stat(dir)
		if err != nil {
			return dir
		}

		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		perm := fi.Mode().Perm()

		switch {
		case int(st.Uid) == p.UID && perm&0o100 != 0:
		case (int(st.Gid) == p.GID || slices.Contains(p.Groups, int(st.Gid))) && perm&0o010 != 0:
		case perm&0o001 != 0:
		default:
			return dir
		}
	}

	return ""
}

// procAttrFor is anchord's process attributes for p: its own process group always, and
// for the account its uid, its gid, exactly the supplementary groups decided and no
// others, and on Linux the capabilities.
func (s *Supervisor) procAttrFor(p Privilege) *syscall.SysProcAttr {
	attr := procAttr()

	if !p.Account {
		return attr
	}

	groups := make([]uint32, 0, len(p.Groups))
	for _, g := range p.Groups {
		groups = append(groups, uint32(g))
	}

	attr.Credential = &syscall.Credential{Uid: uint32(p.UID), Gid: uint32(p.GID), Groups: groups}
	withCaps(attr, p.Caps)

	return attr
}

// freshDaemonRun makes anchord's run directory afresh, for p's identity. Nothing of the
// account's is running by now, and the run directory around it is root's, so its name
// cannot be changed under this.
func (s *Supervisor) freshDaemonRun(p Privilege) error {
	dir := s.Dirs.DaemonRun()

	if err := os.RemoveAll(dir); err != nil {
		return err
	}

	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}

	if p.Account {
		return os.Lchown(dir, p.UID, p.GID)
	}

	return nil
}

// killLeftovers ends whatever runs as the account, which only an anchord that ran as it,
// or something it started, can be: one that left anchord's process group outlives it, and
// could hold the socket's lock, or its name, against the next.
func (s *Supervisor) killLeftovers() {
	if os.Geteuid() != 0 {
		return
	}

	a, err := account.Lookup()
	if err != nil || a == nil {
		return
	}

	if err := account.Kill(a.UID); err != nil {
		s.report().Warn("%v", err)
	}
}

// legacyAnchorDir reports an anchor directory at the account's name that is the
// supervisor's own: conflux 1.0.0's, from before anchord ran as anything but root.
func legacyAnchorDir(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.IsDir() {
		return false
	}

	st, ok := fi.Sys().(*syscall.Stat_t)

	return ok && int(st.Uid) == os.Geteuid()
}

// anchorDirFor reports whether path is a directory, not a link, of p's identity.
func anchorDirFor(path string, p Privilege) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.IsDir() {
		return false
	}

	want := os.Geteuid()
	if p.Account {
		want = p.UID
	}

	st, ok := fi.Sys().(*syscall.Stat_t)

	return ok && int(st.Uid) == want
}

// makeAnchorDir creates path for p's identity. Its parent is the state directory, which
// only root can write, so it is given away by its name.
func makeAnchorDir(path string, p Privilege) error {
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}

	if p.Account {
		return os.Lchown(path, p.UID, p.GID)
	}

	return nil
}

// ownFile gives an open file to p's identity, through its descriptor.
func ownFile(f *os.File, p Privilege) error {
	if !p.Account {
		return nil
	}

	return f.Chown(p.UID, p.GID)
}

// oneLink reports a file with no second name, which a hard link the account made to a
// file of root's would be.
func oneLink(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)

	return ok && st.Nlink == 1
}

// owner is the uid and gid anchord's own files are written for: the account's, or -1 to
// leave them the supervisor's.
func owner(p Privilege) (uid, gid int) {
	if !p.Account {
		return -1, -1
	}

	return p.UID, p.GID
}

// releaseDrop is nothing to release here.
func (s *Supervisor) releaseDrop() {}

// writeDaemonFile writes anchord's -config for p's identity: 0600 and its own, given on
// the descriptor before the rename, so it is never readable to anybody else.
func writeDaemonFile(path string, data []byte, p Privilege) error {
	uid, gid := owner(p)

	return config.WriteFileAtomicAs(path, data, 0o600, uid, gid)
}
