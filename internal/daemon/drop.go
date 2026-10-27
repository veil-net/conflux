package daemon

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/enrol"
)

// Starting anchord with what decide gave it, and nothing else.
//
// privilege settles what the supervisor can actually give: an account it can make and
// that can run anchord here, and the capabilities the supervisor itself holds. Anything
// it cannot give, anchord runs as the supervisor does, which is never more than it was
// before, and says why. prepare then lays out what that identity reaches -- a run
// directory of its own for the socket, and an anchor directory of its own -- and spawn
// starts it.

// errRespawn ends a cycle so that the next starts anchord with what it now needs: a port
// the first enrolment named, an uplink device that has appeared, a host that changed.
var errRespawn = errors.New("anchord needs different privilege now, so it is started again")

// copyFileMax bounds one file copied between the two anchor directories. anchor's caches
// are kilobytes; anything near this is not one of them.
const copyFileMax = 16 << 20

// privilege decides who anchord runs as, and settles what the supervisor can give.
func (s *Supervisor) privilege(cfg *config.Config) Privilege {
	p := decide(runtime.GOOS, cfg, listenPort(cfg, manifestPort(s)), probeHost(cfg))

	if p.Account {
		if !s.Drop {
			p = asSupervisor("")
		} else if why := s.dropTo(&p); why != "" {
			p = asSupervisor(why)
		}
	}

	if !p.Account {
		p.As = supervisorName()
	}

	return p
}

// manifestPort is the port the stored credential names, or 0 before there is one.
func manifestPort(s *Supervisor) int {
	env, err := config.LoadManifest(s.Dirs)
	if err != nil {
		return 0
	}

	m, err := enrol.Decode(env)
	if err != nil {
		return 0
	}

	return m.ListenPort()
}

// supervisorName is who this process runs as, for a person.
func supervisorName() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}

	return "the supervisor's account"
}

// prepare lays out what anchord reaches for the identity p names, and records in p the
// anchor directory it is given.
func (s *Supervisor) prepare(p *Privilege) error {
	s.killLeftovers()

	if err := s.freshDaemonRun(*p); err != nil {
		return fmt.Errorf("prepare %s: %w", s.Dirs.DaemonRun(), err)
	}

	dir, err := s.anchorDir(*p)
	if err != nil {
		return err
	}

	p.Dir = dir

	return nil
}

// anchorDir is the anchor directory for p's identity -- the account's, or root's -- made if
// it is not there, and holding a fresh copy of what the last anchor kept when that one was
// given the other.
//
// Never the account's for root: anchor follows a symlink in its directory, so root's
// anchord in one the account can write would write wherever the account pointed it. And
// never re-owned in place: the account can hard-link into its own directory anything it
// can name, so a chown there could hand it a file root runs. A flip copies instead.
func (s *Supervisor) anchorDir(p Privilege) (string, error) {
	d := s.Dirs

	want := d.RootAnchorDir()
	if p.Account {
		want = d.AnchorDir()
	}

	// conflux 1.0.0 gave a root anchord the account's name for its directory, so a tree
	// there that is root's is root's anchor's state, and takes root's name.
	if legacyAnchorDir(d.AnchorDir()) {
		if _, err := os.Lstat(d.RootAnchorDir()); errors.Is(err, fs.ErrNotExist) {
			if err := os.Rename(d.AnchorDir(), d.RootAnchorDir()); err != nil {
				return "", fmt.Errorf("move %s aside: %w", d.AnchorDir(), err)
			}

			s.lastDir = d.RootAnchorDir()
		} else if err := os.RemoveAll(d.AnchorDir()); err != nil {
			return "", err
		}
	}

	from := s.lastDir

	switch _, err := os.Lstat(want); {
	case from != "" && from != want && exists(from):
		// The last anchor kept its state in the other directory: start this one from it.
	case err == nil && anchorDirFor(want, p):
		return want, nil
	case err == nil:
		// The account's, from an account since replaced: copied, not adopted.
		aside := want + ".old"
		if err := os.RemoveAll(aside); err != nil {
			return "", err
		}

		if err := os.Rename(want, aside); err != nil {
			return "", err
		}

		defer os.RemoveAll(aside)

		from = aside
	default:
		from = ""
	}

	if err := os.RemoveAll(want); err != nil {
		return "", err
	}

	if err := makeAnchorDir(want, p); err != nil {
		return "", fmt.Errorf("create %s: %w", want, err)
	}

	if from != "" {
		if err := copyTree(from, want, p); err != nil {
			s.report().Warn("could not carry the anchor's state from %s to %s: %v", from, want, err)
		}
	}

	return want, nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)

	return err == nil
}

// copyTree copies the regular files and directories under from into to, which is new and
// belongs to p's identity.
//
// from may be a directory the account can write, so nothing in it is trusted: it is read
// through an os.Root, which no symlink leads out of, a file is taken only when it is a
// regular file with one link and no larger than any anchor keeps, and anything else -- a
// symlink, a FIFO, a device, a hard link to something the account could name but not read
// -- is left behind. Everything is written fresh, created exclusively, and owned through
// its descriptor.
func copyTree(from, to string, p Privilege) error {
	src, err := os.OpenRoot(from)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenRoot(to)
	if err != nil {
		return err
	}
	defer dst.Close()

	return fs.WalkDir(src.FS(), ".", func(name string, e fs.DirEntry, err error) error {
		switch {
		case err != nil || name == ".":
			return nil
		case e.IsDir():
			if err := dst.Mkdir(name, 0o700); err != nil {
				return fs.SkipDir
			}

			return ownName(dst, name, p)
		case e.Type().IsRegular():
			return copyFile(src, dst, name, p)
		}

		return nil
	})
}

func copyFile(src, dst *os.Root, name string, p Privilege) error {
	in, err := src.OpenFile(name, openUntrusted, 0)
	if err != nil {
		return nil
	}
	defer in.Close()

	fi, err := in.Stat()
	if err != nil || !fi.Mode().IsRegular() || !oneLink(fi) || fi.Size() > copyFileMax {
		return nil
	}

	out, err := dst.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil
	}
	defer out.Close()

	if err := ownFile(out, p); err != nil {
		return err
	}

	_, err = io.Copy(out, io.LimitReader(in, copyFileMax))

	return err
}

// ownName gives what dst names to p's identity, through a descriptor of it.
func ownName(dst *os.Root, name string, p Privilege) error {
	f, err := dst.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()

	return ownFile(f, p)
}

// anchordEnv is anchord's environment: the supervisor's, without what was the service
// manager's to give the supervisor alone or conflux's own, with the token in it -- which
// keeps the token file root's -- and, for the account, who it is.
func anchordEnv(p Privilege, token string) []string {
	src := os.Environ()
	env := make([]string, 0, len(src)+4)

	for _, kv := range src {
		k, _, _ := strings.Cut(kv, "=")

		switch k {
		case "NOTIFY_SOCKET", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "CONFLUX_DIR",
			anchorctl.SocketEnv, anchorctl.TokenEnv:
			continue
		case "HOME", "USER", "LOGNAME":
			if p.Account && runtime.GOOS != "windows" {
				continue
			}
		}

		env = append(env, kv)
	}

	if p.Account && runtime.GOOS != "windows" {
		env = append(env, "HOME=/", "USER="+p.As, "LOGNAME="+p.As)
	}

	if token != "" {
		env = append(env, anchorctl.TokenEnv+"="+token)
	}

	return env
}

// redecided reports whether anchord would now be started with something other than what
// it was: the cycle's cue to start it again. Asked only after a start or a rebuild failed.
func (s *Supervisor) redecided() bool {
	cfg, err := loadConfig(s.Dirs)
	if err != nil {
		return false
	}

	p := s.privilege(cfg)

	p.Dir = s.Dirs.RootAnchorDir()
	if p.Account {
		p.Dir = s.Dirs.AnchorDir()
	}

	return !sameGrant(p, s.priv)
}

// requestRespawn asks the cycle to end, once.
func (s *Supervisor) requestRespawn() {
	select {
	case s.respawn <- struct{}{}:
	default:
	}
}

// firstLine is the first line of err, for a status row; the whole of it goes to the log.
func firstLine(err error) string {
	line, _, _ := strings.Cut(err.Error(), "\n")

	return line
}
