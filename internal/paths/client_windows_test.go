package paths_test

import (
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/anchortest"
	_ "github.com/veil-net/conflux/internal/apitest" // the default API answers nothing
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privtest"
	"github.com/veil-net/conflux/internal/service"
)

// TestWhatAnAdministratorMakesTheServiceTakes: what an elevated administrator makes without naming an
// owner is the Administrators' on Windows Server and that administrator's own on a Windows client, and
// the boot service, running as SYSTEM, trusts no other account with its root. So every conflux process
// makes the Administrators the owner of what it makes as it starts (paths.ElevatedDefaultOwner). Under a
// client's policy (privtest.CreatorOwns), once that is done, what an administrator's up, install,
// register, enrol and renew make -- EnsureAll's root, run\ and logs\, the two lock files, the
// extraction's bin\, its lock, its set and binaries, the service's copy of conflux and the
// configuration -- is each the Administrators', granting this account nothing, as its maker returns; and
// the root passes the readers' check, which judges an installation's for SYSTEM. Windows-only, so it runs
// in CI's platforms job alone.
func TestWhatAnAdministratorMakesTheServiceTakes(t *testing.T) {
	anchortest.Require(t)

	data := t.TempDir() // made before the policy below

	was := paths.SystemData
	paths.SystemData = func() string { return data }

	t.Cleanup(func() { paths.SystemData = was })

	d := paths.Default()

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}

	restore := privtest.CreatorOwns(t)

	if err := paths.ElevatedDefaultOwner(); err != nil {
		t.Fatal(err)
	}

	// made holds each of ps to what an elevated conflux makes: the Administrators', granting this
	// account nothing.
	made := func(maker string, ps ...string) {
		t.Helper()

		for _, p := range ps {
			s := privtest.ReadSecurity(t, p)
			if !s.Owner.Equals(privtest.Admins) {
				t.Errorf("%s, as %s made it, belongs to %v, not the Administrators", p, maker, s.Owner)
			}

			if slices.ContainsFunc(s.Grantees(), user.User.Sid.Equals) {
				t.Errorf("%s, as %s made it, grants %v, who runs conflux", p, maker, user.User.Sid)
			}
		}
	}

	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	made("EnsureAll", d.State, d.Run, d.Log)

	unlock, err := flock.AcquireContext(t.Context(), d.LockFile(), nil)
	if err != nil {
		t.Fatal(err)
	}

	unlock()
	made("flock.AcquireContext", d.LockFile())

	unlock, ok, err := flock.TryAcquire(d.ServeLockFile())
	if err != nil || !ok {
		t.Fatalf("TryAcquire(%s) = %v, %v", d.ServeLockFile(), ok, err)
	}

	unlock()
	made("flock.TryAcquire", d.ServeLockFile())

	tools, err := libexec.Extract(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}

	made("libexec.Extract", d.Libexec(), filepath.Join(d.Libexec(), ".lock"), tools.Dir, tools.Anchord)

	placed, err := service.PlaceAfresh(d)
	if err != nil {
		t.Fatal(err)
	}

	made("service.PlaceAfresh", placed)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"cfx-owner"}}); err != nil {
		t.Fatal(err)
	}

	made("config.Save", d.ConfigFile())

	restore()

	if err := d.Check(); err != nil {
		t.Errorf("the readers' check of a root an administrator made under a client's policy = %v", err)
	}
}
