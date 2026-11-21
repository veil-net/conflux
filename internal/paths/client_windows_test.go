package paths_test

import (
	"path/filepath"
	"strings"
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
// owner is the Administrators' on Windows Server and that administrator's own on a Windows client,
// and the boot service, running as SYSTEM, trusts no other account with anything in its root. So
// conflux names the Administrators the owner of everything it makes in an installation's root and
// on its way. Made under a client's policy (privtest.CreatorOwns) by what an administrator's up,
// install, register, enrol and renew make -- EnsureAll's root, run\ and logs\, the two lock files,
// the extraction's bin\, its lock, its set and binaries, the service's copy of conflux and the
// configuration -- the root passes the judgement the service makes of it (paths.JudgeAsTheService);
// and that judgement refuses each of them once it is given to the administrator, as a client's
// policy left logs\, the lock files, bin\, its lock and the service's copy before conflux named an
// owner for them. Windows-only, so it runs in CI's platforms job alone.
func TestWhatAnAdministratorMakesTheServiceTakes(t *testing.T) {
	anchortest.Require(t)

	t.Setenv("CONFLUX_DIR", filepath.Join(t.TempDir(), "conflux")) // its way made before the policy below
	d := paths.Default()

	restore := privtest.CreatorOwns(t)

	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	unlock, err := flock.Acquire(d.LockFile())
	if err != nil {
		t.Fatal(err)
	}

	unlock()

	unlock, ok, err := flock.TryAcquire(d.ServeLockFile())
	if err != nil || !ok {
		t.Fatalf("TryAcquire(%s) = %v, %v", d.ServeLockFile(), ok, err)
	}

	unlock()

	tools, err := libexec.Ensure(d)
	if err != nil {
		t.Fatal(err)
	}

	placed, err := service.Place(d)
	if err != nil {
		t.Fatal(err)
	}

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"cfx-owner"}}); err != nil {
		t.Fatal(err)
	}

	restore()

	if err := paths.JudgeAsTheService(d.State); err != nil {
		t.Fatalf("the service's judgement of a root an administrator made under a client's policy = %v", err)
	}

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{d.Run, d.Log, d.LockFile(), d.ServeLockFile(), d.Libexec(),
		filepath.Join(d.Libexec(), ".lock"), tools.Dir, tools.Anchord, placed, d.ConfigFile()} {
		owner := privtest.ReadSecurity(t, p).Owner
		if !owner.Equals(privtest.Admins) {
			t.Errorf("%s, made under a client's policy, belongs to %v, not the Administrators", p, owner)
		}

		privtest.SetOwner(t, p, user.User.Sid)

		if err := paths.JudgeAsTheService(d.State); err == nil || !strings.Contains(err.Error(), p+", which belongs to ") {
			t.Errorf("the service's judgement of a root holding %s, the administrator's = %v, want a refusal naming it",
				p, err)
		}

		privtest.SetOwner(t, p, owner)
	}
}
