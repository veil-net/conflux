package paths_test

import (
	"os"
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

// TestAnInstallationsRootIsGivenToTheAdministrators: a root an earlier conflux, or an administrator
// by hand, left holding what that administrator owns -- logs\, the lock files, bin\ and its lock,
// made under a Windows client's default-owner policy -- is one the SYSTEM service refuses at every
// start, trusting no other account. The administrator's EnsureAll of an installation's root, which
// up, install and register run first, gives each to the Administrators as it judges it, through the
// handle it judges it by, and the service's judgement then takes the root. One owned by another account, the
// Guests here, is still refused, naming it, and left as it was; and an ephemeral run's root, which no
// service runs from, is left as it is found. Windows-only, so it runs in CI's platforms job alone.
func TestAnInstallationsRootIsGivenToTheAdministrators(t *testing.T) {
	t.Setenv("CONFLUX_DIR", filepath.Join(t.TempDir(), "conflux"))
	d := paths.Default()

	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}

	dirs := []string{d.Log, d.Libexec()}
	files := []string{d.LockFile(), d.ServeLockFile(), filepath.Join(d.Libexec(), ".lock")}

	restore := privtest.CreatorOwns(t)

	for _, dir := range dirs {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}

		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	for _, f := range files {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	restore()

	old := append(dirs, files...)

	for _, p := range old {
		if owner := privtest.ReadSecurity(t, p).Owner; !owner.Equals(user.User.Sid) {
			t.Fatalf("%s, made under a client's policy, belongs to %v, not this account", p, owner)
		}
	}

	if err := paths.JudgeAsTheService(d.State); err == nil || !strings.Contains(err.Error(), ", which belongs to ") {
		t.Errorf("the service's judgement of a root holding what the administrator owns = %v, want a refusal", err)
	}

	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll of an installation's root holding what the administrator owns = %v", err)
	}

	for _, p := range old {
		if owner := privtest.ReadSecurity(t, p).Owner; !owner.Equals(privtest.Admins) {
			t.Errorf("%s belongs to %v once EnsureAll secured the root, not the Administrators", p, owner)
		}
	}

	if err := paths.JudgeAsTheService(d.State); err != nil {
		t.Errorf("the service's judgement of the root EnsureAll secured = %v", err)
	}

	guests, err := windows.CreateWellKnownSid(windows.WinBuiltinGuestsSid)
	if err != nil {
		t.Fatal(err)
	}

	privtest.SetOwner(t, d.LockFile(), guests)

	if err := d.EnsureAll(); err == nil || !strings.Contains(err.Error(), d.LockFile()+", which belongs to ") {
		t.Errorf("EnsureAll of a root holding a file the Guests own = %v, want a refusal naming it", err)
	}

	if owner := privtest.ReadSecurity(t, d.LockFile()).Owner; !owner.Equals(guests) {
		t.Errorf("EnsureAll gave %s, the Guests', to %v", d.LockFile(), owner)
	}

	e := paths.EphemeralDirs(filepath.Join(t.TempDir(), "conflux-ephemeral"))
	if err := e.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	restore = privtest.CreatorOwns(t)

	if err := os.WriteFile(e.LockFile(), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	restore()

	if err := e.EnsureAll(); err != nil {
		t.Errorf("EnsureAll of an ephemeral run's root holding a file of this account's = %v", err)
	}

	if owner := privtest.ReadSecurity(t, e.LockFile()).Owner; !owner.Equals(user.User.Sid) {
		t.Errorf("EnsureAll of an ephemeral run's root gave %s to %v", e.LockFile(), owner)
	}
}
