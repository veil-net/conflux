package paths_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/anchor"
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
// owner is the Administrators' on Windows Server and that administrator's own on a Windows client, a
// CREATOR OWNER entry passed on to it grants whoever owns it, and the boot service, running as SYSTEM,
// trusts no other account with anything in its root. So every conflux process makes the Administrators
// the owner of what it makes as it starts (paths.ElevatedDefaultOwner). Under a client's policy
// (privtest.CreatorOwns), once that is done, in a root an administrator tightened by hand to SYSTEM,
// the Administrators and CREATOR OWNER, what an administrator's up, install, register, enrol and renew
// make -- EnsureAll's run\ and logs\, the two lock files, the extraction's bin\, its lock, its set and
// binaries, the service's copy of conflux and the configuration -- is each the Administrators',
// granting this account nothing, as its maker returns, before anything after it secures the root
// again; the root then passes the judgement the service makes of it (paths.JudgeAsTheService), which
// refuses each of them once it is given to the administrator. Windows-only, so it runs in CI's
// platforms job alone.
func TestWhatAnAdministratorMakesTheServiceTakes(t *testing.T) {
	anchortest.Require(t)

	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root) // its way made before the policy below
	d := paths.Default()

	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	privtest.SetSecurity(t, root, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FA;;;CO)")

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

	made("EnsureAll", d.Run, d.Log)

	unlock, err := flock.Acquire(d.LockFile())
	if err != nil {
		t.Fatal(err)
	}

	unlock()
	made("flock.Acquire", d.LockFile())

	unlock, ok, err := flock.TryAcquire(d.ServeLockFile())
	if err != nil || !ok {
		t.Fatalf("TryAcquire(%s) = %v, %v", d.ServeLockFile(), ok, err)
	}

	unlock()
	made("flock.TryAcquire", d.ServeLockFile())

	tools, err := libexec.Ensure(d)
	if err != nil {
		t.Fatal(err)
	}

	made("libexec.Ensure", d.Libexec(), filepath.Join(d.Libexec(), ".lock"), tools.Dir, tools.Anchord)

	placed, err := service.Place(d)
	if err != nil {
		t.Fatal(err)
	}

	made("service.Place", placed)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"cfx-owner"}}); err != nil {
		t.Fatal(err)
	}

	made("config.Save", d.ConfigFile())

	restore()

	if err := paths.JudgeAsTheService(d.State); err != nil {
		t.Fatalf("the service's judgement of a root an administrator made under a client's policy = %v", err)
	}

	for _, p := range []string{d.Run, d.Log, d.LockFile(), d.ServeLockFile(), d.Libexec(),
		filepath.Join(d.Libexec(), ".lock"), tools.Dir, tools.Anchord, placed, d.ConfigFile()} {
		owner := privtest.ReadSecurity(t, p).Owner

		privtest.SetOwner(t, p, user.User.Sid)

		if err := paths.JudgeAsTheService(d.State); err == nil || !strings.Contains(err.Error(), p+", which belongs to ") {
			t.Errorf("the service's judgement of a root holding %s, the administrator's = %v, want a refusal naming it",
				p, err)
		}

		privtest.SetOwner(t, p, owner)
	}
}

// TestAnUpdatedOlderRootIsOneTheServiceTakes: a root an older conflux left on a Windows client holds
// logs\, the lock files, bin\ -- with this build's set planted in it, padded to its sizes -- and the
// service's copy of conflux, each the administrator's own (privtest.CreatorOwns), which the service's
// judgement refuses. What the conflux an update puts in place does to it before its service starts
// (cli's tidy, then its PlaceAfresh), in that order -- the Administrators made the owner of what it
// makes, RemakeOld, EnsureAll, the two lock files taken, the bin directory remade (libexec.Remake), the
// copy written afresh -- leaves a root the service's judgement takes, with this build's pair in place
// of the plant. Windows-only, so it runs in CI's platforms job alone.
func TestAnUpdatedOlderRootIsOneTheServiceTakes(t *testing.T) {
	anchortest.Require(t)

	t.Setenv("CONFLUX_DIR", filepath.Join(t.TempDir(), "conflux"))
	d := paths.Default()

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"cfx-old"}}); err != nil {
		t.Fatal(err)
	}

	set := filepath.Join(d.Libexec(), anchor.SetID())
	plant := map[string][]byte{
		filepath.Join(set, "anchord.exe"):   anchor.Anchord(),
		filepath.Join(set, "anchorctl.exe"): anchor.Anchorctl(),
	}

	restore := privtest.CreatorOwns(t)

	if err := os.RemoveAll(d.Log); err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{d.Log, set} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	files := map[string][]byte{d.LockFile(): nil, d.ServeLockFile(): nil, d.ServiceExecutable(): []byte("an older conflux")}
	for p, want := range plant {
		files[p] = make([]byte, len(want))
	}

	for p, body := range files {
		if err := os.WriteFile(p, body, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	restore()

	if err := paths.JudgeAsTheService(d.State); err == nil {
		t.Fatal("the service's judgement took a root holding what the administrator owns")
	}

	if err := paths.ElevatedDefaultOwner(); err != nil {
		t.Fatal(err)
	}

	if _, err := d.RemakeOld(); err != nil {
		t.Fatalf("RemakeOld = %v", err)
	}

	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll = %v", err)
	}

	unlock, ok, err := flock.TryAcquire(d.ServeLockFile())
	if err != nil || !ok {
		t.Fatalf("TryAcquire(%s) = %v, %v", d.ServeLockFile(), ok, err)
	}

	unlock()

	unlock, err = flock.Acquire(d.LockFile())
	if err != nil {
		t.Fatal(err)
	}

	unlock()

	if _, err := libexec.Remake(d); err != nil {
		t.Fatalf("Remake = %v", err)
	}

	if _, err := service.PlaceAfresh(d); err != nil {
		t.Fatalf("PlaceAfresh = %v", err)
	}

	if err := paths.JudgeAsTheService(d.State); err != nil {
		t.Errorf("the service's judgement of the root the update remade = %v", err)
	}

	for p, want := range plant {
		if b, err := os.ReadFile(p); err != nil || !bytes.Equal(b, want) {
			t.Errorf("%s is still the plant, or not this build's (%d bytes, %v)", p, len(b), err)
		}
	}
}
