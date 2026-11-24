package daemon

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
)

// TestALostManifestIsNotReplaced: a machine whose state names the anchor it was, and whose
// manifest is gone, is refused for good, naming the way out, rather than enrolled again:
// the manifest is the only copy of the identity, and a new one is a new AnchorID and a new
// overlay address every peer would have to learn.
func TestALostManifestIsNotReplaced(t *testing.T) {
	srv, asked, calls := enroller(t, []string{"t"})
	d := dirs(t)

	cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, APIBaseURL: srv.URL}

	_, _, _, err := credential(t.Context(), d, &config.State{AnchorID: fakeAnchorID}, cfg, nopReporter{})
	// uninstall removes conflux too, so the way out installs it again.
	if !Permanent(err) || !strings.Contains(err.Error(), "conflux uninstall") || !strings.Contains(err.Error(), "install conflux again") {
		t.Errorf("credential() = %v, want a refusal for good naming conflux uninstall and installing again", err)
	}

	if calls.Load() != 0 || len(*asked) != 0 || config.HasManifest(d) {
		t.Errorf("a machine whose manifest was lost was enrolled again (%d calls)", calls.Load())
	}
}

// TestAStateThisBuildCannotReadIsRefusedForGood: a state.json that does not parse holds what
// nothing else gives back -- the AnchorID a renewal names -- so a start and a renewal refuse
// it for good, naming it, and leave it exactly as it was written; neither asks the issuer
// anything or starts on what it cannot read.
func TestAStateThisBuildCannotReadIsRefusedForGood(t *testing.T) {
	is := newIssuer(t)
	d := machine(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour))

	raw := `{"version":1,"anchorId":"` + renewTestAnchor + `",}`
	if err := os.WriteFile(d.StateFile(), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := bringUp(t.Context(), d, fakeCtl(t), nopReporter{}, d.RootAnchorDir(), false, nil)
	if !Permanent(err) || !strings.Contains(err.Error(), d.StateFile()) {
		t.Errorf("bringUp = %v, want a refusal for good naming %s", err, d.StateFile())
	}

	if err := RenewNow(t.Context(), d, fakeCtl(t), nil); !Permanent(err) || !strings.Contains(err.Error(), d.StateFile()) {
		t.Errorf("RenewNow = %v, want a refusal for good naming %s", err, d.StateFile())
	}

	if b, _ := os.ReadFile(d.StateFile()); string(b) != raw {
		t.Errorf("the state.json this build cannot read was rewritten:\n%s", b)
	}

	if n := is.calls.Load(); n != 0 {
		t.Errorf("the issuer was asked %d times, want none", n)
	}
}

// TestAnEmptyManifestIsRefusedForGood: a manifest.b64 with nothing in it, or nothing but white
// space, is no identity to start or renew, and no retry fills it: refused for good, naming it,
// rather than retried for ever -- and not enrolled over, since what it held is a person's to
// find out.
func TestAnEmptyManifestIsRefusedForGood(t *testing.T) {
	for name, content := range map[string]string{"zero bytes": "", "white space": " \n"} {
		t.Run(name, func(t *testing.T) {
			is := newIssuer(t)
			d := machine(t, is, time.Now(), time.Now().Add(30*24*time.Hour))

			if err := os.WriteFile(d.ManifestFile(), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := bringUp(t.Context(), d, fakeCtl(t), nopReporter{}, d.RootAnchorDir(), false, nil)
			if !Permanent(err) || !strings.Contains(err.Error(), d.ManifestFile()) {
				t.Errorf("bringUp = %v, want a refusal for good naming %s", err, d.ManifestFile())
			}

			if b, _ := os.ReadFile(d.ManifestFile()); string(b) != content || is.calls.Load() != 0 {
				t.Errorf("the empty manifest became %q after %d calls to the issuer", b, is.calls.Load())
			}
		})
	}
}

// TestAnEmptiedTaintListGetsTheGrantBack: a conflux.json whose taints were emptied by hand is
// started on the taints the credential grants -- nothing was asked for, so the grant is
// taken -- and has them written back, as up writes them, so what the file says is what the
// machine is in again.
func TestAnEmptiedTaintListGetsTheGrantBack(t *testing.T) {
	is := newIssuer(t)
	d := machine(t, is, time.Now(), time.Now().Add(30*24*time.Hour))

	cfg := configOf(t, d)
	cfg.Taints = nil

	if err := config.Save(d, cfg); err != nil {
		t.Fatal(err)
	}

	if _, err := bringUp(t.Context(), d, fakeCtl(t), nopReporter{}, d.RootAnchorDir(), false, nil); err != nil {
		t.Fatalf("bringUp: %v", err)
	}

	if got := configOf(t, d).Taints; !slices.Equal(got, []string{"t"}) {
		t.Errorf("conflux.json's taints after the start are %v, want the grant, [t]", got)
	}
}
