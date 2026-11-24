package daemon

import (
	"strings"
	"testing"

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
