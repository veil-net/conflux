package config

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/paths/pathstest"
)

// canonical is what a start does: conflux.json read once, and handed to Canonical.
func canonical(t *testing.T, d paths.Dirs) {
	t.Helper()

	c, raw, err := LoadBytes(d)
	if err != nil {
		t.Fatal(err)
	}

	if err := Canonical(d, c, raw); err != nil {
		t.Fatal(err)
	}
}

// TestCanonicalRewritesWhatWasEdited: the configuration and the state are written in
// conflux's own form at every start, so a hand edit that is valid still takes effect but
// leaves no key conflux does not know, and one written by conflux is left untouched.
func TestCanonicalRewritesWhatWasEdited(t *testing.T) {
	d := pathstest.Root(t)

	if err := Save(d, base(ModeProxy)); err != nil {
		t.Fatal(err)
	}

	if err := SaveState(d, &State{AnchorID: "anchoraaaa"}); err != nil {
		t.Fatal(err)
	}

	saved, _ := os.ReadFile(d.ConfigFile())
	savedState, _ := os.ReadFile(d.StateFile())

	before, err := os.Stat(d.ConfigFile())
	if err != nil {
		t.Fatal(err)
	}

	canonical(t, d)

	if after, err := os.Stat(d.ConfigFile()); err != nil || !os.SameFile(before, after) {
		t.Errorf("a configuration conflux wrote was written again (%v)", err)
	}

	if b, _ := os.ReadFile(d.ConfigFile()); string(b) != string(saved) {
		t.Errorf("a configuration conflux wrote was rewritten:\n%s\nwas\n%s", b, saved)
	}

	// A hand edit: a key conflux does not know, and the taints and the proxies changed.
	edited := `{"version":1,"mode":"proxy","taints":["t"],"proxies":["8080=127.0.0.1:1"],"handEdited":true}`
	if err := os.WriteFile(d.ConfigFile(), []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.StateFile(), []byte(`{"version":1,"anchorId":"anchoraaaa","note":"mine"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	canonical(t, d)

	cfg, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Mode != ModeProxy || !slices.Equal(cfg.Taints, []string{"t"}) || !slices.Equal(cfg.Proxies, []string{"8080=127.0.0.1:1"}) {
		t.Errorf("the hand edit did not take effect: mode %q, taints %q, proxies %q", cfg.Mode, cfg.Taints, cfg.Proxies)
	}

	for path, gone := range map[string]string{d.ConfigFile(): "handEdited", d.StateFile(): "note"} {
		if b, _ := os.ReadFile(path); strings.Contains(string(b), gone) {
			t.Errorf("%s still holds %q:\n%s", path, gone, b)
		}
	}

	if b, _ := os.ReadFile(d.StateFile()); string(b) != string(savedState) {
		t.Errorf("the state is\n%s\nwant it as conflux writes it\n%s", b, savedState)
	}
}

// TestTheCanonicalFormHasNoTimesNobodySet: a hand-written conflux.json with no createdAt or
// updatedAt is written back with none, not with the zero time, year 1.
func TestTheCanonicalFormHasNoTimesNobodySet(t *testing.T) {
	b, err := encodeConfig(base(ModeProxy))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(b), "createdAt") || strings.Contains(string(b), "updatedAt") {
		t.Errorf("a configuration nobody saved is written with times:\n%s", b)
	}
}

// TestAStateThisBuildCannotReadIsRefusedAndLeft: a state.json that does not parse, or that a
// newer conflux wrote, is an error to read, never an empty state -- it holds the AnchorID a
// renewal names -- and a start leaves it exactly as it is.
func TestAStateThisBuildCannotReadIsRefusedAndLeft(t *testing.T) {
	for name, raw := range map[string]string{
		"a trailing comma":  `{"version":1,"anchorId":"anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq",}`,
		"a newer conflux's": `{"version":99,"anchorId":"anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq"}`,
	} {
		t.Run(name, func(t *testing.T) {
			d := pathstest.Root(t)

			if err := Save(d, base(ModeProxy)); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(d.StateFile(), []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}

			if st, err := LoadState(d); err == nil || !strings.Contains(err.Error(), d.StateFile()) {
				t.Errorf("LoadState = %+v, %v; want an error naming the file", st, err)
			}

			canonical(t, d)

			if b, _ := os.ReadFile(d.StateFile()); string(b) != raw {
				t.Errorf("a state.json this build cannot read was rewritten:\n%s", b)
			}
		})
	}
}
