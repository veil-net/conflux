package config

import (
	"os"
	"strings"
	"testing"
)

// TestCanonicalRewritesWhatWasEdited: the configuration and the state are written in
// conflux's own form at every start, so a hand edit that is valid still takes effect but
// leaves no key conflux does not know, and one written by conflux is left untouched.
func TestCanonicalRewritesWhatWasEdited(t *testing.T) {
	d := dirsForTest(t)

	if err := Save(d, base(ModeProxy)); err != nil {
		t.Fatal(err)
	}

	if err := SaveState(d, &State{AnchorID: "anchoraaaa"}); err != nil {
		t.Fatal(err)
	}

	saved, _ := os.ReadFile(d.ConfigFile())
	savedState, _ := os.ReadFile(d.StateFile())

	if err := Canonical(d); err != nil {
		t.Fatal(err)
	}

	if b, _ := os.ReadFile(d.ConfigFile()); string(b) != string(saved) {
		t.Errorf("a configuration conflux wrote was rewritten:\n%s\nwas\n%s", b, saved)
	}

	// A hand edit: a key conflux does not know, and the mode changed.
	edited := `{"version":1,"mode":"proxy","taints":["t"],"proxies":["8080=127.0.0.1:1"],"handEdited":true}`
	if err := os.WriteFile(d.ConfigFile(), []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.StateFile(), []byte(`{"version":1,"anchorId":"anchoraaaa","note":"mine"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Canonical(d); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Mode != ModeProxy {
		t.Errorf("the hand edit's mode was not kept: %q", cfg.Mode)
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

// TestCanonicalLeavesWhatItCannotRead: a configuration that does not parse is the
// supervisor's to refuse, saying where, and is left exactly as it is; none at all is nothing
// to do.
func TestCanonicalLeavesWhatItCannotRead(t *testing.T) {
	d := dirsForTest(t)

	if err := Canonical(d); err != nil {
		t.Errorf("Canonical with nothing configured: %v", err)
	}

	if err := os.WriteFile(d.ConfigFile(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Canonical(d); err != nil {
		t.Errorf("Canonical of a configuration that does not parse: %v; the supervisor refuses it as it reads it", err)
	}

	if b, _ := os.ReadFile(d.ConfigFile()); string(b) != "{not json" {
		t.Errorf("an unreadable configuration was rewritten: %q", b)
	}
}
