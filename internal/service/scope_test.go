package service

import "testing"

func TestScopeIsEmptyForAnOrdinaryInstall(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	if got := scope(); got != "" {
		t.Errorf("scope() = %q with no CONFLUX_DIR, want \"\" — the machine's own service keeps its plain name", got)
	}
}

func TestScopeIsStableAndDistinct(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "/tmp/cfx-a")
	a := scope()

	if a == "" {
		t.Fatal("a CONFLUX_DIR run must not share the machine's service name")
	}

	// Stable: the same root has to name the same service across runs, or uninstall
	// could not find what install registered.
	t.Setenv("CONFLUX_DIR", "/tmp/cfx-a")

	if again := scope(); again != a {
		t.Errorf("scope() = %q then %q for one root; a service nobody can name again is a service nobody can remove", a, again)
	}

	t.Setenv("CONFLUX_DIR", "/tmp/cfx-b")

	if b := scope(); b == a {
		t.Errorf("two roots both scoped to %q, so one dev run would still replace the other", b)
	}

	// Two roots ending in the same segment must not collide: a truncated path
	// would, which is why this hashes the whole thing.
	t.Setenv("CONFLUX_DIR", "/var/tmp/cfx-a")

	if deep := scope(); deep == a {
		t.Errorf("/tmp/cfx-a and /var/tmp/cfx-a both scoped to %q", deep)
	}
}

// TestScopeIsNameSafe: whatever a root looks like, the scope has to be usable inside
// a systemd unit name, a launchd label and an SCM entry. Hex and a hyphen are.
func TestScopeIsNameSafe(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "/tmp/a b/c:d\\e*f")

	got := scope()
	if len(got) != 9 || got[0] != '-' {
		t.Fatalf("scope() = %q, want a hyphen and eight hex digits", got)
	}

	for _, r := range got[1:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			t.Errorf("scope() = %q contains %q, which is not hex", got, r)
		}
	}
}
