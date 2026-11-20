//go:build !windows

package paths

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestEnsureAllJudgesWhatAWideRootHolds: a root of this account's left wider than conflux leaves one
// -- 0757 here -- let anybody put what they liked in it, which narrowing it takes nothing out of: a
// link at logs/conflux.log, for the service to write its log through as root, or a file every account
// may write, or one another account owns, a configuration of theirs. So EnsureAll judges what a root
// holds, each thing by its own owner, mode and ACL, read from the root it holds open and never by its
// name, and refuses such a root, naming what it holds, with nothing followed.
func TestEnsureAllJudgesWhatAWideRootHolds(t *testing.T) {
	for _, c := range []struct {
		name    string
		plant   func(t *testing.T, root string) (at string)
		refused string
	}{
		{"a link at logs/conflux.log", func(t *testing.T, root string) string {
			if err := os.Mkdir(filepath.Join(root, "logs"), 0o700); err != nil {
				t.Fatal(err)
			}

			at := filepath.Join(root, "logs", "conflux.log")
			if err := os.Symlink(outside(t), at); err != nil {
				t.Fatal(err)
			}

			return at
		}, ", a link, is in "},
		{"a file every account may write", func(t *testing.T, root string) string {
			at := filepath.Join(root, "conflux.json")
			if err := os.WriteFile(at, nil, 0o600); err != nil {
				t.Fatal(err)
			}

			if err := os.Chmod(at, 0o666); err != nil {
				t.Fatal(err)
			}

			return at
		}, ", which anybody may write"},
		{"a second name for a file outside it", func(t *testing.T, root string) string {
			at := filepath.Join(root, "conflux.log")
			if err := os.Link(outside(t), at); err != nil {
				t.Fatal(err)
			}

			return at
		}, ", which has another name, is in "},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "conflux")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			if err := os.Chmod(root, 0o757); err != nil {
				t.Fatal(err)
			}

			at := c.plant(t, root)
			t.Setenv("CONFLUX_DIR", root)

			if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), at+c.refused) {
				t.Errorf("EnsureAll(a 0757 root holding %s) = %v, want a refusal naming it", c.name, err)
			}
		})
	}
}

// outside is a file outside any root, whose content a test checks nothing wrote to.
func outside(t *testing.T) string {
	t.Helper()

	p := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(p, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if b, err := os.ReadFile(p); err != nil || !bytes.Equal(b, []byte("untouched")) {
			t.Errorf("%s, where a link planted in a root leads, was written: %q, %v", p, b, err)
		}
	})

	return p
}

// TestSecureJudgesWhatARootGainsBeforeItIsNarrowed: until a wide root is narrowed anybody may still add
// to it, so what it holds is judged again once it is: a link added in between is refused, naming it.
func TestSecureJudgesWhatARootGainsBeforeItIsNarrowed(t *testing.T) {
	root := foundRoot(t)
	if err := os.Chmod(root, 0o757); err != nil {
		t.Fatal(err)
	}

	at := filepath.Join(root, "conflux.json")

	was := narrowed
	t.Cleanup(func() { narrowed = was })

	narrowed = func(string) {
		if err := os.Symlink(outside(t), at); err != nil {
			t.Fatal(err)
		}
	}

	if err := secure(root); err == nil || !strings.Contains(err.Error(), at+", a link, is in ") {
		t.Errorf("secure(a root a link was added to as it was narrowed) = %v, want a refusal naming it", err)
	}
}

// TestARootHoldingAnotherAccountsFileIsRefused: a file another account owns is theirs, whatever its
// name and mode, and refused, naming the owner: given to uid 65534, as root, by EnsureAll; and
// otherwise this account's own, judged for another.
func TestARootHoldingAnotherAccountsFileIsRefused(t *testing.T) {
	root := foundRoot(t)
	at := filepath.Join(root, "conflux.json")

	if err := os.WriteFile(at, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	judge, owner := func() error { return contentsAs(root, os.Geteuid()+1) }, os.Geteuid()

	if os.Geteuid() == 0 {
		if err := os.Chown(at, 65534, 65534); err != nil {
			t.Fatal(err)
		}

		t.Setenv("CONFLUX_DIR", root)

		judge, owner = Default().EnsureAll, 65534
	}

	if err := judge(); err == nil || !strings.Contains(err.Error(), at+", which belongs to uid "+strconv.Itoa(owner)) {
		t.Errorf("a root holding %s, which uid %d owns, = %v, want a refusal naming it", at, owner, err)
	}
}

// TestWhatConfluxKeepsInARootPassesTheJudgement: what conflux keeps in a root is let through, and so
// is what anchord makes in its own directories, which are not gone into: an extracted set, the token,
// a pid record, anchord's run directory with its socket and that socket's lock, its -dir with what
// it caches. Here every one is this account's, as an ephemeral run's are for a user who runs one,
// and EnsureAll, which judges them, takes the root, as Foreign does.
func TestWhatConfluxKeepsInARootPassesTheJudgement(t *testing.T) {
	// Short, for the socket's path.
	base, err := os.MkdirTemp("", "cfx")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { os.RemoveAll(base) })

	root := filepath.Join(base, "conflux")
	d := EphemeralDirs(root)

	for _, dir := range []string{filepath.Join(d.Libexec(), "set"), d.DaemonRun(), d.AnchorDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	for _, f := range []string{filepath.Join(d.Libexec(), "set", "anchord"), d.TokenFile(), d.DaemonPIDFile(),
		d.Socket() + ".lock", filepath.Join(d.AnchorDir(), "bootstrap.json")} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	l, err := net.Listen("unix", d.Socket())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { l.Close() })

	// As anchord makes it, rather than at the umask's mode.
	if err := os.Chmod(d.Socket(), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", "")

	if err := d.EnsureAll(); err != nil {
		t.Errorf("EnsureAll(a root holding what conflux keeps there) = %v", err)
	}

	if err := Foreign(root); err != nil {
		t.Errorf("Foreign(a root holding what conflux keeps there) = %v", err)
	}
}

// TestAnchordsPlacesAreItsAlone: the places in a root where the supervisor gives anchord's account
// what it needs, and nowhere else, are where an entry that account owns is let through.
func TestAnchordsPlacesAreItsAlone(t *testing.T) {
	for rel, want := range map[string]bool{
		"anchor":                                true,
		"anchor.new":                            true,
		"anchord.json":                          true,
		".tmp-123":                              true,
		"anchord":                               true,
		filepath.Join("run", "anchord"):         true,
		"conflux.json":                          false,
		"token":                                 false,
		filepath.Join("run", "token"):           false,
		filepath.Join("bin", "anchor"):          false,
		filepath.Join("logs", ".tmp-123"):       false,
		filepath.Join("anchor", "anchord.json"): false,
	} {
		if got := anchordPlace(rel); got != want {
			t.Errorf("anchordPlace(%s) = %v, want %v", rel, got, want)
		}
	}
}
