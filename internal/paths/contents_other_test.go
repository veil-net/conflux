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

// TestASecondNameIsRefusedOnlyInARootFoundWide: a file in a root with a second name would lead root's
// writes to wherever that name is, but only an account that could write the root can have made it
// there. So it is refused as secure finds a root wider than conflux leaves one, before narrowing it,
// with a refusal that sends nobody to remove the file -- it may be the manifest -- and nowhere else: a
// root already 0700, or 0710, whose manifest anchord's account, which may link what it can name, gave
// a second name, is taken by EnsureAll and by Foreign.
func TestASecondNameIsRefusedOnlyInARootFoundWide(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	for _, mode := range []os.FileMode{0o700, 0o710, 0o750} {
		root := foundRoot(t)
		at := filepath.Join(root, "manifest.b64")

		if err := os.WriteFile(at, nil, 0o600); err != nil {
			t.Fatal(err)
		}

		if err := os.Link(at, filepath.Join(t.TempDir(), "second")); err != nil {
			t.Fatal(err)
		}

		if err := os.Chmod(root, mode); err != nil {
			t.Fatal(err)
		}

		err := Dirs{Config: root, State: root, Run: filepath.Join(root, runName)}.EnsureAll()

		switch wide := mode == 0o750; {
		case wide && (err == nil || !strings.Contains(err.Error(), at+", which has another name, is in ")):
			t.Errorf("EnsureAll(a %#o root holding %s, which has a second name) = %v, want a refusal naming it", mode,
				at, err)
		case wide && strings.Contains(err.Error(), "Remove it"):
			t.Errorf("the refusal of a second name sends the operator to remove the file: %v", err)
		case !wide && err != nil:
			t.Errorf("EnsureAll(a %#o root holding %s, which has a second name) = %v", mode, at, err)
		case !wide:
			if err := Foreign(root); err != nil {
				t.Errorf("Foreign(a %#o root holding %s, which has a second name) = %v", mode, at, err)
			}
		}
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

// TestARootReplacedAsItIsJudgedIsRefused: what a root holds is judged through the root opened by its
// name, and that is held to the directory secure judged the owner and mode of, not to one looked up
// again beside the open: a root another directory took the place of once secure had narrowed it is
// refused, though the one at the name by then is empty and this account's, rather than judged in its
// stead.
func TestARootReplacedAsItIsJudgedIsRefused(t *testing.T) {
	root := foundRoot(t)
	if err := os.Chmod(root, 0o757); err != nil {
		t.Fatal(err)
	}

	was := narrowed
	t.Cleanup(func() { narrowed = was })

	narrowed = func(string) {
		if err := os.Rename(root, root+".judged"); err != nil {
			t.Fatal(err)
		}

		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	if err := secure(root); err == nil || !strings.Contains(err.Error(), root+" changed while conflux judged it") {
		t.Errorf("secure(a root replaced once it was narrowed) = %v, want a refusal naming it", err)
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

	judge, owner := func() error {
		fi, err := os.Stat(root)
		if err != nil {
			return err
		}

		return contentsAs(root, fi, os.Geteuid()+1, false)
	}, os.Geteuid()

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
