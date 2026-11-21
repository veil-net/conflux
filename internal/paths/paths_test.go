package paths

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

// TestRootIsAbsoluteAndClean: the root is written into the service definition and hashed
// into its name, so every spelling of one directory has to come out the same.
func TestRootIsAbsoluteAndClean(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)

	t.Setenv("CONFLUX_DIR", filepath.Join("rel", "x")+string(filepath.Separator))

	if got, want := Root(), filepath.Join(cwd, "rel", "x"); got != want {
		t.Errorf("Root() = %q, want %q", got, want)
	}

	t.Setenv("CONFLUX_DIR", "")

	if got := Root(); got != "" {
		t.Errorf("Root() = %q with no CONFLUX_DIR, want \"\"", got)
	}
}

// TestALogDirectoryOnlyWhereThePlatformHasOne: under CONFLUX_DIR the log goes beside the
// rest only on a platform that writes the service's output to a file.
func TestALogDirectoryOnlyWhereThePlatformHasOne(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CONFLUX_DIR", root)

	d := Default()

	switch platform := platformDirs().Log; {
	case platform == "" && d.Log != "":
		t.Errorf("Log = %q, but nothing on this platform writes a log file", d.Log)
	case platform != "" && d.Log != filepath.Join(root, "logs"):
		t.Errorf("Log = %q, want it under the root", d.Log)
	}
}

// foundRoot is a root as secure finds one already there: a folder named conflux, made at 0700 in a
// temporary directory of the test's, with what that passes on.
func foundRoot(t *testing.T) string {
	t.Helper()

	root := filepath.Join(t.TempDir(), "conflux")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	return root
}

// TestClearExceptSaysWhatItRemoved: everything in the directory but the one kept is removed, a folder
// with all it holds, and what was removed is named, for tidy to list; the one kept stays, and a
// directory not there is an error, with nothing named.
func TestClearExceptSaysWhatItRemoved(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "keep")

	for _, p := range []string{keep, filepath.Join(dir, "a"), filepath.Join(dir, "c", "d")} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	want := []string{filepath.Join(dir, "a"), filepath.Join(dir, "c")}

	if removed, err := ClearExcept(dir, keep); err != nil || !slices.Equal(removed, want) {
		t.Errorf("ClearExcept = %q, %v, want %q", removed, err, want)
	}

	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 || entries[0].Name() != "keep" {
		t.Errorf("ClearExcept left %v (%v), want only what it kept", entries, err)
	}

	if removed, err := ClearExcept(filepath.Join(dir, "not-there"), ""); err == nil || removed != nil {
		t.Errorf("ClearExcept(a directory not there) = %q, %v, want an error and nothing named", removed, err)
	}
}

// TestOneTestOfWhatIsInsideWhat: the roots conflux holds and removes are those inside no other, each
// once, the system's shared log directory never among them; a directory is inside a root only below
// it, a name that merely starts with ".." included; and the folders Way takes from the record are
// those above a root of conflux's, never one above the shared log directory alone, which conflux does
// not make.
func TestOneTestOfWhatIsInsideWhat(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "conflux")
	shared := filepath.Join(base, "log", "shared")

	was := sharedLog
	t.Cleanup(func() { sharedLog = was })

	sharedLog = shared

	d := Dirs{Config: root, State: root, Run: filepath.Join(root, "run"), Log: shared}
	if got := d.Outer(); !slices.Equal(got, []string{root}) {
		t.Errorf("Outer() = %q, want %q", got, []string{root})
	}

	apart := Dirs{Config: filepath.Join(base, "etc"), State: filepath.Join(base, "lib"), Run: filepath.Join(base, "run")}
	if got := apart.Outer(); !slices.Equal(got, []string{apart.Config, apart.State, apart.Run}) {
		t.Errorf("Outer() of three roots apart = %q, want each", got)
	}

	for dir, want := range map[string]bool{
		filepath.Join(root, "ephemeral"): true,
		filepath.Join(root, "..x"):       true,
		root:                             false,
		filepath.Join(base, "other"):     false,
		filepath.Join(shared, "x"):       false,
	} {
		if got := d.Inside(dir); got != want {
			t.Errorf("Inside(%s) = %v, want %v", dir, got, want)
		}
	}

	if !within(filepath.Join(root, "..x"), []string{root}) {
		t.Errorf("within(%s, %s) = false, want it inside", filepath.Join(root, "..x"), root)
	}

	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, wayName), []byte(base+"\n"+filepath.Dir(shared)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if way, err := d.Way(); err != nil || !slices.Equal(way, []string{base}) {
		t.Errorf("Way() = %q, %v, want %q, and nothing above the shared log directory alone", way, err,
			[]string{base})
	}
}

// TestTheListHoldsWhatConfluxMakesInARoot: own, the one list of the names conflux makes at the top of a
// root, holds every path the platform's roots, a CONFLUX_DIR's and an ephemeral run's name directly in
// one of them -- each method of Dirs that takes nothing and is a path, so that a path added to Dirs is
// on it, each root inside another, and an ephemeral run's root inside a CONFLUX_DIR -- and what is made
// beside those: the anchor directories the supervisor makes and sets aside, the copy an update moves
// aside, the log moved aside, the way record, and what an atomic write, the service's copy and an
// update's download leave before a rename. A name conflux makes nowhere is not on it.
func TestTheListHoldsWhatConfluxMakesInARoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")

	layouts := map[string]Dirs{"the platform's": platformDirs(), "an ephemeral run's": EphemeralDirs(root)}

	t.Setenv("CONFLUX_DIR", root)

	layouts["a CONFLUX_DIR's"] = Default()

	for name, d := range layouts {
		made := append([]string{d.Config, d.State, d.Run, d.Log, filepath.Join(d.State, wayName),
			d.AnchorDir() + ".new", d.AnchorDir() + ".old", d.RootAnchorDir() + ".old", d.ServiceExecutable() + ".old",
			filepath.Join(d.State, ".tmp-1"), filepath.Join(d.State, ".conflux-1")}, EphemeralCandidates()...)

		if d.Log != "" {
			made = append(made, d.LogFile()+".1")
		}

		v := reflect.ValueOf(d)
		for i := range v.NumMethod() {
			if m := v.Method(i).Type(); m.NumIn() == 0 && m.NumOut() == 1 && m.Out(0).Kind() == reflect.String {
				made = append(made, v.Method(i).Call(nil)[0].String())
			}
		}

		for dir := range d.roots() {
			for _, p := range made {
				if p == "" || p == dir || filepath.Dir(p) != dir {
					continue
				}

				if ours, _ := nameIn(d.ownIn(dir), filepath.Base(p)); !ours {
					t.Errorf("%s, which conflux makes in %s, a root of %s, is not on the list", filepath.Base(p), dir, name)
				}
			}

			if ours, _ := nameIn(d.ownIn(dir), "alice"); ours {
				t.Errorf("alice, which conflux makes nowhere, is on the list of %s, a root of %s", dir, name)
			}
		}
	}
}
