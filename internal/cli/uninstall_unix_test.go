//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// pointSudoLink points the link an update makes for sudo at one of the test's own, for as long
// as the test runs: serveRelease's, beside the release and the file an update replaces.
func pointSudoLink(t *testing.T) {
	t.Helper()

	was := updateLink
	t.Cleanup(func() { updateLink = was })

	link := filepath.Join(t.TempDir(), "conflux")
	updateLink = func() string { return link }
}

// TestUninstallTakesTheInstalledConflux: what install.sh put in place goes -- the executable,
// and the link it made for sudo -- and a link or a file of the same name that is somebody
// else's stays.
func TestUninstallTakesTheInstalledConflux(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "local", "conflux")
	link := filepath.Join(dir, "bin", "conflux")

	for _, d := range []string{filepath.Dir(exe), filepath.Dir(link)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(exe, []byte("conflux"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(exe, link); err != nil {
		t.Fatal(err)
	}

	if err := removeInstalled(exe, link); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{exe, link} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived uninstall (%v)", p, err)
		}
	}

	// A link to something else is not conflux's.
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, nil, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}

	if err := removeInstalled(exe, link); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(link); err != nil {
		t.Errorf("a link that is not conflux's was removed (%v)", err)
	}
}

// TestAFreshUpdateLinksItForSudo: on Unix an update that installs conflux where there was none
// makes the link install.sh makes for sudo where the conflux the update's own PATH -- root's,
// under sudo -- finds is not the installed file, and keeps it only where that PATH, asked again,
// finds the installed file through it: one that leaves its directory out, or finds another
// conflux after the link's directory. One that finds another before it would do nothing there,
// so none is left, a link made before included, and the other is named, to be removed before the
// link is made by hand -- the line that makes it said, not the installer, which would fetch the
// release and move a dev build off its channel. As install.sh does, it makes none where that PATH
// finds the installed file, and leaves a file of the link's name that is not that link alone,
// saying so.
// Each PATH is the test's own directories, the link's among them as /usr/bin is on every root's
// but where a case leaves it out, so no conflux of the machine's is found.
func TestAFreshUpdateLinksItForSudo(t *testing.T) {
	asRoot(t, true)

	newer := []byte("#!/bin/sh\necho 'conflux 9.9.9 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH + "'\n")

	// Another conflux, in a directory a PATH can name before the installed file's or the link's.
	other := filepath.Join(t.TempDir(), "conflux")
	if err := os.WriteFile(other, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	const (
		relink   = "remove it, then link the installed conflux for sudo (sudo ln -s {exe} {link}), or type {exe} by its full path under sudo"
		shadowed = "root's PATH finds {other} before {dir}: " + relink
		leftOut  = "root's PATH leaves {dir} out too: type {exe} by its full path under sudo"
	)

	for _, c := range []struct {
		name   string
		path   []string // "exe", "other", "link" and "spelt": the directories of each, in this order
		before string   // at the link's name before the update: "link", an earlier install's, or "file", somebody else's
		after  string   // and after it: "link", "file" or nothing
		said   string   // what the update says of it, {exe}, {link} and {other} standing for each and {dir} for the link's directory; "" for nothing
	}{
		{name: "a PATH that leaves it out", path: []string{"link"}, after: "link", said: "Linked {link} to it"},
		{name: "a PATH that holds it", path: []string{"exe", "link"}},
		{name: "a PATH that finds another conflux before the link", path: []string{"other", "link"}, said: shadowed},
		{name: "a PATH that finds another conflux before it", path: []string{"other", "exe", "link"}, said: shadowed},
		{name: "a PATH that finds another conflux after the link", path: []string{"link", "other"}, after: "link", said: "Linked {link} to it"},
		{name: "a PATH that finds it through a link made before", path: []string{"link"}, before: "link", after: "link"},
		{name: "a link made before, behind another conflux", path: []string{"other", "link"}, before: "link", said: shadowed},
		{name: "a link made before, its directory left out", path: nil, before: "link", said: leftOut},
		{
			name: "a file at the link's name, which the PATH finds", path: []string{"link"}, before: "file", after: "file",
			said: "{link} is not conflux's, and root's PATH finds it rather than {exe}: " + relink,
		},
		{
			name: "a file at the link's name, which the PATH finds through another spelling", path: []string{"spelt"}, before: "file", after: "file",
			said: "{link} is not conflux's, and root's PATH finds it rather than {exe}: " + relink,
		},
		{
			name: "a file at the link's name, behind another conflux", path: []string{"other", "link"}, before: "file", after: "file",
			said: "{link} is not conflux's, and root's PATH finds {other} instead: type {exe} by its full path under sudo",
		},
	} {
		exe := filepath.Join(t.TempDir(), "bin", "conflux")
		serveRelease(t, newer, exe)
		link := updateLink()

		// "spelt" is the link's directory by another name, as a merged /bin is /usr/bin.
		spelt := filepath.Join(t.TempDir(), "bin")
		if err := os.Symlink(filepath.Dir(link), spelt); err != nil {
			t.Fatal(err)
		}

		dirs := map[string]string{"exe": filepath.Dir(exe) + "/", "other": filepath.Dir(other), "link": filepath.Dir(link), "spelt": spelt}

		var path []string
		for _, p := range c.path {
			path = append(path, dirs[p])
		}

		t.Setenv("PATH", strings.Join(path, string(os.PathListSeparator)))

		switch c.before {
		case "link":
			if err := os.Symlink(exe, link); err != nil {
				t.Fatal(err)
			}
		case "file":
			if err := os.WriteFile(link, []byte("somebody else's"), 0o755); err != nil {
				t.Fatal(err)
			}
		}

		out, errOut, code := capture(t, "update")
		if code != ExitOK {
			t.Fatalf("%s: the update exited %d:\n%s%s", c.name, code, out, errOut)
		}

		after := ""
		if target, err := os.Readlink(link); err == nil && target == exe {
			after = "link"
		} else if got, err := os.ReadFile(link); err == nil && string(got) == "somebody else's" {
			after = "file"
		} else if _, err := os.Lstat(link); !os.IsNotExist(err) {
			after = "something else"
		}

		said := strings.NewReplacer("{exe}", exe, "{link}", link, "{other}", other, "{dir}", filepath.Dir(link)).Replace(c.said)

		if after != c.after || (said == "" && (errOut != "" || strings.Contains(out, "Linked"))) || !strings.Contains(out+errOut, said) {
			t.Errorf("%s: %q is at %s, want %q, and the update said:\n%s%s\nwant it to say: %s", c.name, after, link, c.after, out, errOut, said)
		}
	}
}
