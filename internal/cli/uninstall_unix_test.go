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

// TestAFreshUpdateLinksItForSudo: on Unix an update that installs conflux where there was none
// makes the link install.sh makes for sudo where the conflux the update's own PATH -- root's,
// under sudo -- finds is not the installed file, and keeps it only where that PATH, asked again,
// finds the installed file through it: one that leaves its directory out, or finds another
// conflux after the link's directory. One that finds another before it would do nothing there,
// so none is left, and the other is named, as it is beside a link made before. As install.sh
// does, it makes none where that PATH finds the installed file, and leaves a file of the link's
// name that is not that link alone, saying so. Each PATH is the test's own directories, the
// link's among them as /usr/bin is on every root's, so no conflux of the machine's is found.
func TestAFreshUpdateLinksItForSudo(t *testing.T) {
	asRoot(t, true)

	newer := []byte("#!/bin/sh\necho 'conflux 9.9.9 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH + "'\n")

	// Another conflux, in a directory a PATH can name before the installed file's or the link's.
	other := filepath.Join(t.TempDir(), "conflux")
	if err := os.WriteFile(other, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	const (
		linked   = iota // the link to the installed file, said
		none            // no link, and nothing said
		shadowed        // no link made, and the other conflux named on stderr
		foreign         // the file at the link's name kept, and said
	)

	for _, c := range []struct {
		name string
		path []string // "exe", "other" and "link": the directories of each, in this order
		made bool     // the link is there before the update, as an earlier install made it
		want int
	}{
		{name: "a PATH that leaves it out", path: []string{"link"}, want: linked},
		{name: "a PATH that holds it", path: []string{"exe", "link"}, want: none},
		{name: "a PATH that finds another conflux before the link", path: []string{"other", "link"}, want: shadowed},
		{name: "a PATH that finds another conflux before it", path: []string{"other", "exe", "link"}, want: shadowed},
		{name: "a PATH that finds another conflux after the link", path: []string{"link", "other"}, want: linked},
		{name: "a link made before, behind another conflux", path: []string{"other", "link"}, made: true, want: shadowed},
		{name: "a file at the link's name", path: []string{"link"}, want: foreign},
	} {
		exe := filepath.Join(t.TempDir(), "bin", "conflux")
		serveRelease(t, newer, exe)
		link := updateLink()

		dirs := map[string]string{"exe": filepath.Dir(exe) + "/", "other": filepath.Dir(other), "link": filepath.Dir(link)}

		var path []string
		for _, p := range c.path {
			path = append(path, dirs[p])
		}

		t.Setenv("PATH", strings.Join(path, string(os.PathListSeparator)))

		switch {
		case c.made:
			if err := os.Symlink(exe, link); err != nil {
				t.Fatal(err)
			}
		case c.want == foreign:
			if err := os.WriteFile(link, []byte("somebody else's"), 0o755); err != nil {
				t.Fatal(err)
			}
		}

		out, errOut, code := capture(t, "update")
		if code != ExitOK {
			t.Fatalf("%s: the update exited %d:\n%s%s", c.name, code, out, errOut)
		}

		target, err := os.Readlink(link)

		switch c.want {
		case linked:
			if err != nil || target != exe || !strings.Contains(out, "Linked "+link) {
				t.Errorf("%s: %s links to %q (%v), want %s, and the update said:\n%s%s", c.name, link, target, err, exe, out, errOut)
			}
		case none:
			if !os.IsNotExist(err) || errOut != "" {
				t.Errorf("%s: the update made %s (%v), which root's PATH does not need, saying:\n%s", c.name, link, err, errOut)
			}
		case shadowed:
			if made := err == nil; made != c.made || !strings.Contains(errOut, "finds "+other+" before "+filepath.Dir(link)) {
				t.Errorf("%s: %s is there: %v, want %v, and the update said:\n%s%s", c.name, link, made, c.made, out, errOut)
			}
		case foreign:
			if got, _ := os.ReadFile(link); string(got) != "somebody else's" || !strings.Contains(errOut, link+" is not conflux's") {
				t.Errorf("%s: the update left %q there, saying:\n%s", c.name, got, errOut)
			}
		}
	}
}
