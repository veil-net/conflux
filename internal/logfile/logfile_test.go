package logfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixed() time.Time { return time.Date(2026, 11, 2, 9, 30, 0, 123e6, time.UTC) }

// TestEachLineIsStamped: every line is stamped once, at its start, however the writes that
// make it are cut -- a line in two writes, two lines in one.
func TestEachLineIsStamped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conflux.log")

	w, err := open(path, Max, fixed, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range []string{"  anchor is up\n", "conflux: the observer ", "did not start\n", "one\ntwo\n"} {
		if n, err := w.Write([]byte(s)); err != nil || n != len(s) {
			t.Fatalf("Write(%q) = %d, %v", s, n, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	got, _ := os.ReadFile(path)
	want := "2026-11-02T09:30:00.123Z   anchor is up\n" +
		"2026-11-02T09:30:00.123Z conflux: the observer did not start\n" +
		"2026-11-02T09:30:00.123Z one\n" +
		"2026-11-02T09:30:00.123Z two\n"

	if string(got) != want {
		t.Errorf("the log is\n%s\nwant\n%s", got, want)
	}
}

// TestAFullLogIsMovedAside: past its size the log is moved to .1, replacing the one before,
// at the start of a line and never in one, and what was there is kept.
func TestAFullLogIsMovedAside(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conflux.log")

	if err := os.WriteFile(path, []byte("from before\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w, err := open(path, 100, fixed, false)
	if err != nil {
		t.Fatal(err)
	}

	defer w.Close()

	for i := range 12 {
		fmt.Fprintf(w, "line %d ", i)
		fmt.Fprintf(w, "ends here\n")
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("the directory holds %d files, want the log and one moved aside", len(entries))
	}

	for _, p := range []string{path, path + ".1"} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}

		for line := range strings.Lines(string(b)) {
			if line != "from before\n" && !strings.HasPrefix(line, "2026-11-02T09:30:00.123Z line ") {
				t.Errorf("%s holds a line cut or unstamped: %q", filepath.Base(p), line)
			}
		}

		if len(b) > 100+len("2026-11-02T09:30:00.123Z line 10 ends here\n") {
			t.Errorf("%s is %d bytes, past the size and the one line that crossed it", filepath.Base(p), len(b))
		}
	}

	last, _ := os.ReadFile(path)
	if !strings.HasSuffix(string(last), "line 11 ends here\n") {
		t.Errorf("the log does not end with the last line written:\n%s", last)
	}
}

// TestRemoveTakesBoth: uninstall's removal takes the log and the one moved aside, and is
// content when neither is there.
func TestRemoveTakesBoth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conflux.log")

	for _, p := range []string{path, path + ".1"} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := Remove(path); err != nil {
		t.Fatal(err)
	}

	if err := Remove(path); err != nil {
		t.Errorf("a second Remove = %v, want nil", err)
	}

	for _, p := range []string{path, path + ".1"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived Remove", p)
		}
	}
}
