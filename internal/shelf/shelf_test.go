package shelf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// serve stands up a shelf holding the given files, and returns its base URL.
//
// The manifest's own urls point back at this server, which is what makes the same-host
// rule testable: a test that wants to break it rewrites them afterwards.
func serve(t *testing.T, files map[string][]byte, edit func(*Manifest)) string {
	t.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	m := Manifest{FormatVersion: 1, Pin: "realmtestpin"}

	for name, body := range files {
		sum := sha256.Sum256(body)
		m.Binaries = append(m.Binaries, Binary{
			Name:   name,
			Bytes:  int64(len(body)),
			SHA256: hex.EncodeToString(sum[:]),
			URL:    srv.URL + "/" + name,
		})

		mux.HandleFunc("/"+name, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(body)
		})
	}

	if edit != nil {
		edit(&m)
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(m)
	})

	// The test server is plain http, which Fetch refuses by design. Same override
	// internal/enrol's client uses, and set through t.Setenv so it cannot leak.
	t.Setenv(insecureEnv, "1")

	return srv.URL
}

func quiet(string, ...any) {}

func TestFetchWritesVerifiedBinaries(t *testing.T) {
	files := map[string][]byte{
		"anchord-linux-amd64":   []byte("an anchord, for the purposes of this test"),
		"anchorctl-linux-amd64": []byte("an anchorctl"),
	}

	dir := t.TempDir()
	base := serve(t, files, nil)

	if err := Fetch(context.Background(), base, keys(files), dir, quiet); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if string(got) != string(want) {
			t.Errorf("%s: content is %q, want %q", name, got, want)
		}

		// Executable, because the whole point is that libexec extracts and runs it.
		//
		// Not on Windows: Go maps a file mode to the read-only attribute there, so
		// Perm() never reports an executable bit and this would fail on every run for
		// a reason that has nothing to do with the fetch. internal/config's atomic
		// tests skip for the same reason and say the same thing -- mode bits are not
		// meaningful on windows, the DACL is.
		if runtime.GOOS == "windows" {
			continue
		}

		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}

		if info.Mode().Perm()&0o111 == 0 {
			t.Errorf("%s: mode is %v, which is not executable", name, info.Mode().Perm())
		}
	}
}

// TestFetchRefusesAWrongDigest is the assertion the whole package exists for. A shelf
// that serves the wrong bytes for a name is the failure no later gate catches: a real
// binary of the right size passes the size gate in `make dist`, and one of the right
// architecture passes anchor.TestPairIsRealExecutables.
func TestFetchRefusesAWrongDigest(t *testing.T) {
	files := map[string][]byte{"anchord-linux-amd64": []byte("the right bytes")}

	base := serve(t, files, func(m *Manifest) {
		m.Binaries[0].SHA256 = strings.Repeat("00", sha256.Size)
		m.Binaries[0].Bytes = 0 // so the length check does not fire first
	})

	dir := t.TempDir()

	err := Fetch(context.Background(), base, keys(files), dir, quiet)
	if err == nil {
		t.Fatal("a digest that does not match should be refused")
	}

	if !strings.Contains(err.Error(), "sha256") {
		t.Errorf("the error should name the digest; it said: %v", err)
	}

	// And nothing is left behind: a rejected download must not be renamed into place,
	// or the next build embeds it.
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a refused download left %d files in place", len(entries))
	}
}

// TestFetchRefusesAnchoradmin: it mints realm roots, and anything in anchor/bin is a
// candidate for being embedded into every conflux a user runs. Refused rather than
// filtered, because a shelf serving it at all is worth stopping over.
func TestFetchRefusesAnchoradmin(t *testing.T) {
	files := map[string][]byte{
		"anchord-linux-amd64":     []byte("fine"),
		"anchoradmin-linux-amd64": []byte("not fine"),
	}

	base := serve(t, files, nil)

	err := Fetch(context.Background(), base, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil {
		t.Fatal("a shelf serving anchoradmin should be refused")
	}

	if !strings.Contains(err.Error(), "anchoradmin") {
		t.Errorf("the error should name it; it said: %v", err)
	}
}

func TestFetchNamesWhatIsMissing(t *testing.T) {
	files := map[string][]byte{"anchord-linux-amd64": []byte("only one of them")}

	base := serve(t, files, nil)

	err := Fetch(context.Background(), base,
		[]string{"anchord-linux-amd64", "anchorctl-linux-amd64", "anchord-darwin-arm64"},
		t.TempDir(), quiet)
	if err == nil {
		t.Fatal("a partial shelf should be refused")
	}

	// Both of them, by name. This is the state the real shelf is in today, so the
	// message is the thing somebody acts on.
	for _, want := range []string{"anchorctl-linux-amd64", "anchord-darwin-arm64"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should name %s; it said: %v", want, err)
		}
	}
}

func TestFetchRefusesAnUnknownFormatVersion(t *testing.T) {
	files := map[string][]byte{"anchord-linux-amd64": []byte("x")}

	base := serve(t, files, func(m *Manifest) { m.FormatVersion = 2 })

	err := Fetch(context.Background(), base, keys(files), t.TempDir(), quiet)
	if err == nil {
		t.Fatal("a future manifest format should be refused rather than guessed at")
	}
}

func TestFetchRefusesAManifestWithNoPin(t *testing.T) {
	files := map[string][]byte{"anchord-linux-amd64": []byte("x")}

	base := serve(t, files, func(m *Manifest) { m.Pin = "" })

	err := Fetch(context.Background(), base, keys(files), t.TempDir(), quiet)
	if err == nil {
		t.Fatal("a manifest with no pin says nothing about which realm these are for")
	}
}

// TestFetchRefusesAForeignURL: the manifest names its own download urls, so a shelf
// could point them at a third party. The digest would catch substituted content; this
// catches being sent somewhere conflux was never told about.
func TestFetchRefusesAForeignURL(t *testing.T) {
	files := map[string][]byte{"anchord-linux-amd64": []byte("x")}

	base := serve(t, files, func(m *Manifest) {
		m.Binaries[0].URL = "https://example.invalid/anchord-linux-amd64"
	})

	err := Fetch(context.Background(), base, keys(files), t.TempDir(), quiet)
	if err == nil {
		t.Fatal("a per-binary url on another host should be refused")
	}

	if !strings.Contains(err.Error(), "example.invalid") {
		t.Errorf("the error should name the host; it said: %v", err)
	}
}

func TestFetchRefusesPlainHTTPWithoutTheOverride(t *testing.T) {
	files := map[string][]byte{"anchord-linux-amd64": []byte("x")}
	base := serve(t, files, nil)

	// serve() set the override; take it away again for this one.
	t.Setenv(insecureEnv, "")

	err := Fetch(context.Background(), base, keys(files), t.TempDir(), quiet)
	if err == nil {
		t.Fatal("a plain-http shelf should be refused unless the override is set")
	}

	if !strings.Contains(err.Error(), "plain http") {
		t.Errorf("the error should say why; it said: %v", err)
	}
}

func TestFetchRefusesAShortBody(t *testing.T) {
	files := map[string][]byte{"anchord-linux-amd64": []byte("the whole thing")}

	base := serve(t, files, func(m *Manifest) { m.Binaries[0].Bytes = 999999 })

	err := Fetch(context.Background(), base, keys(files), t.TempDir(), quiet)
	if err == nil {
		t.Fatal("a body shorter than the manifest promises should be refused")
	}

	if !strings.Contains(err.Error(), "bytes") {
		t.Errorf("the error should name the length; it said: %v", err)
	}
}

func TestFetchReportsTheRealm(t *testing.T) {
	files := map[string][]byte{"anchord-linux-amd64": []byte("x")}
	base := serve(t, files, nil)

	var lines []string
	log := func(format string, a ...any) { lines = append(lines, fmt.Sprintf(format, a...)) }

	if err := Fetch(context.Background(), base, keys(files), t.TempDir(), log); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// The realm these binaries are pinned to decides which tree a conflux built from
	// them can ever join, so it belongs in front of whoever ran the build.
	if !strings.Contains(strings.Join(lines, "\n"), "realmtestpin") {
		t.Errorf("the pin was not reported; the output was:\n%s", strings.Join(lines, "\n"))
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	return out
}
