package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A release, served the way GitHub serves one: a release document listing assets by id,
// with the digest of each, and an asset endpoint per id that answers with the bytes.
type fakeRelease struct {
	files map[string][]byte

	// served replaces what the asset endpoint answers, for a body that is not the one
	// the document describes. state and noDigest change what the document says.
	served   []byte
	state    string
	noDigest bool

	// status, if set, is what the release document answers instead.
	status int
	header map[string]string
}

func (f *fakeRelease) serve(t *testing.T) Source {
	t.Helper()

	// Ids by name, the same in the document and at the asset endpoint.
	names := slices.Sorted(maps.Keys(f.files))

	mux := http.NewServeMux()

	mux.HandleFunc("/repos/veil-net/conflux/releases/tags/", func(w http.ResponseWriter, r *http.Request) {
		if f.status != 0 {
			for k, v := range f.header {
				w.Header().Set(k, v)
			}

			w.WriteHeader(f.status)

			return
		}

		if strings.TrimPrefix(r.URL.Path, "/repos/veil-net/conflux/releases/tags/") != "latest" {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		var assets []map[string]any

		for i, name := range names {
			body := f.files[name]
			sum := sha256.Sum256(body)

			digest := "sha256:" + hex.EncodeToString(sum[:])
			if f.noDigest {
				digest = ""
			}

			state := "uploaded"
			if f.state != "" {
				state = f.state
			}

			assets = append(assets, map[string]any{"id": i + 1, "name": name, "size": len(body), "state": state, "digest": digest})
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":             "latest (1.1.0)",
			"tag_name":         "latest",
			"target_commitish": "0aea0f77bb77f8bbaa23c5055d9fe245d3a9bee2",
			"assets":           assets,
		})
	})

	mux.HandleFunc("/repos/veil-net/conflux/releases/assets/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("a request to a public repository carried a credential")
		}

		if f.served != nil {
			_, _ = w.Write(f.served)

			return
		}

		var want int
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/repos/veil-net/conflux/releases/assets/"), "%d", &want)

		if want < 1 || want > len(names) {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		_, _ = w.Write(f.files[names[want-1]])
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Setenv(insecureEnv, "1")

	return Source{API: srv.URL, UserAgent: "conflux/test"}
}

var newBuild = []byte("\x7fELF a newer conflux")

func TestAnUpdateIsDownloadedVerifiedAndPutInPlace(t *testing.T) {
	f := &fakeRelease{files: map[string][]byte{
		"conflux-linux-amd64":       newBuild,
		"conflux-windows-amd64.exe": []byte("MZ"),
		"SHA256SUMS":                []byte("…"),
	}}
	src := f.serve(t)

	rel, err := Latest(context.Background(), src, "linux", "amd64")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}

	if rel.Asset != "conflux-linux-amd64" || rel.Name != "latest (1.1.0)" || rel.Commit == "" {
		t.Errorf("Latest picked %+v", rel)
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "conflux")

	if err := os.WriteFile(exe, []byte("\x7fELF this conflux"), 0o755); err != nil {
		t.Fatal(err)
	}

	if same, err := rel.Is(exe); err != nil || same {
		t.Fatalf("Is says an older binary is the release's: %v, %v", same, err)
	}

	tmp, err := rel.Download(context.Background(), dir)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}

	if err := Replace(tmp, exe); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	got, err := os.ReadFile(exe)
	if err != nil || !bytes.Equal(got, newBuild) {
		t.Fatalf("after Replace the executable holds %q, %v", got, err)
	}

	if same, err := rel.Is(exe); err != nil || !same {
		t.Errorf("Is does not recognise the release's own binary: %v, %v", same, err)
	}

	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the directory holds %d files after an update, want just the executable", len(entries))
	}
}

func TestAWindowsAssetIsNamedAndDownloadedAsAnExecutable(t *testing.T) {
	f := &fakeRelease{files: map[string][]byte{"conflux-windows-arm64.exe": []byte("MZ a newer conflux")}}

	rel, err := Latest(context.Background(), f.serve(t), "windows", "arm64")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}

	tmp, err := rel.Download(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Download: %v", err)
	}

	if filepath.Ext(tmp) != ".exe" {
		t.Errorf("the download is %s, which Windows would not run", filepath.Base(tmp))
	}
}

// TestSubstitutedBytesAreNeverLeftBehind: a body that is not the one the release document
// describes fails the compare, and nothing it wrote survives to be run.
func TestSubstitutedBytesAreNeverLeftBehind(t *testing.T) {
	f := &fakeRelease{files: map[string][]byte{"conflux-linux-amd64": newBuild}}
	src := f.serve(t)

	rel, err := Latest(context.Background(), src, "linux", "amd64")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}

	for _, body := range [][]byte{
		[]byte("\x7fELF somebody else's program, same len"),
		newBuild[:len(newBuild)-1],
	} {
		f.served = body
		dir := t.TempDir()

		if _, err := rel.Download(context.Background(), dir); err == nil {
			t.Errorf("Download accepted %q", body)
		}

		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("a rejected download left %d file(s) behind", len(entries))
		}
	}
}

func TestAReleaseThatCannotBeTrustedOrUsedIsRefused(t *testing.T) {
	cases := []struct {
		name string
		f    fakeRelease
		want string
	}{
		{"no digest", fakeRelease{files: map[string][]byte{"conflux-linux-amd64": newBuild}, noDigest: true}, "no SHA-256"},
		{"still uploading", fakeRelease{files: map[string][]byte{"conflux-linux-amd64": newBuild}, state: "starter"}, "not finished"},
		{"no build for this platform", fakeRelease{files: map[string][]byte{"conflux-darwin-arm64": newBuild}}, "no conflux-linux-amd64"},
		{"no release", fakeRelease{status: http.StatusNotFound}, "no release tagged"},
		{"rate limited", fakeRelease{status: http.StatusForbidden, header: map[string]string{"X-RateLimit-Remaining": "0"}}, "limit"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Latest(context.Background(), c.f.serve(t), "linux", "amd64")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Latest: %v, want an error mentioning %q", err, c.want)
			}
		})
	}
}

func TestPlainHTTPIsRefusedUnlessATestAsksForIt(t *testing.T) {
	t.Setenv(insecureEnv, "")

	if _, err := Latest(context.Background(), Source{API: "http://127.0.0.1:1"}, "linux", "amd64"); err == nil ||
		!strings.Contains(err.Error(), "plain http") {
		t.Errorf("Latest over plain http: %v", err)
	}

	if err := checkScheme("ftp://example.com"); err == nil {
		t.Error("checkScheme accepted ftp")
	}
}

// TestARedirectToPlainHTTPIsRefused: the hop to storage is followed, but not one that
// would hand the binary to anyone on the path.
func TestARedirectToPlainHTTPIsRefused(t *testing.T) {
	t.Setenv(insecureEnv, "")

	req, _ := http.NewRequest(http.MethodGet, "http://objects.example.com/conflux", nil)
	if err := httpClient.CheckRedirect(req, nil); err == nil {
		t.Error("a redirect to plain http was followed")
	}
}

func TestAssetNamesAreTheOnesDistBuilds(t *testing.T) {
	for goos, want := range map[string]string{
		"linux":   "conflux-linux-amd64",
		"windows": "conflux-windows-amd64.exe",
		"freebsd": "conflux-freebsd-amd64",
	} {
		if got := AssetName(goos, "amd64"); got != want {
			t.Errorf("AssetName(%s, amd64) = %s, want %s", goos, got, want)
		}
	}
}
