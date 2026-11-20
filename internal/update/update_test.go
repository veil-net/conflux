package update

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/ghrelease/ghreleasetest"
	"github.com/veil-net/conflux/internal/httpsonly"
)

// release is conflux's `latest` release holding files, served the way GitHub serves one.
func release(files map[string][]byte) *ghreleasetest.Release {
	return &ghreleasetest.Release{
		Repo:   DefaultRepo,
		Name:   "latest (1.1.0)",
		Commit: "0aea0f77bb77f8bbaa23c5055d9fe245d3a9bee2",
		Files:  files,
	}
}

// serve stands f up and points a Source at it. Auth stays empty: conflux is public, so a
// request that carried a credential fails the test.
func serve(t *testing.T, f *ghreleasetest.Release) Source {
	t.Helper()

	return Source{API: f.Serve(t), UserAgent: "conflux/test"}
}

var newBuild = []byte("\x7fELF a newer conflux")

func TestAnUpdateIsDownloadedVerifiedAndPutInPlace(t *testing.T) {
	src := serve(t, release(map[string][]byte{
		"conflux-linux-amd64":       newBuild,
		"conflux-windows-amd64.exe": []byte("MZ"),
		"SHA256SUMS":                []byte("…"),
	}))

	rel, err := Latest(context.Background(), src, "linux", "amd64")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}

	if rel.Asset != "conflux-linux-amd64" || rel.Name != "latest (1.1.0)" || rel.Commit == "" ||
		rel.Bytes != int64(len(newBuild)) {
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
	f := release(map[string][]byte{"conflux-windows-arm64.exe": []byte("MZ a newer conflux")})

	rel, err := Latest(context.Background(), serve(t, f), "windows", "arm64")
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
	f := release(map[string][]byte{"conflux-linux-amd64": newBuild})
	src := serve(t, f)

	rel, err := Latest(context.Background(), src, "linux", "amd64")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}

	for _, body := range [][]byte{
		[]byte("\x7fELF somebody else's program, same len"),
		newBuild[:len(newBuild)-1],
	} {
		f.Served = map[string][]byte{"conflux-linux-amd64": body}
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
	ours := map[string][]byte{"conflux-linux-amd64": newBuild}

	cases := []struct {
		name string
		f    func(*ghreleasetest.Release)
		want string
	}{
		{"no digest", func(f *ghreleasetest.Release) { f.NoDigest = true }, "no SHA-256"},
		{"still uploading", func(f *ghreleasetest.Release) { f.States = map[string]string{"conflux-linux-amd64": "starter"} }, "not finished"},
		{"no build for this platform", func(f *ghreleasetest.Release) {
			f.Files = map[string][]byte{"conflux-darwin-arm64": newBuild}
		}, "no conflux-linux-amd64"},
		{"no release", func(f *ghreleasetest.Release) { f.Status = http.StatusNotFound }, "no release tagged"},
		{"rate limited", func(f *ghreleasetest.Release) {
			f.Status, f.Header = http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"}
		}, "limit"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := release(ours)
			c.f(f)

			_, err := Latest(context.Background(), serve(t, f), "linux", "amd64")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Latest: %v, want an error mentioning %q", err, c.want)
			}
		})
	}
}

func TestPlainHTTPIsRefusedUnlessATestAsksForIt(t *testing.T) {
	t.Setenv(httpsonly.InsecureEnv, "")

	if _, err := Latest(context.Background(), Source{API: "http://127.0.0.1:1"}, "linux", "amd64"); err == nil ||
		!strings.Contains(err.Error(), "plain http") {
		t.Errorf("Latest over plain http: %v", err)
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
