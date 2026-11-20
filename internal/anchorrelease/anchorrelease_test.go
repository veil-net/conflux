package anchorrelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/ghrelease"
	"github.com/veil-net/conflux/internal/ghrelease/ghreleasetest"
)

// newRelease is anchor's release holding files, with the manifest.json that describes
// them, served the way GitHub serves one. Every request must carry the token.
func newRelease(files map[string][]byte, pin string, version int) *ghreleasetest.Release {
	all := maps.Clone(files)
	all[manifestName] = []byte(manifestOf(files, pin, version))

	return &ghreleasetest.Release{
		Repo:   DefaultRepo,
		Tag:    "latest",
		Commit: "0aea0f77bb77f8bbaa23c5055d9fe245d3a9bee2",
		Files:  all,
		Auth:   "Bearer t0ken",
	}
}

// serve stands f up and points a Source at it.
func serve(t *testing.T, f *ghreleasetest.Release) Source {
	t.Helper()

	return Source{API: f.Serve(t), Repo: "veil-net/anchor", Tag: "latest", Token: "t0ken"}
}

// manifestOf is the manifest.json describing files.
func manifestOf(files map[string][]byte, pin string, version int) string {
	type entry struct {
		Name    string `json:"name"`
		Program string `json:"program"`
		OS      string `json:"os"`
		Arch    string `json:"arch"`
		Bytes   int64  `json:"bytes"`
		SHA256  string `json:"sha256"`
	}

	var entries []entry

	for name, body := range files {
		sum := sha256.Sum256(body)
		entries = append(entries, entry{
			Name:    name,
			Program: strings.SplitN(name, "-", 2)[0],
			OS:      "linux",
			Arch:    "amd64",
			Bytes:   int64(len(body)),
			SHA256:  hex.EncodeToString(sum[:]),
		})
	}

	// In one order, as a file is: the release document's digest of it and the bytes the
	// asset endpoint serves are two renderings that must agree.
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.Name, b.Name) })

	out, _ := json.Marshal(map[string]any{
		"formatVersion": version,
		"pin":           pin,
		"binaries":      entries,
	})

	return string(out)
}

// rewrite replaces old with new in f's manifest.json, once: a manifest that says something
// other than what is served.
func rewrite(f *ghreleasetest.Release, old, new string) {
	f.Files[manifestName] = []byte(strings.Replace(string(f.Files[manifestName]), old, new, 1))
}

func quiet(string, ...any) {}

const testPin = "realmtglwuedqqa33e364nv73p46jk3kwi67lxjmnntz2mv3mb3mklasq"

func pair() map[string][]byte {
	return map[string][]byte{
		"anchord-linux-amd64":   []byte(strings.Repeat("d", 4096)),
		"anchorctl-linux-amd64": []byte(strings.Repeat("c", 2048)),
	}
}

func TestFetchWritesVerifiedBinaries(t *testing.T) {
	files := pair()
	f := newRelease(files, testPin, 1)
	src := serve(t, f)

	dir := t.TempDir()

	want := []string{"anchord-linux-amd64", "anchorctl-linux-amd64"}
	if err := Fetch(context.Background(), src, want, dir, quiet); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	for _, name := range want {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}

		if string(got) != string(files[name]) {
			t.Errorf("%s: wrong bytes", name)
		}

		// Not on Windows: Go maps a file mode to the read-only attribute there, so
		// Perm() never reports an executable bit whatever was asked for.
		if runtime.GOOS == "windows" {
			continue
		}

		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}

		if fi.Mode().Perm()&0o111 == 0 {
			t.Errorf("%s is not executable: %v", name, fi.Mode().Perm())
		}
	}
}

// TestFetchKeepsAVerifiedCopy: a binary already in place with the manifest's digest is
// not downloaded again, and one that differs from it -- a stale or a poisoned cache --
// is replaced by the verified download.
func TestFetchKeepsAVerifiedCopy(t *testing.T) {
	files := pair()
	f := newRelease(files, testPin, 1)
	src := serve(t, f)

	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "anchord-linux-amd64"), files["anchord-linux-amd64"], 0o755); err != nil {
		t.Fatal(err)
	}

	stale := []byte(strings.Repeat("x", len(files["anchorctl-linux-amd64"])))
	if err := os.WriteFile(filepath.Join(dir, "anchorctl-linux-amd64"), stale, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := Fetch(context.Background(), src, []string{"anchord-linux-amd64", "anchorctl-linux-amd64"}, dir, quiet); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	var downloads []string

	for _, p := range f.Seen() {
		if strings.Contains(p, "/releases/assets/") {
			downloads = append(downloads, p)
		}
	}

	// The manifest, and the one binary that did not match.
	if len(downloads) != 2 {
		t.Errorf("downloaded %d assets, want the manifest and the stale binary: %v", len(downloads), downloads)
	}

	if got, _ := os.ReadFile(filepath.Join(dir, "anchorctl-linux-amd64")); string(got) != string(files["anchorctl-linux-amd64"]) {
		t.Error("a binary that did not match the manifest was kept")
	}
}

// The token must reach the API and it must be a Bearer. A fetch that silently sent no
// credential would pass against a server that does not check one, and fail only against
// the private repository it exists for. The fake holds every request to the bearer
// (newRelease's Auth); this is the fetch that makes sure there were requests to hold.
func TestFetchSendsTheToken(t *testing.T) {
	f := newRelease(pair(), testPin, 1)
	src := serve(t, f)

	if err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if len(f.Seen()) == 0 {
		t.Fatal("no requests were made")
	}
}

func TestFetchRefusesAWrongDigest(t *testing.T) {
	files := pair()
	f := newRelease(files, testPin, 1)

	// A manifest describing different bytes from the ones served: the substitution the
	// digest exists to catch.
	rewrite(f, hex.EncodeToString(sha256Of(files["anchord-linux-amd64"])), strings.Repeat("a", 64))

	src := serve(t, f)

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("want a digest refusal, got %v", err)
	}
}

// A failed fetch must leave nothing behind: not a half-written file, which the temp-and-rename
// keeps from being mistaken for a binary, and not the binaries that did arrive, which beside
// an older copy of the one that did not would be a pair from two builds.
func TestARefusedFetchWritesNothing(t *testing.T) {
	files := pair()
	f := newRelease(files, testPin, 1)
	rewrite(f, hex.EncodeToString(sha256Of(files["anchord-linux-amd64"])), strings.Repeat("a", 64))

	src := serve(t, f)

	dir := t.TempDir()

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64", "anchorctl-linux-amd64"}, dir, quiet)
	if err == nil {
		t.Fatal("want a refusal")
	}

	left, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(left) != 0 {
		names := []string{}
		for _, e := range left {
			names = append(names, e.Name())
		}

		t.Fatalf("a refused fetch left %v behind", names)
	}
}

// anchoradmin mints realm roots. Refused on sight in the release, before anything is
// downloaded -- not merely left unselected.
func TestFetchRefusesAnchoradminInTheRelease(t *testing.T) {
	files := pair()
	files["anchoradmin-linux-amd64"] = []byte("admin")

	f := newRelease(files, testPin, 1)
	src := serve(t, f)

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "anchoradmin") {
		t.Fatalf("want an anchoradmin refusal, got %v", err)
	}
}

func TestFetchNamesWhatIsMissing(t *testing.T) {
	f := newRelease(pair(), testPin, 1)
	src := serve(t, f)

	want := []string{"anchord-linux-amd64", "anchord-darwin-arm64", "anchorctl-darwin-arm64"}

	err := Fetch(context.Background(), src, want, t.TempDir(), quiet)
	if err == nil {
		t.Fatal("want a missing-binaries refusal")
	}

	for _, name := range []string{"anchord-darwin-arm64", "anchorctl-darwin-arm64"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the error does not name %s: %v", name, err)
		}
	}
}

// A binary the manifest describes but that was never attached. Distinct from "not in the
// manifest", and the message says which -- they have different causes in anchor's
// publish step.
func TestFetchNamesAnUnattachedBinary(t *testing.T) {
	files := pair()
	f := newRelease(files, testPin, 1)

	// Describe a third binary in the manifest without serving it.
	rewrite(f, `"binaries":[`,
		`"binaries":[{"name":"anchord-darwin-arm64","program":"anchord","os":"darwin","arch":"arm64","bytes":1,"sha256":"`+
			strings.Repeat("b", 64)+`"},`)

	src := serve(t, f)

	err := Fetch(context.Background(), src, []string{"anchord-darwin-arm64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "not attached to the release") {
		t.Fatalf("want an unattached refusal, got %v", err)
	}
}

func TestFetchRefusesAnUnknownFormatVersion(t *testing.T) {
	f := newRelease(pair(), testPin, 2)
	src := serve(t, f)

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "format") {
		t.Fatalf("want a format refusal, got %v", err)
	}
}

func TestFetchRefusesAManifestWithNoPin(t *testing.T) {
	f := newRelease(pair(), "", 1)
	src := serve(t, f)

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("want a pin refusal, got %v", err)
	}
}

// A release with no manifest describes nothing, so nothing can be verified -- and the
// binaries are there, which is what makes this worth refusing rather than shrugging at.
func TestFetchRefusesAReleaseWithNoManifest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 1, "tag_name": "latest", "target_commitish": "abc",
			"assets": []map[string]any{
				{"id": 1, "name": "anchord-linux-amd64", "size": 4096, "state": "uploaded"},
			},
		})
	}))
	t.Cleanup(srv.Close)

	t.Setenv(ghrelease.InsecureEnv, "1")

	src := Source{API: srv.URL, Repo: "veil-net/anchor", Tag: "latest", Token: "t0ken"}

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), manifestName) {
		t.Fatalf("want a missing-manifest refusal, got %v", err)
	}
}

// Half-uploaded assets mean the publish step is still running, or failed part way. Either
// way the release is not what the manifest claims yet.
func TestFetchRefusesAnUnfinishedRelease(t *testing.T) {
	f := newRelease(pair(), testPin, 1)
	f.States = map[string]string{"anchord-linux-amd64": "starter"}

	src := serve(t, f)

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "not finished") {
		t.Fatalf("want an unfinished-release refusal, got %v", err)
	}
}

func TestFetchWithoutATokenSaysSo(t *testing.T) {
	f := newRelease(pair(), testPin, 1)
	src := serve(t, f)

	src.Token = ""

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), TokenEnv) {
		t.Fatalf("want an error naming %s, got %v", TokenEnv, err)
	}
}

// A 404 against a private repository is ambiguous between "no such tag" and "this token
// cannot see the repository", so the message has to raise both.
func TestAMissingTagNamesBothCauses(t *testing.T) {
	f := newRelease(pair(), testPin, 1)
	src := serve(t, f)

	src.Tag = "nope"

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil {
		t.Fatal("want a 404 refusal")
	}

	for _, s := range []string{"nope", "Contents: read", TokenEnv} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("the error does not mention %q: %v", s, err)
		}
	}
}

func TestARefusedTokenSaysSo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	t.Setenv(ghrelease.InsecureEnv, "1")

	src := Source{API: srv.URL, Repo: "veil-net/anchor", Tag: "latest", Token: "expired"}

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("want a 401 refusal, got %v", err)
	}
}

// TestA403SaysWhoRefused: a 403 from the API is the token's; one from the storage host a
// binary is redirected to, which is sent no token, is the signed link's, and saying the token
// lacks a permission there would send somebody to fix the wrong thing.
func TestA403SaysWhoRefused(t *testing.T) {
	src := ghrelease.Source{API: "https://api.github.com", Repo: "veil-net/anchor", Tag: "latest"}

	for host, want := range map[string]string{
		"api.github.com":                       "Contents: read",
		"release-assets.githubusercontent.com": "signed link",
	} {
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     http.Header{},
			Request:    &http.Request{URL: &url.URL{Scheme: "https", Host: host, Path: "/x"}},
		}

		if err := statusErr(resp, src); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("a 403 from %s: %v, want it to say %q", host, err, want)
		}
	}
}

func TestFetchRefusesPlainHTTPWithoutTheOverride(t *testing.T) {
	src := serve(t, newRelease(pair(), testPin, 1))

	// serve() sets the override; take it away again, which is the real configuration.
	t.Setenv(ghrelease.InsecureEnv, "")

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "plain http") {
		t.Fatalf("want a scheme refusal, got %v", err)
	}
}

// A truncated download is a real binary of nearly the right size, which is the shape
// neither the size gate in `make dist` nor the header check in anchor's own test would
// catch. The byte count is checked before the digest so the message says which it was.
func TestFetchRefusesAShortBody(t *testing.T) {
	files := pair()
	f := newRelease(files, testPin, 1)

	// Claim more bytes than are served.
	rewrite(f,
		fmt.Sprintf(`"bytes":%d`, len(files["anchord-linux-amd64"])),
		fmt.Sprintf(`"bytes":%d`, len(files["anchord-linux-amd64"])+1))

	src := serve(t, f)

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("want a short-body refusal, got %v", err)
	}
}

// The realm and the commit are the two lines worth reading on a fetch: they say which
// tree these binaries will talk to, and which anchor commit produced them.
func TestFetchReportsTheRealmAndCommit(t *testing.T) {
	f := newRelease(pair(), testPin, 1)
	src := serve(t, f)

	var out strings.Builder

	log := func(format string, a ...any) { fmt.Fprintf(&out, format+"\n", a...) }

	if err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), log); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	for _, s := range []string{testPin, f.Commit, "veil-net/anchor", "latest"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("the log does not mention %q:\n%s", s, out.String())
		}
	}
}

func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)

	return sum[:]
}

// TestFetchHoldsTheManifestToTheRelease: manifest.json arrives through the same redirect
// as the binaries, so a manifest substituted there -- with digests to match substituted
// binaries -- would vouch for anything. It is held to the digest the release document,
// answered by the API itself, gives for it; and a release giving none is refused.
func TestFetchHoldsTheManifestToTheRelease(t *testing.T) {
	files := pair()
	evil := manifestOf(map[string][]byte{"anchord-linux-amd64": []byte("not anchord")}, testPin, 1)

	f := newRelease(files, testPin, 1)
	f.Served = map[string][]byte{manifestName: []byte(evil)}
	src := serve(t, f)

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("want a refusal of the substituted manifest, got %v", err)
	}

	bare := newRelease(files, testPin, 1)
	bare.NoDigest = true
	src = serve(t, bare)

	err = Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "vouches") {
		t.Fatalf("want a refusal of a release giving no digest, got %v", err)
	}
}
