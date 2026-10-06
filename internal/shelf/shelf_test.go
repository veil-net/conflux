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
	"slices"
	"strings"
	"sync"
	"testing"
)

// A release, served the way GitHub serves one: a release document listing assets by id,
// and an asset endpoint per id that answers with the bytes.
//
// Modelled on the real API rather than on what this package happens to need, because the
// gap between those two is where a fetcher that passes its tests and fails in CI lives.
type fakeRelease struct {
	tag    string
	commit string
	files  map[string][]byte

	// states overrides an asset's state, for the half-finished-release case.
	states map[string]string

	// manifestJSON overrides the generated manifest, for the malformed cases.
	manifestJSON string
	// served, when set, is what the asset endpoint answers for the manifest in place of
	// the file the release document lists and digests: a substitution past the API.
	served string
	// noDigest leaves the release document's digests out.
	noDigest bool

	// mu guards what the server records: Fetch downloads every binary at once, so the
	// handlers that append run side by side.
	mu       sync.Mutex
	requests []string
	tokens   []string
}

// record notes a request, from whichever handler goroutine served it.
func (f *fakeRelease) record(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.requests = append(f.requests, r.URL.Path)
	f.tokens = append(f.tokens, r.Header.Get("Authorization"))
}

// seen is what the server recorded, copied under the lock.
func (f *fakeRelease) seen() (requests, tokens []string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.requests), slices.Clone(f.tokens)
}

func newRelease(files map[string][]byte) *fakeRelease {
	return &fakeRelease{
		tag:    "shelf",
		commit: "0aea0f77bb77f8bbaa23c5055d9fe245d3a9bee2",
		files:  files,
		states: map[string]string{},
	}
}

func (f *fakeRelease) manifest(pin string, version int) string {
	if f.manifestJSON != "" {
		return f.manifestJSON
	}

	type entry struct {
		Name    string `json:"name"`
		Program string `json:"program"`
		OS      string `json:"os"`
		Arch    string `json:"arch"`
		Bytes   int64  `json:"bytes"`
		SHA256  string `json:"sha256"`
	}

	var entries []entry

	for name, body := range f.files {
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

// serve returns a server and the Source pointing at it. The manifest is built from files
// unless one was set explicitly.
func (f *fakeRelease) serve(t *testing.T, pin string, version int) (*httptest.Server, Source) {
	t.Helper()

	// ids are assigned in one pass so that the release document and the asset endpoints
	// agree without either being the source of truth for the other.
	ids := map[string]int64{}
	byID := map[int64]string{}

	var id int64 = 100

	names := []string{manifestName}
	for name := range f.files {
		names = append(names, name)
	}

	for _, name := range names {
		ids[name] = id
		byID[id] = name
		id++
	}

	bodies := func(name string) []byte {
		if name == manifestName {
			return []byte(f.manifest(pin, version))
		}

		return f.files[name]
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/repos/veil-net/anchor/releases/tags/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)

		tag := strings.TrimPrefix(r.URL.Path, "/repos/veil-net/anchor/releases/tags/")
		if tag != f.tag {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"Not Found"}`)

			return
		}

		type a struct {
			ID     int64  `json:"id"`
			Name   string `json:"name"`
			Size   int64  `json:"size"`
			State  string `json:"state"`
			Digest string `json:"digest,omitempty"`
		}

		var assets []a

		for _, name := range names {
			state := "uploaded"
			if s, ok := f.states[name]; ok {
				state = s
			}

			sum := sha256.Sum256(bodies(name))

			digest := "sha256:" + hex.EncodeToString(sum[:])
			if f.noDigest {
				digest = ""
			}

			assets = append(assets, a{ID: ids[name], Name: name, Size: int64(len(bodies(name))), State: state, Digest: digest})
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":               42,
			"tag_name":         f.tag,
			"target_commitish": f.commit,
			"assets":           assets,
		})
	})

	mux.HandleFunc("/repos/veil-net/anchor/releases/assets/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)

		var got int64
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/repos/veil-net/anchor/releases/assets/"), "%d", &got)

		name, ok := byID[got]
		if !ok {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		if name == manifestName && f.served != "" {
			_, _ = w.Write([]byte(f.served))

			return
		}

		_, _ = w.Write(bodies(name))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Setenv(insecureEnv, "1")

	return srv, Source{API: srv.URL, Repo: "veil-net/anchor", Tag: "shelf", Token: "t0ken"}
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
	f := newRelease(files)
	_, src := f.serve(t, testPin, 1)

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
	f := newRelease(files)
	_, src := f.serve(t, testPin, 1)

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

	requests, _ := f.seen()

	for _, p := range requests {
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
// credential would pass every other test here against a server that does not check one,
// and fail only against the private repository it exists for.
func TestFetchSendsTheToken(t *testing.T) {
	f := newRelease(pair())
	_, src := f.serve(t, testPin, 1)

	if err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	requests, tokens := f.seen()
	if len(tokens) == 0 {
		t.Fatal("no requests were made")
	}

	for i, got := range tokens {
		if got != "Bearer t0ken" {
			t.Errorf("request %d (%s) carried Authorization %q", i, requests[i], got)
		}
	}
}

func TestFetchRefusesAWrongDigest(t *testing.T) {
	files := pair()
	f := newRelease(files)

	// A manifest describing different bytes from the ones served: the substitution the
	// digest exists to catch.
	f.manifestJSON = f.manifest(testPin, 1)
	f.manifestJSON = strings.Replace(f.manifestJSON,
		hex.EncodeToString(sha256Of(files["anchord-linux-amd64"])),
		strings.Repeat("a", 64), 1)

	_, src := f.serve(t, testPin, 1)

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("want a digest refusal, got %v", err)
	}
}

// A failed fetch must leave nothing behind. The temp-and-rename exists so a half-written
// file cannot be mistaken for a binary, and this is what proves it.
func TestARefusedFetchWritesNothing(t *testing.T) {
	files := pair()
	f := newRelease(files)
	f.manifestJSON = strings.Replace(f.manifest(testPin, 1),
		hex.EncodeToString(sha256Of(files["anchord-linux-amd64"])),
		strings.Repeat("a", 64), 1)

	_, src := f.serve(t, testPin, 1)

	dir := t.TempDir()

	if err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, dir, quiet); err == nil {
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

	f := newRelease(files)
	_, src := f.serve(t, testPin, 1)

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "anchoradmin") {
		t.Fatalf("want an anchoradmin refusal, got %v", err)
	}
}

func TestFetchNamesWhatIsMissing(t *testing.T) {
	f := newRelease(pair())
	_, src := f.serve(t, testPin, 1)

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
	f := newRelease(files)

	// Describe a third binary in the manifest without serving it.
	f.manifestJSON = strings.Replace(f.manifest(testPin, 1), `"binaries":[`,
		`"binaries":[{"name":"anchord-darwin-arm64","program":"anchord","os":"darwin","arch":"arm64","bytes":1,"sha256":"`+
			strings.Repeat("b", 64)+`"},`, 1)

	_, src := f.serve(t, testPin, 1)

	err := Fetch(context.Background(), src, []string{"anchord-darwin-arm64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "not attached to the release") {
		t.Fatalf("want an unattached refusal, got %v", err)
	}
}

func TestFetchRefusesAnUnknownFormatVersion(t *testing.T) {
	f := newRelease(pair())
	_, src := f.serve(t, testPin, 2)

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "format") {
		t.Fatalf("want a format refusal, got %v", err)
	}
}

func TestFetchRefusesAManifestWithNoPin(t *testing.T) {
	f := newRelease(pair())
	_, src := f.serve(t, "", 1)

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
			"id": 1, "tag_name": "shelf", "target_commitish": "abc",
			"assets": []map[string]any{
				{"id": 1, "name": "anchord-linux-amd64", "size": 4096, "state": "uploaded"},
			},
		})
	}))
	t.Cleanup(srv.Close)

	t.Setenv(insecureEnv, "1")

	src := Source{API: srv.URL, Repo: "veil-net/anchor", Tag: "shelf", Token: "t0ken"}

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), manifestName) {
		t.Fatalf("want a missing-manifest refusal, got %v", err)
	}
}

// Half-uploaded assets mean the publish step is still running, or failed part way. Either
// way the release is not what the manifest claims yet.
func TestFetchRefusesAnUnfinishedRelease(t *testing.T) {
	f := newRelease(pair())
	f.states["anchord-linux-amd64"] = "starter"

	_, src := f.serve(t, testPin, 1)

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "not finished") {
		t.Fatalf("want an unfinished-release refusal, got %v", err)
	}
}

func TestFetchWithoutATokenSaysSo(t *testing.T) {
	f := newRelease(pair())
	_, src := f.serve(t, testPin, 1)

	src.Token = ""

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), TokenEnv) {
		t.Fatalf("want an error naming %s, got %v", TokenEnv, err)
	}
}

// A 404 against a private repository is ambiguous between "no such tag" and "this token
// cannot see the repository", so the message has to raise both.
func TestAMissingTagNamesBothCauses(t *testing.T) {
	f := newRelease(pair())
	_, src := f.serve(t, testPin, 1)

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

	t.Setenv(insecureEnv, "1")

	src := Source{API: srv.URL, Repo: "veil-net/anchor", Tag: "shelf", Token: "expired"}

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("want a 401 refusal, got %v", err)
	}
}

func TestFetchRefusesPlainHTTPWithoutTheOverride(t *testing.T) {
	f := newRelease(pair())
	srv, src := f.serve(t, testPin, 1)

	// serve() sets the override; take it away again, which is the real configuration.
	t.Setenv(insecureEnv, "")

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "plain http") {
		t.Fatalf("want a scheme refusal, got %v", err)
	}

	_ = srv
}

// A truncated download is a real binary of nearly the right size, which is the shape
// neither the size gate in `make dist` nor the header check in anchor's own test would
// catch. The byte count is checked before the digest so the message says which it was.
func TestFetchRefusesAShortBody(t *testing.T) {
	files := pair()
	f := newRelease(files)

	f.manifestJSON = f.manifest(testPin, 1)

	// Claim more bytes than are served.
	f.manifestJSON = strings.Replace(f.manifestJSON,
		fmt.Sprintf(`"bytes":%d`, len(files["anchord-linux-amd64"])),
		fmt.Sprintf(`"bytes":%d`, len(files["anchord-linux-amd64"])+1), 1)

	_, src := f.serve(t, testPin, 1)

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("want a short-body refusal, got %v", err)
	}
}

// The realm and the commit are the two lines worth reading on a fetch: they say which
// tree these binaries will talk to, and which anchor commit produced them.
func TestFetchReportsTheRealmAndCommit(t *testing.T) {
	f := newRelease(pair())
	_, src := f.serve(t, testPin, 1)

	var out strings.Builder

	log := func(format string, a ...any) { fmt.Fprintf(&out, format+"\n", a...) }

	if err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), log); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	for _, s := range []string{testPin, f.commit, "veil-net/anchor", "shelf"} {
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
	evil := newRelease(map[string][]byte{"anchord-linux-amd64": []byte("not anchord")})

	f := newRelease(files)
	f.served = evil.manifest(testPin, 1)
	_, src := f.serve(t, testPin, 1)

	err := Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("want a refusal of the substituted manifest, got %v", err)
	}

	bare := newRelease(files)
	bare.noDigest = true
	_, src = bare.serve(t, testPin, 1)

	err = Fetch(context.Background(), src, []string{"anchord-linux-amd64"}, t.TempDir(), quiet)
	if err == nil || !strings.Contains(err.Error(), "vouches") {
		t.Fatalf("want a refusal of a release giving no digest, got %v", err)
	}
}
