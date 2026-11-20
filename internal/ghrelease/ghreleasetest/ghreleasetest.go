// Package ghreleasetest serves a GitHub release the way GitHub's API serves one, for the
// tests of the packages that read one through ghrelease, and only for tests.
package ghreleasetest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/veil-net/conflux/internal/httpsonly"
)

// Release is one release of one repository: a release document listing its assets by id,
// with each one's size, state and digest, and an asset endpoint per id that answers with
// the bytes.
//
// Modelled on the real API rather than on what a caller happens to need, because the gap
// between those two is where a client that passes its tests and fails against GitHub
// lives.
type Release struct {
	// Repo and Tag are where it is served, /repos/<Repo>/releases/tags/<Tag>; any other
	// tag is a 404. An empty Tag is "latest".
	Repo string
	Tag  string

	// Name and Commit are the document's title and its target_commitish.
	Name   string
	Commit string

	// Files are the assets, by name.
	Files map[string][]byte

	// States overrides an asset's state, "uploaded" otherwise: a release still uploading.
	States map[string]string

	// NoDigest leaves the digests out of the release document.
	NoDigest bool

	// Served, by asset name, is what the asset endpoint answers in place of the file the
	// release document lists and digests: bytes substituted past the API.
	Served map[string][]byte

	// Status, when set, is what the release document answers instead, with Header.
	Status int
	Header map[string]string

	// Auth is the Authorization header every request must carry; empty is none.
	Auth string

	// Hold, when set, is called with an asset's name before the endpoint answers for it, so
	// a test can put the answers in an order.
	Hold func(name string)

	// mu guards what the server records: a caller may fetch every asset at once, so the
	// handlers run side by side.
	mu       sync.Mutex
	requests []string
}

// Serve stands the release up and returns its API's URL, plain http, with
// httpsonly.InsecureEnv set for the test so that a client accepts it.
func (f *Release) Serve(t *testing.T) string {
	t.Helper()

	tag := f.Tag
	if tag == "" {
		tag = "latest"
	}

	// Ids by name, the same in the document and at the asset endpoint.
	names := slices.Sorted(maps.Keys(f.Files))
	prefix := "/repos/" + f.Repo + "/releases/"

	mux := http.NewServeMux()

	mux.HandleFunc(prefix+"tags/", func(w http.ResponseWriter, r *http.Request) {
		f.record(t, r)

		if f.Status != 0 {
			for k, v := range f.Header {
				w.Header().Set(k, v)
			}

			w.WriteHeader(f.Status)

			return
		}

		if strings.TrimPrefix(r.URL.Path, prefix+"tags/") != tag {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"Not Found"}`)

			return
		}

		type asset struct {
			ID     int    `json:"id"`
			Name   string `json:"name"`
			Size   int    `json:"size"`
			State  string `json:"state"`
			Digest string `json:"digest,omitempty"`
		}

		assets := []asset{}

		for i, name := range names {
			body := f.Files[name]

			state := "uploaded"
			if s, ok := f.States[name]; ok {
				state = s
			}

			var digest string

			if !f.NoDigest {
				sum := sha256.Sum256(body)
				digest = "sha256:" + hex.EncodeToString(sum[:])
			}

			assets = append(assets, asset{ID: i + 1, Name: name, Size: len(body), State: state, Digest: digest})
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":               42,
			"name":             f.Name,
			"tag_name":         tag,
			"target_commitish": f.Commit,
			"assets":           assets,
		})
	})

	mux.HandleFunc(prefix+"assets/", func(w http.ResponseWriter, r *http.Request) {
		f.record(t, r)

		var id int
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, prefix+"assets/"), "%d", &id)

		if id < 1 || id > len(names) {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		name := names[id-1]

		if f.Hold != nil {
			f.Hold(name)
		}

		body, ok := f.Served[name]
		if !ok {
			body = f.Files[name]
		}

		_, _ = w.Write(body)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Setenv(httpsonly.InsecureEnv, "1")

	return srv.URL
}

// record notes a request, from whichever handler goroutine served it, and holds it to Auth.
func (f *Release) record(t *testing.T, r *http.Request) {
	if got := r.Header.Get("Authorization"); got != f.Auth {
		t.Errorf("%s carried Authorization %q, want %q", r.URL.Path, got, f.Auth)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.requests = append(f.requests, r.URL.Path)
}

// Seen is every path the server was asked for, in the order the requests arrived.
func (f *Release) Seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.requests)
}
