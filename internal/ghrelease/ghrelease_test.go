package ghrelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/veil-net/conflux/internal/httpsonly"
)

// TestTheRedirectPolicy holds the one client every release conflux reads goes through,
// update's and anchorrelease's alike, to its rule: the hop from an asset to storage on
// another host is followed, without the token; a redirect to plain http is not, and
// neither is a chain past five requests.
func TestTheRedirectPolicy(t *testing.T) {
	t.Run("to plain http", func(t *testing.T) {
		t.Setenv(httpsonly.InsecureEnv, "")

		req := httptest.NewRequest(http.MethodGet, "http://objects.example.com/conflux", nil)
		if err := client.CheckRedirect(req, make([]*http.Request, 1)); err == nil {
			t.Error("a redirect to plain http was followed")
		}
	})

	t.Run("past five requests", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://objects.example.com/conflux", nil)

		if err := client.CheckRedirect(req, make([]*http.Request, 4)); err != nil {
			t.Errorf("the fifth request of a chain was refused: %v", err)
		}

		if err := client.CheckRedirect(req, make([]*http.Request, 5)); err == nil {
			t.Error("a sixth request was followed")
		}
	})

	t.Run("to another host, without the token", func(t *testing.T) {
		body := []byte("a binary, from storage")
		sum := sha256.Sum256(body)

		var (
			mu               sync.Mutex
			toAPI, toStorage []string
		)

		// One server answers for both hosts, so the redirect really crosses from one name
		// to another, which is what decides whether net/http forwards the header.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()

			switch r.Host {
			case "api.example":
				toAPI = append(toAPI, r.Header.Get("Authorization"))
				http.Redirect(w, r, "http://storage.example/blob?signed=1", http.StatusFound)
			case "storage.example":
				toStorage = append(toStorage, r.Header.Get("Authorization"))
				_, _ = w.Write(body)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		t.Cleanup(srv.Close)

		was := client.Transport
		t.Cleanup(func() { client.Transport = was })

		client.Transport = &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		}}

		t.Setenv(httpsonly.InsecureEnv, "1")

		src := Source{
			API:    "http://api.example",
			Repo:   "veil-net/anchor",
			Header: http.Header{"Authorization": {"Bearer t0ken"}},
			Status: func(*http.Response) error { return nil },
		}

		a := Asset{ID: 7, Bytes: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}
		if _, err := src.Download(context.Background(), a, t.TempDir(), "asset-*", false); err != nil {
			t.Fatalf("Download through the redirect: %v", err)
		}

		mu.Lock()
		defer mu.Unlock()

		if len(toAPI) != 1 || toAPI[0] != "Bearer t0ken" {
			t.Errorf("the API was sent Authorization %q, want the token once", toAPI)
		}

		if len(toStorage) != 1 || toStorage[0] != "" {
			t.Errorf("storage was sent Authorization %q, want none, once", toStorage)
		}
	})
}

// TestWhatTheDocumentVouchesFor: an asset is finished in state "uploaded" or in none, and
// its SHA-256 is GitHub's "sha256:" digest of the right length, read in lower case; any
// other digest gives none.
func TestWhatTheDocumentVouchesFor(t *testing.T) {
	hexSum := strings.Repeat("ab", sha256.Size)

	for state, want := range map[string]bool{"": true, "uploaded": true, "starter": false, "open": false} {
		if got := (Listing{State: state}).Uploaded(); got != want {
			t.Errorf("state %q: Uploaded() = %v, want %v", state, got, want)
		}
	}

	for digest, want := range map[string]string{
		"sha256:" + hexSum:                  hexSum,
		"sha256:" + strings.ToUpper(hexSum): hexSum,
		"":                                  "",
		hexSum:                              "",
		"sha512:" + hexSum:                  "",
		"sha256:" + hexSum[:len(hexSum)-1]:  "",
		"sha256:" + hexSum + "ab":           "",
	} {
		got, ok := (Listing{Digest: digest}).SHA256()
		if got != want || ok != (want != "") {
			t.Errorf("digest %q: SHA256() = %q, %v, want %q", digest, got, ok, want)
		}
	}
}

// TestMatchesHoldsAFileToTheAsset: a file is the asset only with its size, where known, and
// its SHA-256, in either case; a missing file is an error, not a mismatch.
func TestMatchesHoldsAFileToTheAsset(t *testing.T) {
	body := []byte("a binary")
	sum := sha256.Sum256(body)
	hexSum := hex.EncodeToString(sum[:])

	path := filepath.Join(t.TempDir(), "asset")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		a    Asset
		want bool
	}{
		{"the asset", Asset{Bytes: int64(len(body)), SHA256: hexSum}, true},
		{"its size unknown", Asset{SHA256: hexSum}, true},
		{"its digest in upper case", Asset{Bytes: int64(len(body)), SHA256: strings.ToUpper(hexSum)}, true},
		{"another size", Asset{Bytes: int64(len(body)) + 1, SHA256: hexSum}, false},
		{"another digest", Asset{Bytes: int64(len(body)), SHA256: strings.Repeat("0", len(hexSum))}, false},
	} {
		if got, err := c.a.Matches(path); err != nil || got != c.want {
			t.Errorf("%s: Matches = %v, %v, want %v", c.name, got, err, c.want)
		}
	}

	if _, err := (Asset{SHA256: hexSum}).Matches(path + ".gone"); err == nil {
		t.Error("Matches on a missing file gave no error")
	}
}
