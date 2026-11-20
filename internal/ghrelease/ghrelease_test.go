package ghrelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestOnlyHTTPSIsAccepted(t *testing.T) {
	t.Setenv(InsecureEnv, "")

	if err := CheckScheme("ftp://example.com", ""); err == nil {
		t.Error("CheckScheme accepted ftp")
	}
}

// TestTheRedirectPolicy holds the one client every release conflux reads goes through,
// update's and anchorrelease's alike, to its rule: the hop from an asset to storage on
// another host is followed, without the token; a redirect to plain http is not, and
// neither is a chain past five requests.
func TestTheRedirectPolicy(t *testing.T) {
	t.Run("to plain http", func(t *testing.T) {
		t.Setenv(InsecureEnv, "")

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

		t.Setenv(InsecureEnv, "1")

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
