package enrol

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// server stands in for the enrolment API. Every test that touches the network
// touches this instead: the real route mints a real identity, and a test suite
// that draws one on every run is a test suite that litters.
func server(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	t.Setenv(insecureEnv, "1")

	s := httptest.NewServer(h)
	t.Cleanup(s.Close)

	return &Client{BaseURL: s.URL, HTTP: s.Client()}, s
}

func TestEnrol(t *testing.T) {
	var calls int

	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		calls++

		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}

		if r.URL.Path != enrolPath {
			t.Errorf("path = %s, want %s", r.URL.Path, enrolPath)
		}

		if ua := r.Header.Get("User-Agent"); !strings.HasPrefix(ua, "conflux/") {
			t.Errorf("User-Agent = %q, want it to name conflux", ua)
		}

		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"credentials":%q}`, base64.StdEncoding.EncodeToString([]byte(alphaDocument)))
	})

	env, err := c.Enrol(t.Context())
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}

	if calls != 1 {
		t.Errorf("made %d calls, want 1", calls)
	}

	if _, err := Decode(env); err != nil {
		t.Errorf("the envelope does not decode: %v", err)
	}
}

// TestEnrolRefusesGarbage: a malformed document must fail at enrolment, while
// there is a user watching, not at the next boot.
func TestEnrolRefusesGarbage(t *testing.T) {
	for name, body := range map[string]string{
		"empty credentials": `{"credentials":""}`,
		"not base64":        `{"credentials":"!!!!"}`,
		"a realm manifest": fmt.Sprintf(`{"credentials":%q}`,
			base64.StdEncoding.EncodeToString([]byte(`{"formatVersion":1,"kind":"realm","key":"aa"}`))),
		"no credentials field": `{}`,
	} {
		c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, body)
		})

		if _, err := c.Enrol(t.Context()); err == nil {
			t.Errorf("Enrol accepted %s", name)
		}
	}
}

func TestEnrolHTTPErrors(t *testing.T) {
	for _, code := range []int{400, 403, 429, 500, 503} {
		c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
			fmt.Fprint(w, `{"message":"nope"}`)
		})

		_, err := c.Enrol(t.Context())
		if err == nil {
			t.Fatalf("Enrol succeeded against a %d", code)
		}

		var he *HTTPError
		if !errors.As(err, &he) {
			t.Fatalf("error for %d is %T, want *HTTPError", code, err)
		}

		if he.Status != code {
			t.Errorf("Status = %d, want %d", he.Status, code)
		}

		wantTemp := code >= 500 || code == 429
		if he.Temporary() != wantTemp {
			t.Errorf("%d: Temporary() = %v, want %v", code, he.Temporary(), wantTemp)
		}
	}
}

// TestBodyIsBounded: a server that answers with a gigabyte must not be able to
// make conflux hold it.
func TestBodyIsBounded(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)

		chunk := strings.Repeat("a", 1<<16)
		for range 64 { // 4 MiB, four times the cap
			fmt.Fprint(w, chunk)
		}
	})

	if _, err := c.Enrol(t.Context()); err == nil {
		t.Fatal("Enrol accepted an oversized body")
	}
}

func TestRenew(t *testing.T) {
	chain := []byte("a renewed credential chain")
	expiry := time.Date(2026, 9, 20, 4, 12, 0, 0, time.UTC)

	c, s := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != renewPath {
			t.Errorf("path = %s, want %s", r.URL.Path, renewPath)
		}

		var in struct {
			AnchorID string `json:"anchorId"`
		}

		if err := jsonDecode(r, &in); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		if in.AnchorID != "anchor1qxy" {
			t.Errorf("anchorId = %q", in.AnchorID)
		}

		fmt.Fprintf(w, `{"chain":%q,"notAfter":%q}`,
			base64.StdEncoding.EncodeToString(chain), expiry.Format(ManifestTime))
	})

	got, err := c.Renew(t.Context(), s.URL+renewPath, "anchor1qxy")
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}

	if string(got.Chain) != string(chain) {
		t.Errorf("Chain = %q, want %q -- it must arrive base64-decoded, because -cred takes raw bytes",
			got.Chain, chain)
	}

	if !got.NotAfter.Equal(expiry) {
		t.Errorf("NotAfter = %v, want %v", got.NotAfter, expiry)
	}
}

// TestRenewRefusesAForeignHost is the check on a field conflux stores and re-reads.
func TestRenewRefusesAForeignHost(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"chain":"YQ==","notAfter":"2026-09-20T04:12:00.000Z"}`)
	})

	_, err := c.Renew(t.Context(), "https://attacker.example/ghosts/alpha/renew", "anchor1qxy")
	if err == nil {
		t.Fatal("Renew sent the request to a host the config does not name")
	}

	if !strings.Contains(err.Error(), "attacker.example") {
		t.Errorf("the error should name the host it refused: %v", err)
	}
}

func TestRenewRefusesBadInput(t *testing.T) {
	c, s := server(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"chain":"YQ==","notAfter":"2026-09-20T04:12:00.000Z"}`)
	})

	for name, id := range map[string]string{
		"an empty AnchorID": "",
		"not an AnchorID":   "definitely-not-one",
	} {
		if _, err := c.Renew(t.Context(), s.URL+renewPath, id); err == nil {
			t.Errorf("Renew accepted %s", name)
		}
	}

	// A chain that is not base64, and a missing expiry, are both the server being
	// wrong -- and both must fail rather than write a broken credential to disk.
	for name, body := range map[string]string{
		"a chain that is not base64": `{"chain":"!!!","notAfter":"2026-09-20T04:12:00.000Z"}`,
		"an empty chain":             `{"chain":"","notAfter":"2026-09-20T04:12:00.000Z"}`,
		"no expiry":                  `{"chain":"YQ=="}`,
		"an unparseable expiry":      `{"chain":"YQ==","notAfter":"soon"}`,
	} {
		bad, bs := server(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) })

		if _, err := bad.Renew(t.Context(), bs.URL+renewPath, "anchor1qxy"); err == nil {
			t.Errorf("Renew accepted %s", name)
		}
	}
}

// TestPlainHTTPIsRefused: the override exists for tests, and its absence must be
// what stops a credential going over the wire in the clear.
func TestPlainHTTPIsRefused(t *testing.T) {
	t.Setenv(insecureEnv, "")

	c := &Client{BaseURL: "http://api.example"}

	if _, err := c.Enrol(t.Context()); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("Enrol over plain http should be refused, got %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	if _, err := c.Enrol(ctx); err == nil {
		t.Fatal("Enrol ignored a cancelled context")
	}
}

func TestSkewIsMeasured(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"credentials":%q}`, base64.StdEncoding.EncodeToString([]byte(alphaDocument)))
	})

	// A clock two hours fast. anchor's handshake rotates hourly and tolerates one
	// epoch, so this is the amount that breaks connections while looking like a
	// realm mismatch.
	c.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }

	if _, err := c.Enrol(t.Context()); err != nil {
		t.Fatalf("Enrol: %v", err)
	}

	if Skew < 90*time.Minute {
		t.Errorf("Skew = %v, want about two hours", Skew)
	}

	if err := CheckSkew(time.Hour); err == nil {
		t.Error("CheckSkew passed a two-hour skew")
	}

	var se *SkewError
	if err := CheckSkew(time.Hour); !errors.As(err, &se) {
		t.Errorf("CheckSkew returned %T, want *SkewError", err)
	}
}

func jsonDecode(r *http.Request, v any) error {
	defer r.Body.Close()

	return decodeJSON(r.Body, v)
}
