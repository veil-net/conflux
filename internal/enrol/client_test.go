package enrol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// asked is the set every enrolment and renewal below asks for.
var asked = []string{alphaTaint}

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

		var in struct {
			Taints []string `json:"taints"`
		}

		if err := jsonDecode(r, &in); err != nil || len(in.Taints) != 1 || in.Taints[0] != alphaTaint {
			t.Errorf("the request asked for taints %v (%v), want %v", in.Taints, err, asked)
		}

		if ua := r.Header.Get("User-Agent"); !strings.HasPrefix(ua, "conflux/") {
			t.Errorf("User-Agent = %q, want it to name conflux", ua)
		}

		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"credentials":%q}`, base64.StdEncoding.EncodeToString([]byte(alphaDocument)))
	})

	env, err := c.Enrol(t.Context(), asked)
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

// TestEnrolAsksForATaint: the alpha realm's default compartment is every untainted
// device's, so an enrolment asking for none -- or for a name anchor would refuse to
// start under -- is refused before anything is sent.
func TestEnrolAsksForATaint(t *testing.T) {
	c, _ := server(t, func(http.ResponseWriter, *http.Request) {
		t.Error("Enrol made a request it should have refused")
	})

	if _, err := c.Enrol(t.Context(), nil); !errors.Is(err, ErrNoTaints) {
		t.Errorf("Enrol with no taints = %v, want ErrNoTaints", err)
	}

	for _, bad := range [][]string{{"a@b"}, {"has space"}, {""}} {
		if _, err := c.Enrol(t.Context(), bad); err == nil {
			t.Errorf("Enrol asked for %q", bad)
		}
	}
}

// TestEnrolHandsOverWhatArrived: the response is the only copy of an identity, so a
// document this build cannot read is still handed back to be written -- a later
// conflux may read it -- and refused afterwards, by Decode, rather than discarded.
func TestEnrolHandsOverWhatArrived(t *testing.T) {
	realm := base64.StdEncoding.EncodeToString([]byte(`{"formatVersion":1,"kind":"realm","key":"aa"}`))

	c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"credentials":%q}`, realm)
	})

	env, err := c.Enrol(t.Context(), asked)
	if err != nil {
		t.Fatalf("Enrol refused a document before it could be written: %v", err)
	}

	if string(env) != realm {
		t.Errorf("Enrol returned %q, want the credentials exactly as they arrived", env)
	}

	if _, err := Decode(env); err == nil {
		t.Error("Decode accepted a realm manifest")
	}
}

// TestEnrolRefusesGarbage: a response with nothing in it to write is an enrolment
// that did not happen.
func TestEnrolRefusesGarbage(t *testing.T) {
	for name, body := range map[string]string{
		"empty credentials":    `{"credentials":""}`,
		"no credentials field": `{}`,
		"not json":             `credentials`,
	} {
		c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, body)
		})

		if _, err := c.Enrol(t.Context(), asked); err == nil {
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

		_, err := c.Enrol(t.Context(), asked)
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
	}
}

// TestHTTPErrorSaysWhatTheServerSaid: the API's refusals, as the live renewal route
// sends them, read as the message rather than as JSON.
func TestHTTPErrorSaysWhatTheServerSaid(t *testing.T) {
	for body, want := range map[string]string{
		`{"message":"member: id: wrong length: want 58 characters, got 28","error":"Bad Request","statusCode":400}`: "the server answered 400 Bad Request: member: id: wrong length: want 58 characters, got 28",
		`{"message":["anchorId must start with \"anchor\""],"error":"Bad Request","statusCode":400}`:                `the server answered 400 Bad Request: anchorId must start with "anchor"`,
		`upstream timed out`: "the server answered 400 Bad Request: upstream timed out",
		``:                   "the server answered 400 Bad Request",
	} {
		if got := (&HTTPError{Status: 400, Body: body}).Error(); got != want {
			t.Errorf("HTTPError{%q}.Error() = %q, want %q", body, got, want)
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

	if _, err := c.Enrol(t.Context(), asked); err == nil {
		t.Fatal("Enrol accepted an oversized body")
	}
}

func TestRenew(t *testing.T) {
	chain := []byte("a renewed credential chain")
	expiry := time.Date(2026, 9, 20, 4, 12, 0, 0, time.UTC)

	c, s := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != alphaRenewPath {
			t.Errorf("path = %s, want %s", r.URL.Path, alphaRenewPath)
		}

		var in struct {
			AnchorID string   `json:"anchorId"`
			Taints   []string `json:"taints"`
		}

		if err := jsonDecode(r, &in); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		if in.AnchorID != "anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq" {
			t.Errorf("anchorId = %q", in.AnchorID)
		}

		if len(in.Taints) != 1 || in.Taints[0] != alphaTaint {
			t.Errorf("taints = %v, want the granted set restated, %v", in.Taints, asked)
		}

		fmt.Fprintf(w, `{"chain":%q,"notAfter":%q,"bootstrap":[%q,%q]}`,
			base64.StdEncoding.EncodeToString(chain), expiry.Format(ManifestTime), bootNode, bootAPI)
	})

	got, err := c.Renew(t.Context(), s.URL+alphaRenewPath, "anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq", asked)
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

	if len(got.Bootstrap) != 2 || got.Bootstrap[0] != bootNode || got.Bootstrap[1] != bootAPI {
		t.Errorf("Bootstrap = %v, want the issuer's list as it came", got.Bootstrap)
	}
}

// The renewal route's bootstrap list: its nodes as AnchorID@host:port, then every
// instance of the API as host:port.
const (
	bootNode = "anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq@genesis.veilnet.com.au:4700"
	bootAPI  = "api.veilnet.com.au:4700"
)

// TestRenewToleratesABootstrapItCannotUse: a bootstrap list is worth refreshing and not
// worth failing a renewal over, so one conflux cannot use is dropped whole -- the
// manifest keeps its own -- rather than refusing the chain or keeping part of it.
func TestRenewToleratesABootstrapItCannotUse(t *testing.T) {
	for name, list := range map[string]string{
		"absent":                ``,
		"empty":                 `,"bootstrap":[]`,
		"an entry anchor skips": `,"bootstrap":["genesis.veilnet.com.au:4700","not an entry"]`,
	} {
		c, s := server(t, func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, `{"chain":"YQ==","notAfter":"2026-09-20T04:12:00.000Z"%s}`, list)
		})

		got, err := c.Renew(t.Context(), s.URL+alphaRenewPath, "anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq", asked)
		if err != nil {
			t.Errorf("%s: Renew failed over the bootstrap list: %v", name, err)
		}

		if got.Bootstrap != nil {
			t.Errorf("%s: Bootstrap = %v, want nil so the manifest keeps its own", name, got.Bootstrap)
		}
	}
}

// TestRenewRefusesAForeignHost is the check on a field conflux stores and re-reads.
func TestRenewRefusesAForeignHost(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"chain":"YQ==","notAfter":"2026-09-20T04:12:00.000Z"}`)
	})

	_, err := c.Renew(t.Context(), "https://attacker.example/ghosts/alpha/renew", "anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq", asked)
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
		if _, err := c.Renew(t.Context(), s.URL+alphaRenewPath, id, asked); err == nil {
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

		if _, err := bad.Renew(t.Context(), bs.URL+alphaRenewPath, "anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq", asked); err == nil {
			t.Errorf("Renew accepted %s", name)
		}
	}
}

// TestPlainHTTPIsRefused: the override exists for tests, and its absence must be
// what stops a credential going over the wire in the clear.
func TestPlainHTTPIsRefused(t *testing.T) {
	t.Setenv(insecureEnv, "")

	c := &Client{BaseURL: "http://api.example"}

	if _, err := c.Enrol(t.Context(), asked); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("Enrol over plain http should be refused, got %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		// Read first: a server notices a client that went away only once it has the
		// body, which an enrolment now carries.
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	})

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	if _, err := c.Enrol(ctx, asked); err == nil {
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

	if _, err := c.Enrol(t.Context(), asked); err != nil {
		t.Fatalf("Enrol: %v", err)
	}

	skew, measured := c.Skew()
	if !measured || skew < 90*time.Minute {
		t.Errorf("Skew() = %v, %v, want about two hours, measured", skew, measured)
	}

	var se *SkewError
	if err := CheckSkew(skew, time.Hour); !errors.As(err, &se) {
		t.Errorf("CheckSkew passed a two-hour skew, or returned %T rather than *SkewError", err)
	}

	if err := CheckSkew(skew, 3*time.Hour); err != nil {
		t.Errorf("CheckSkew refused a skew inside its limit: %v", err)
	}
}

// TestRenewNeedsAURL: a credential that names nowhere to renew is refused rather
// than sent to a route of conflux's choosing.
func TestRenewNeedsAURL(t *testing.T) {
	c, _ := server(t, func(http.ResponseWriter, *http.Request) {
		t.Error("Renew made a request with no renewal URL to make it to")
	})

	if _, err := c.Renew(t.Context(), "", "anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq", asked); err == nil {
		t.Error("Renew accepted an empty renewal URL")
	}
}

// TestRedirectsStayOnOneHostAndOnHTTPS: Go keeps an Authorization header across a
// same-host redirect, so a downgrade to plain http would hand a renewal bearer to
// the path.
func TestRedirectsStayOnOneHostAndOnHTTPS(t *testing.T) {
	t.Setenv(insecureEnv, "")

	via := []*http.Request{httptest.NewRequest(http.MethodPost, "https://api.example/ghosts/alpha/renew", nil)}

	for target, ok := range map[string]bool{
		"https://api.example/ghosts/alpha/renew2": true,
		"http://api.example/ghosts/alpha/renew":   false,
		"https://elsewhere.example/renew":         false,
	} {
		err := defaultHTTP.CheckRedirect(httptest.NewRequest(http.MethodPost, target, nil), via)
		if (err == nil) != ok {
			t.Errorf("a redirect to %s: err = %v, want allowed = %v", target, err, ok)
		}
	}
}

func jsonDecode(r *http.Request, v any) error {
	defer r.Body.Close()

	return json.NewDecoder(r.Body).Decode(v)
}
