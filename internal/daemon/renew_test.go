package daemon

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/paths"
)

const renewTestAnchor = "anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq"

// issuer stands in for the renewal route. Its Date header is the clock conflux
// measures against, offset by skew.
type issuer struct {
	srv   *httptest.Server
	calls atomic.Int32
	skew  time.Duration
	fail  bool
	chain []byte
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	t.Setenv("CONFLUX_ALLOW_INSECURE_API", "1")

	is := &issuer{chain: []byte("a renewed chain")}
	is.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		is.calls.Add(1)
		w.Header().Set("Date", time.Now().Add(-is.skew).UTC().Format(http.TimeFormat))

		if is.fail {
			http.Error(w, `{"message":"down"}`, http.StatusServiceUnavailable)

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]string{
			"chain":    base64.StdEncoding.EncodeToString(is.chain),
			"notAfter": time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	t.Cleanup(is.srv.Close)

	return is
}

// machine is a configured, enrolled machine whose credential was issued at issued and
// expires at expires, renewing against is.
func machine(t *testing.T, is *issuer, issued, expires time.Time) paths.Dirs {
	t.Helper()
	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, APIBaseURL: is.srv.URL}); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveState(d, &config.State{AnchorID: renewTestAnchor}); err != nil {
		t.Fatal(err)
	}

	doc, _ := json.Marshal(map[string]any{
		"formatVersion": 1, "kind": "anchor", "identity": "aa", "genesis": "bb",
		"chain":      base64.StdEncoding.EncodeToString([]byte("the first chain")),
		"issuedAt":   issued.UTC().Format(enrol.ManifestTime),
		"notAfter":   expires.UTC().Format(enrol.ManifestTime),
		"renewalUrl": is.srv.URL + "/ghosts/alpha/renew", "renewalAuth": "anchor-id",
	})

	if err := config.SaveManifest(d, config.Envelope(base64.StdEncoding.EncodeToString(doc))); err != nil {
		t.Fatal(err)
	}

	return d
}

func stored(t *testing.T, d paths.Dirs) *enrol.Manifest {
	t.Helper()

	env, err := config.LoadManifest(d)
	if err != nil {
		t.Fatal(err)
	}

	m, err := enrol.Decode(env)
	if err != nil {
		t.Fatal(err)
	}

	return m
}

// TestRenewNowSplicesAndInstalls: the renewed chain is on disk, with the expiry and
// the moment it arrived, before it is installed; the state mirrors it and records the
// clock.
func TestRenewNowSplicesAndInstalls(t *testing.T) {
	is := newIssuer(t)
	is.skew = 10 * time.Minute

	d := machine(t, is, time.Now().Add(-5*24*time.Hour), time.Now().Add(2*24*time.Hour))
	before := time.Now()

	if err := RenewNow(t.Context(), d, fakeCtl(t), nil); err != nil {
		t.Fatalf("RenewNow: %v", err)
	}

	m := stored(t, d)
	if m.IssuedAt().Before(before.Add(-time.Second)) || m.NotAfter().Before(time.Now().Add(6*24*time.Hour)) {
		t.Errorf("the manifest holds a window of %v to %v, want the renewed one", m.IssuedAt(), m.NotAfter())
	}

	st, err := config.LoadState(d)
	if err != nil {
		t.Fatal(err)
	}

	if !st.NotAfter.Equal(m.NotAfter()) || !st.IssuedAt.Equal(m.IssuedAt()) || st.LastRenewalError != "" {
		t.Errorf("the state (%v to %v, error %q) does not mirror the manifest", st.IssuedAt, st.NotAfter, st.LastRenewalError)
	}

	if st.ClockSkew < 9*time.Minute || st.ClockSkew > 11*time.Minute {
		t.Errorf("ClockSkew = %v, want about ten minutes", st.ClockSkew)
	}

	// What conflux does next depends on the window, and it is the renewed one: not due.
	if DueAt(st.IssuedAt, st.NotAfter, time.Now()) {
		t.Error("a credential renewed a moment ago reads as due again")
	}
}

// TestAFailedRenewalIsRecorded: the error is kept for status, and the manifest is the
// one the anchor is running on.
func TestAFailedRenewalIsRecorded(t *testing.T) {
	is := newIssuer(t)
	is.fail = true

	d := machine(t, is, time.Now().Add(-5*24*time.Hour), time.Now().Add(2*24*time.Hour))
	chain := stored(t, d).NotAfter()

	if err := RenewNow(t.Context(), d, fakeCtl(t), nil); err == nil {
		t.Fatal("RenewNow succeeded against an issuer that is down")
	}

	st, _ := config.LoadState(d)
	if st.LastRenewalError == "" || st.LastRenewalTry.IsZero() {
		t.Errorf("the failure was not recorded: %+v", st)
	}

	if !stored(t, d).NotAfter().Equal(chain) {
		t.Error("a failed renewal changed the stored credential")
	}
}

// TestAnEnrolmentIsKeptBeforeItIsRead: a document this build cannot read is still
// written -- it is the only copy of an identity -- and then refused, permanently.
func TestAnEnrolmentIsKeptBeforeItIsRead(t *testing.T) {
	t.Setenv("CONFLUX_DIR", t.TempDir())
	t.Setenv("CONFLUX_ALLOW_INSECURE_API", "1")

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	future := base64.StdEncoding.EncodeToString([]byte(`{"formatVersion":2,"kind":"anchor"}`))

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"credentials": future})
	}))
	t.Cleanup(api.Close)

	_, _, err := credential(t.Context(), d, &config.State{}, api.URL, nopReporter{})
	if err == nil || !isPermanent(err) {
		t.Fatalf("credential() = %v, want a permanent refusal", err)
	}

	b, err := os.ReadFile(d.ManifestFile())
	if err != nil || string(b) != future+"\n" {
		t.Errorf("the enrolment was not kept: %q, %v", b, err)
	}
}

// TestAStaleClockIsMeasuredAgain: a start whose credential is current makes no call,
// unless the clock was last measured wrong -- then it renews to measure again, so a
// fixed clock is not refused on an old figure, and a wrong one is still refused.
func TestAStaleClockIsMeasuredAgain(t *testing.T) {
	for name, tc := range map[string]struct {
		skew    time.Duration
		refused bool
	}{
		"the clock was fixed": {0, false},
		"it is still wrong":   {2 * time.Hour, true},
	} {
		t.Run(name, func(t *testing.T) {
			is := newIssuer(t)
			is.skew = tc.skew

			d := machine(t, is, time.Now(), time.Now().Add(7*24*time.Hour))
			st := &config.State{AnchorID: renewTestAnchor, ClockSkew: 3 * time.Hour}

			_, _, err := credential(t.Context(), d, st, is.srv.URL, nopReporter{})

			if is.calls.Load() != 1 {
				t.Errorf("made %d calls to the issuer, want the one that measures", is.calls.Load())
			}

			var skew *enrol.SkewError
			if got := errors.As(err, &skew); got != tc.refused {
				t.Errorf("credential() = %v, want refused = %v", err, tc.refused)
			}
		})
	}
}
