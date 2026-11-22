package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/httpsonly"
	"github.com/veil-net/conflux/internal/paths"
)

const renewTestAnchor = "anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq"

// issuer stands in for the renewal route. Its Date header is the clock conflux
// measures against, offset by skew; bootstrap is the list it answers with.
type issuer struct {
	srv       *httptest.Server
	calls     atomic.Int32
	skew      time.Duration
	fail      bool
	chain     []byte
	bootstrap []string

	mu   sync.Mutex
	body string // the last request's
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	t.Setenv(httpsonly.InsecureEnv, "1")

	is := &issuer{chain: []byte("a renewed chain"), bootstrap: []string{"api.veilnet.com.au:4700"}}
	is.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.calls.Add(1)
		w.Header().Set("Date", time.Now().Add(-is.skew).UTC().Format(http.TimeFormat))

		b, _ := io.ReadAll(r.Body)
		is.mu.Lock()
		is.body = string(b)
		is.mu.Unlock()

		if is.fail {
			http.Error(w, `{"message":"down"}`, http.StatusServiceUnavailable)

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"chain":     base64.StdEncoding.EncodeToString(is.chain),
			"notAfter":  time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
			"bootstrap": is.bootstrap,
		})
	}))
	t.Cleanup(is.srv.Close)

	return is
}

// asked is what the last request sent.
func (is *issuer) asked(t *testing.T) (req struct {
	AnchorID string   `json:"anchorId"`
	Taints   []string `json:"taints"`
},
) {
	t.Helper()
	is.mu.Lock()
	defer is.mu.Unlock()

	if err := json.Unmarshal([]byte(is.body), &req); err != nil {
		t.Fatalf("the request body %q: %v", is.body, err)
	}

	return req
}

// configOf is the configuration a test machine was saved with.
func configOf(t *testing.T, d paths.Dirs) *config.Config {
	t.Helper()

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatal(err)
	}

	return cfg
}

// manifestDoc is an anchor's manifest as its issuer writes one: chain, issued and expiring
// when asked, granting taints, renewed by its AnchorID at renewal.
func manifestDoc(chain []byte, issued, expires time.Time, taints []string, renewal string) map[string]any {
	return map[string]any{
		"formatVersion": 1, "kind": "anchor", "identity": "aa", "genesis": "bb",
		"chain":      base64.StdEncoding.EncodeToString(chain),
		"issuedAt":   issued.UTC().Format(enrol.ManifestTime),
		"notAfter":   expires.UTC().Format(enrol.ManifestTime),
		"taints":     taints,
		"bootstrap":  []string{"genesis.veilnet.com.au:4700"},
		"renewalUrl": renewal, "renewalAuth": "anchor-id",
	}
}

// envelope is a manifest document as the issuer hands it over.
func envelope(doc map[string]any) config.Envelope {
	b, _ := json.Marshal(doc) // strings, numbers and lists of them

	return config.Envelope(base64.StdEncoding.EncodeToString(b))
}

// saveDoc stores a manifest document as the machine's credential.
func saveDoc(tb testing.TB, d paths.Dirs, doc map[string]any) {
	tb.Helper()

	if err := config.SaveManifest(d, envelope(doc)); err != nil {
		tb.Fatal(err)
	}
}

// machine is a configured, enrolled machine whose credential was issued at issued and
// expires at expires, renewing against is.
func machine(t *testing.T, is *issuer, issued, expires time.Time) paths.Dirs {
	t.Helper()
	d := dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, APIBaseURL: is.srv.URL}); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveState(d, &config.State{AnchorID: renewTestAnchor}); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveManifest(d, handed(t, is, issued, expires)); err != nil {
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
	if m.IssuedAt().Before(before.Add(-time.Second)) || m.NotAfter().Before(time.Now().Add(29*24*time.Hour)) {
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
	if dueAt(st.IssuedAt, st.NotAfter, time.Now()) {
		t.Error("a credential renewed a moment ago reads as due again")
	}

	// The bootstrap list the issuer answered with is the next start's.
	if got := m.Bootstrap(); !slices.Equal(got, is.bootstrap) {
		t.Errorf("the manifest's bootstrap is %v, want the renewal's %v", got, is.bootstrap)
	}
}

// TestTheRenewedChainArrivesOnStdin: what the issuer answered is handed to anchorctl on
// stdin, byte for byte, and no file of it is left behind: a renewal writes the manifest it
// splices into, and nothing else.
func TestTheRenewedChainArrivesOnStdin(t *testing.T) {
	is := newIssuer(t)
	d := machine(t, is, time.Now().Add(-5*24*time.Hour), time.Now().Add(2*24*time.Hour))

	sent := filepath.Join(t.TempDir(), "sent")
	t.Setenv(fakeAnchorctlRenewedEnv, sent)

	before, err := os.ReadDir(d.State)
	if err != nil {
		t.Fatal(err)
	}

	if err := RenewNow(t.Context(), d, fakeCtl(t), nil); err != nil {
		t.Fatalf("RenewNow: %v", err)
	}

	got, err := os.ReadFile(sent)
	if err != nil {
		t.Fatalf("anchorctl renew was handed nothing: %v", err)
	}

	if !bytes.Equal(got, is.chain) {
		t.Errorf("anchorctl renew was handed %q, want the issuer's chain %q", got, is.chain)
	}

	after, err := os.ReadDir(d.State)
	if err != nil {
		t.Fatal(err)
	}

	// What was there, and the lock every renewal takes: never a file of the chain.
	had := map[string]bool{d.LockFile(): true}
	for _, e := range before {
		had[filepath.Join(d.State, e.Name())] = true
	}

	for _, e := range after {
		if p := filepath.Join(d.State, e.Name()); !had[p] {
			t.Errorf("a renewal left %s behind", p)
		}
	}
}

// TestRenewalRestatesTheGrantedTaints: the issuer keeps no record of an alpha anchor's
// taints and the running anchor refuses a chain granting others, so a renewal asks for
// the ones the manifest names -- never conflux.json's, whatever it says.
func TestRenewalRestatesTheGrantedTaints(t *testing.T) {
	is := newIssuer(t)
	d := machine(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour))

	cfg := configOf(t, d)
	cfg.Taints = []string{"other"}

	if err := config.Save(d, cfg); err != nil {
		t.Fatal(err)
	}

	if err := RenewNow(t.Context(), d, fakeCtl(t), nil); err != nil {
		t.Fatalf("RenewNow: %v", err)
	}

	if got := is.asked(t); got.AnchorID != renewTestAnchor || !slices.Equal(got.Taints, []string{"t"}) {
		t.Errorf("the renewal asked for %+v, want %s in [t]", got, renewTestAnchor)
	}

	if got := stored(t, d).Taints(); !slices.Equal(got, []string{"t"}) {
		t.Errorf("the renewed manifest grants %v, want [t] kept", got)
	}
}

// TestAnAnswerWithNoBootstrapKeepsTheList: a renewal whose answer carries no list conflux
// can use leaves the manifest's own, rather than a machine with nowhere to start from.
func TestAnAnswerWithNoBootstrapKeepsTheList(t *testing.T) {
	is := newIssuer(t)
	is.bootstrap = nil

	d := machine(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour))

	if err := RenewNow(t.Context(), d, fakeCtl(t), nil); err != nil {
		t.Fatalf("RenewNow: %v", err)
	}

	if got := stored(t, d).Bootstrap(); !slices.Equal(got, []string{"genesis.veilnet.com.au:4700"}) {
		t.Errorf("the manifest's bootstrap is %v, want its own kept", got)
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

// TestAFailedInstallIsDueAgain: a renewed chain the running anchor would not take is
// kept on disk for the next start, but the state goes on describing the chain the anchor
// holds -- so the timer asks again rather than sleeping until the renewed one is due,
// and status says what failed.
func TestAFailedInstallIsDueAgain(t *testing.T) {
	is := newIssuer(t)

	d := machine(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour))
	t.Setenv(fakeAnchorctlFailEnv, "renew")

	if err := RenewNow(t.Context(), d, fakeCtl(t), nil); err == nil {
		t.Fatal("RenewNow succeeded with an install the anchor refused")
	}

	if !stored(t, d).NotAfter().After(time.Now().Add(29 * 24 * time.Hour)) {
		t.Error("the renewed chain was not kept for the next start")
	}

	st, _ := config.LoadState(d)
	if !dueAt(st.IssuedAt, st.NotAfter, time.Now()) {
		t.Errorf("the state reads %v to %v, which is not due, so the timer would sleep past the running chain",
			st.IssuedAt, st.NotAfter)
	}

	if !strings.Contains(st.LastRenewalError, "refused") {
		t.Errorf("LastRenewalError = %q, want the install's refusal", st.LastRenewalError)
	}
}

// TestAnEnrolmentIsKeptBeforeItIsRead: a document this build cannot read is still
// written -- it is the only copy of an identity -- and then refused, permanently.
func TestAnEnrolmentIsKeptBeforeItIsRead(t *testing.T) {
	t.Setenv(httpsonly.InsecureEnv, "1")

	d := dirs(t)

	future := base64.StdEncoding.EncodeToString([]byte(`{"formatVersion":2,"kind":"anchor"}`))

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"credentials": future})
	}))
	t.Cleanup(api.Close)

	cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, APIBaseURL: api.URL}

	_, err := credential(t.Context(), d, &config.State{}, cfg, nopReporter{})
	if err == nil || !Permanent(err) {
		t.Fatalf("credential() = %v, want a permanent refusal", err)
	}

	b, err := os.ReadFile(d.ManifestFile())
	if err != nil || string(b) != future+"\n" {
		t.Errorf("the enrolment was not kept: %q, %v", b, err)
	}
}

// enroller stands in for POST /ghosts/alpha, answering with a document that grants
// grants, and recording what it was asked for.
func enroller(t *testing.T, grants []string) (*httptest.Server, *[]string, *atomic.Int32) {
	t.Helper()
	t.Setenv(httpsonly.InsecureEnv, "1")

	var (
		asked []string
		calls atomic.Int32
	)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)

		var in struct {
			Taints []string `json:"taints"`
		}

		_ = json.NewDecoder(r.Body).Decode(&in)
		asked = in.Taints

		doc := manifestDoc([]byte("chain"), time.Now(), time.Now().Add(30*24*time.Hour), grants,
			"http://"+r.Host+"/ghosts/alpha/renew")

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"credentials": string(envelope(doc))})
	}))
	t.Cleanup(api.Close)

	return api, &asked, &calls
}

// TestAnEnrolmentAsksForTheConfiguredTaints: the taints conflux.json names are the
// request, so the credential that comes back commits to them.
func TestAnEnrolmentAsksForTheConfiguredTaints(t *testing.T) {
	d := dirs(t)
	api, asked, _ := enroller(t, []string{"office", "lab"})

	cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"office", "lab"}, APIBaseURL: api.URL}

	h, err := credential(t.Context(), d, &config.State{}, cfg, nopReporter{})
	if err != nil {
		t.Fatalf("credential() = %v", err)
	}

	if !slices.Equal(*asked, cfg.Taints) || !slices.Equal(h.m.Taints(), cfg.Taints) {
		t.Errorf("asked for %v and was granted %v, want %v both", *asked, h.m.Taints(), cfg.Taints)
	}
}

// TestAnEnrolmentWithNoTaintsIsRefused: conflux never asks the alpha realm for its
// shared compartment, so an emptied conflux.json is refused for good, with no call.
func TestAnEnrolmentWithNoTaintsIsRefused(t *testing.T) {
	d := dirs(t)
	api, _, calls := enroller(t, nil)

	cfg := &config.Config{Mode: config.ModeProxy, APIBaseURL: api.URL}

	_, err := credential(t.Context(), d, &config.State{}, cfg, nopReporter{})
	if !Permanent(err) || !errors.Is(err, enrol.ErrNoTaints) {
		t.Errorf("credential() = %v, want a permanent ErrNoTaints", err)
	}

	if calls.Load() != 0 {
		t.Errorf("made %d calls to the API, want none", calls.Load())
	}
}

// TestAnEnrolmentGrantingOtherTaintsIsKeptAndRefused: the response is the only copy of an
// identity, so it is kept even when the issuer granted other taints than were asked for --
// and the machine is refused for good, since no renewal can move it.
func TestAnEnrolmentGrantingOtherTaintsIsKeptAndRefused(t *testing.T) {
	d := dirs(t)
	api, _, _ := enroller(t, []string{"somebody-else"})

	cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, APIBaseURL: api.URL}

	_, err := credential(t.Context(), d, &config.State{}, cfg, nopReporter{})

	var te *enrol.TaintsError
	if !Permanent(err) || !errors.As(err, &te) {
		t.Errorf("credential() = %v, want a permanent TaintsError", err)
	}

	if !config.HasManifest(d) {
		t.Error("the enrolment was not kept")
	}
}

// TestAPreTaintEnrolmentIsRefusedForGood: an alpha credential enrolled before the realm
// granted taints grants none, which anchor will not start under any taint conflux names
// and conflux will not start in the shared compartment. Refused for good, with no call,
// saying what draws a new one -- whatever conflux.json says.
func TestAPreTaintEnrolmentIsRefusedForGood(t *testing.T) {
	for name, configured := range map[string][]string{
		"configured with a taint": {"t"},
		"configured with none":    nil,
	} {
		t.Run(name, func(t *testing.T) {
			is := newIssuer(t)
			d := machine(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour))

			doc := map[string]any{
				"formatVersion": 1, "kind": "anchor", "identity": "aa", "genesis": "bb",
				"chain":      base64.StdEncoding.EncodeToString([]byte("an old chain")),
				"issuedAt":   time.Now().Add(-25 * 24 * time.Hour).UTC().Format(enrol.ManifestTime),
				"notAfter":   time.Now().Add(5 * 24 * time.Hour).UTC().Format(enrol.ManifestTime),
				"taints":     []string{},
				"renewalUrl": is.srv.URL + "/ghosts/alpha/renew", "renewalAuth": "anchor-id",
			}
			saveDoc(t, d, doc)

			cfg := configOf(t, d)
			cfg.Taints = configured

			_, err := credential(t.Context(), d, &config.State{AnchorID: renewTestAnchor}, cfg, nopReporter{})
			if !Permanent(err) || !strings.Contains(err.Error(), "conflux uninstall") {
				t.Errorf("credential() = %v, want a permanent refusal naming the way out", err)
			}

			if is.calls.Load() != 0 {
				t.Errorf("made %d calls to the issuer, want none", is.calls.Load())
			}
		})
	}
}

// TestAnIssuedCredentialMayGrantNone: a guardian's credential granting no taints is its
// own realm's default compartment, and starts as it is.
func TestAnIssuedCredentialMayGrantNone(t *testing.T) {
	is := newIssuer(t)
	d := machine(t, is, time.Now(), time.Now().Add(30*24*time.Hour))

	saveDoc(t, d, map[string]any{
		"formatVersion": 1, "kind": "anchor", "identity": "aa", "genesis": "bb",
		"chain":      base64.StdEncoding.EncodeToString([]byte("a guardian's chain")),
		"issuedAt":   time.Now().UTC().Format(enrol.ManifestTime),
		"notAfter":   time.Now().Add(30 * 24 * time.Hour).UTC().Format(enrol.ManifestTime),
		"taints":     []string{},
		"renewalUrl": is.srv.URL + "/nodes/x/credential", "renewalAuth": "node-secret", "renewalSecret": "x.y",
	})

	cfg := configOf(t, d)
	cfg.Taints = nil

	if _, err := credential(t.Context(), d, &config.State{AnchorID: renewTestAnchor}, cfg, nopReporter{}); err != nil {
		t.Errorf("credential() = %v, want a start in the realm's default compartment", err)
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
		"the clock was fixed":             {0, false},
		"within anchor's allowance":       {5 * time.Minute, false},
		"past a fresh credential's start": {20 * time.Minute, true},
	} {
		t.Run(name, func(t *testing.T) {
			is := newIssuer(t)
			is.skew = tc.skew

			d := machine(t, is, time.Now(), time.Now().Add(30*24*time.Hour))
			st := &config.State{AnchorID: renewTestAnchor, ClockSkew: 30 * time.Minute}

			_, err := credential(t.Context(), d, st, configOf(t, d), nopReporter{})

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

// TestAFixedTermCredentialIsNotRenewed: a manifest naming nowhere to renew it -- a node
// traveller minted for a century -- is asked nothing, at a start or by hand, even with
// its window two thirds gone and a clock last measured wrong. RenewNow says why, and
// records no failure, because nothing failed.
func TestAFixedTermCredentialIsNotRenewed(t *testing.T) {
	is := newIssuer(t)
	d := machine(t, is, time.Now().Add(-5*24*time.Hour), time.Now().Add(2*24*time.Hour))

	saveDoc(t, d, map[string]any{
		"formatVersion": 1, "kind": "anchor", "identity": "aa", "genesis": "bb",
		"chain":    base64.StdEncoding.EncodeToString([]byte("a node's chain")),
		"issuedAt": time.Now().Add(-5 * 24 * time.Hour).UTC().Format(enrol.ManifestTime),
		"notAfter": time.Now().Add(2 * 24 * time.Hour).UTC().Format(enrol.ManifestTime),
		"taints":   []string{"t"},
	})

	st := &config.State{AnchorID: renewTestAnchor, ClockSkew: 30 * time.Minute}
	if _, err := credential(t.Context(), d, st, configOf(t, d), nopReporter{}); err != nil {
		t.Errorf("credential() = %v, want a start from the credential as it is", err)
	}

	if err := RenewNow(t.Context(), d, fakeCtl(t), nil); !errors.Is(err, enrol.ErrDoesNotRenew) {
		t.Errorf("RenewNow = %v, want ErrDoesNotRenew", err)
	}

	if is.calls.Load() != 0 {
		t.Errorf("made %d calls to the issuer, want none", is.calls.Load())
	}

	if st, _ := config.LoadState(d); st.LastRenewalError != "" {
		t.Errorf("recorded a renewal failure for a credential that does not renew: %q", st.LastRenewalError)
	}
}

// TestAnExpiredFixedTermCredentialIsPermanent: anchor will not build an anchor on an
// expired chain, and nothing will renew this one, so a start is refused for good rather
// than retried for ever.
func TestAnExpiredFixedTermCredentialIsPermanent(t *testing.T) {
	is := newIssuer(t)
	d := machine(t, is, time.Now().Add(-40*24*time.Hour), time.Now().Add(-time.Hour))

	saveDoc(t, d, map[string]any{
		"formatVersion": 1, "kind": "anchor", "identity": "aa", "genesis": "bb",
		"chain":    base64.StdEncoding.EncodeToString([]byte("a node's chain")),
		"issuedAt": time.Now().Add(-40 * 24 * time.Hour).UTC().Format(enrol.ManifestTime),
		"notAfter": time.Now().Add(-time.Hour).UTC().Format(enrol.ManifestTime),
		"taints":   []string{"t"},
	})

	_, err := credential(t.Context(), d, &config.State{AnchorID: renewTestAnchor}, configOf(t, d), nopReporter{})
	if !Permanent(err) || !errors.Is(err, enrol.ErrDoesNotRenew) {
		t.Errorf("credential() = %v, want a permanent refusal naming a credential that does not renew", err)
	}

	if is.calls.Load() != 0 {
		t.Errorf("made %d calls to the issuer, want none", is.calls.Load())
	}
}

// TestAnExpiredCredentialWithNoAnchorIDIsPermanent: a renewal names the anchor by the
// AnchorID a start reported, and anchor will not start on an expired chain, so a lapsed
// credential with none recorded -- never started, or its state lost -- cannot come back.
// Refused for good, with no call, rather than retried for ever.
func TestAnExpiredCredentialWithNoAnchorIDIsPermanent(t *testing.T) {
	is := newIssuer(t)
	d := machine(t, is, time.Now().Add(-40*24*time.Hour), time.Now().Add(-time.Hour))

	_, err := credential(t.Context(), d, &config.State{}, configOf(t, d), nopReporter{})
	if !Permanent(err) || !strings.Contains(err.Error(), "no AnchorID") {
		t.Errorf("credential() = %v, want a permanent refusal naming the missing AnchorID", err)
	}

	if is.calls.Load() != 0 {
		t.Errorf("made %d calls to the issuer, want none", is.calls.Load())
	}
}

// renewedInto points the stand-in anchorctl's renew and observe -cred at files of their own,
// and returns them: what the anchor and the observer were handed.
func renewedInto(t *testing.T) (anchor, observer string) {
	t.Helper()

	anchor, observer = filepath.Join(t.TempDir(), "anchor"), filepath.Join(t.TempDir(), "observer")
	t.Setenv(fakeAnchorctlRenewedEnv, anchor)
	t.Setenv(fakeAnchorctlObserverRenewedEnv, observer)

	return anchor, observer
}

// handedTo says whether path holds chain: the stand-in was handed it.
func handedTo(path string, chain []byte) bool {
	b, err := os.ReadFile(path)

	return err == nil && bytes.Equal(b, chain)
}

// TestARenewalReachesWhatRuns: a renewed chain is installed in everything the configuration
// runs, each in place and on stdin -- the anchor by renew, and the observer by observe -cred,
// since a renewal of the anchor's does not reach it -- and a machine that only observes renews
// by the AnchorID its observer reported, and installs in the observer alone.
func TestARenewalReachesWhatRuns(t *testing.T) {
	for name, tc := range map[string]struct {
		mode             config.Mode
		observer         bool
		anchor, observed bool
	}{
		"an anchor":                  {config.ModeProxy, false, true, false},
		"an anchor and the observer": {config.ModeProxy, true, true, true},
		"observing alone":            {config.ModeObserve, true, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(fakeAnchorctlObserverEnv, "running")

			is := newIssuer(t)
			d := machine(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour))

			cfg := configOf(t, d)
			if cfg.Mode = tc.mode; tc.observer {
				cfg.Observer = &config.Observer{}
			}

			if err := config.Save(d, cfg); err != nil {
				t.Fatal(err)
			}

			anchor, observer := renewedInto(t)

			if err := RenewNow(t.Context(), d, fakeCtl(t), nil); err != nil {
				t.Fatalf("RenewNow: %v", err)
			}

			if got := handedTo(anchor, is.chain); got != tc.anchor {
				t.Errorf("the anchor was handed the renewed chain: %v, want %v", got, tc.anchor)
			}

			if got := handedTo(observer, is.chain); got != tc.observed {
				t.Errorf("the observer was handed the renewed chain: %v, want %v", got, tc.observed)
			}

			if got := is.asked(t).AnchorID; got != renewTestAnchor {
				t.Errorf("renewed for %q, want the recorded %q", got, renewTestAnchor)
			}
		})
	}
}

// TestAnObserverThatIsNotRunningHasNothingToRenew: REASON_NOT_OBSERVING is no failed install --
// nothing holds the old chain, and the next start hands the observer the renewed manifest -- so
// the renewal stands, and is not due again.
func TestAnObserverThatIsNotRunningHasNothingToRenew(t *testing.T) {
	is := newIssuer(t)
	d := machine(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour))

	cfg := configOf(t, d)
	cfg.Mode, cfg.Observer = config.ModeObserve, &config.Observer{}

	if err := config.Save(d, cfg); err != nil {
		t.Fatal(err)
	}

	if err := RenewNow(t.Context(), d, fakeCtl(t), nil); err != nil {
		t.Fatalf("RenewNow: %v", err)
	}

	st, err := config.LoadState(d)
	if err != nil {
		t.Fatal(err)
	}

	if dueAt(st.IssuedAt, st.NotAfter, time.Now()) || st.LastRenewalError != "" {
		t.Errorf("the renewal is due again (%v to %v, error %q)", st.IssuedAt, st.NotAfter, st.LastRenewalError)
	}
}

// TestARenewalBeforeAStartReachesWhatAlreadyRuns: the watcher starting one part again renews a
// due credential before it does, and the part that runs on is handed the renewed chain too, or
// it would run on the old one past its expiry while the state said it held the new.
func TestARenewalBeforeAStartReachesWhatAlreadyRuns(t *testing.T) {
	for name, start := range map[string]parts{"the observer started again": {observer: true}, "the anchor rebuilt": {anchor: true}} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(fakeAnchorctlObserverEnv, "running")

			is := newIssuer(t)
			d := machine(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour))

			cfg := configOf(t, d)
			cfg.Observer = &config.Observer{}

			if err := config.Save(d, cfg); err != nil {
				t.Fatal(err)
			}

			anchor, observer := renewedInto(t)

			if _, err := bringUp(t.Context(), d, fakeCtl(t), nopReporter{}, d.RootAnchorDir(), false, start); err != nil {
				t.Fatalf("bringUp: %v", err)
			}

			if is.calls.Load() != 1 {
				t.Fatalf("the issuer was asked %d times, want the one renewal before the start", is.calls.Load())
			}

			runs := observer
			if start.observer {
				runs = anchor
			}

			if !handedTo(runs, is.chain) {
				t.Error("what runs on was not handed the renewed chain")
			}
		})
	}
}

// dueBesideTheObserver is a machine running an anchor and an observer, both started on its
// stored chain, which is due for renewal: the state describes that chain, as their starts left
// it. It returns the chain.
func dueBesideTheObserver(t *testing.T) (paths.Dirs, *enrol.Manifest) {
	t.Helper()

	d := machine(t, newIssuer(t), time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour))

	cfg := configOf(t, d)
	cfg.Observer = &config.Observer{}

	if err := config.Save(d, cfg); err != nil {
		t.Fatal(err)
	}

	old := stored(t, d)
	if err := config.SaveState(d, &config.State{AnchorID: renewTestAnchor, IssuedAt: old.IssuedAt(), NotAfter: old.NotAfter()}); err != nil {
		t.Fatal(err)
	}

	return d, old
}

// TestAPartStartedAgainKeepsTheWindowOfWhatRunsOn: a renewal one part would not take leaves the
// state describing the chain that part still holds, due again; the watcher starting the other
// part on the manifest the renewed chain is in leaves it so, rather than moving the window onto
// the renewed chain, which would have the timer sleep while the part that runs on holds the old
// one past its expiry. Everything started again holds the renewed chain, and the window is the
// manifest's: left on the old chain, the timer would renew again straight after every start.
func TestAPartStartedAgainKeepsTheWindowOfWhatRunsOn(t *testing.T) {
	for name, tc := range map[string]struct {
		refusing string
		start    parts
	}{
		"the observer started again beside an anchor on the old chain": {"renew", parts{observer: true}},
		"the anchor rebuilt beside an observer on the old chain":       {"observe", parts{anchor: true}},
		"everything started again":                                     {"renew", parts{observer: true, anchor: true}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(fakeAnchorctlObserverEnv, "running")

			d, _ := dueBesideTheObserver(t)

			t.Setenv(fakeAnchorctlFailEnv, tc.refusing)

			if err := RenewNow(t.Context(), d, fakeCtl(t), nil); err == nil {
				t.Fatal("RenewNow succeeded with an install one part refused")
			}

			t.Setenv(fakeAnchorctlFailEnv, "")

			held, err := config.LoadState(d)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := bringUp(t.Context(), d, fakeCtl(t), nopReporter{}, d.RootAnchorDir(), false, tc.start); err != nil {
				t.Fatalf("bringUp: %v", err)
			}

			st, err := config.LoadState(d)
			if err != nil {
				t.Fatal(err)
			}

			if tc.start.observer && tc.start.anchor {
				if m := stored(t, d); !st.IssuedAt.Equal(m.IssuedAt()) || !st.NotAfter.Equal(m.NotAfter()) {
					t.Errorf("the state reads %v to %v, want the manifest's window, %v to %v",
						st.IssuedAt, st.NotAfter, m.IssuedAt(), m.NotAfter())
				}

				return
			}

			if !st.IssuedAt.Equal(held.IssuedAt) || !st.NotAfter.Equal(held.NotAfter) || !dueAt(st.IssuedAt, st.NotAfter, time.Now()) {
				t.Errorf("the state reads %v to %v, want the window the part running on holds, %v to %v, still due",
					st.IssuedAt, st.NotAfter, held.IssuedAt, held.NotAfter)
			}
		})
	}
}

// TestARenewalThePartRunningOnRefusesStaysDue: a renewal made on the way to starting one part,
// which the part running on would not take, is kept on disk for the next start, while the state
// goes on describing the chain that part still holds, due again, and says why -- as RenewNow
// leaves one it could not install -- rather than the renewed window, which would have the timer
// sleep while the part running on held the old chain past its expiry.
func TestARenewalThePartRunningOnRefusesStaysDue(t *testing.T) {
	d, old := dueBesideTheObserver(t)

	t.Setenv(fakeAnchorctlFailEnv, "renew")

	if _, err := bringUp(t.Context(), d, fakeCtl(t), nopReporter{}, d.RootAnchorDir(), false, parts{observer: true}); err != nil {
		t.Fatalf("bringUp: %v", err)
	}

	if !stored(t, d).NotAfter().After(old.NotAfter()) {
		t.Error("the renewed chain was not kept for the next start")
	}

	st, err := config.LoadState(d)
	if err != nil {
		t.Fatal(err)
	}

	if !st.IssuedAt.Equal(old.IssuedAt()) || !st.NotAfter.Equal(old.NotAfter()) || !dueAt(st.IssuedAt, st.NotAfter, time.Now()) {
		t.Errorf("the state reads %v to %v, want the window the anchor holds, %v to %v, still due",
			st.IssuedAt, st.NotAfter, old.IssuedAt(), old.NotAfter())
	}

	if !strings.Contains(st.LastRenewalError, "refused") {
		t.Errorf("LastRenewalError = %q, want the anchor's refusal", st.LastRenewalError)
	}
}

// TestARenewalWhileTheAnchorIsNotRunningIsNotDueAgain: REASON_NOT_RUNNING is no failed install
// either -- the renewed chain is saved, and the watcher's rebuild starts the anchor from it -- so
// the renewal stands, recorded, rather than staying due and drawing a fresh credential from the
// issuer every minute the anchor is down; and an observer running beside it is handed the chain.
func TestARenewalWhileTheAnchorIsNotRunningIsNotDueAgain(t *testing.T) {
	for name, observer := range map[string]bool{"an anchor": false, "an anchor and the observer": true} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(fakeAnchorctlStatusEnv, "none")
			t.Setenv(fakeAnchorctlObserverEnv, "running")

			is := newIssuer(t)
			d := machine(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour))

			if observer {
				cfg := configOf(t, d)
				cfg.Observer = &config.Observer{}

				if err := config.Save(d, cfg); err != nil {
					t.Fatal(err)
				}
			}

			_, observed := renewedInto(t)

			if err := RenewNow(t.Context(), d, fakeCtl(t), nil); err != nil {
				t.Fatalf("RenewNow: %v", err)
			}

			st, err := config.LoadState(d)
			if err != nil {
				t.Fatal(err)
			}

			if m := stored(t, d); !st.NotAfter.Equal(m.NotAfter()) || dueAt(st.IssuedAt, st.NotAfter, time.Now()) || st.LastRenewalError != "" {
				t.Errorf("the state (%v to %v, error %q) does not record the renewal saved, to %v",
					st.IssuedAt, st.NotAfter, st.LastRenewalError, m.NotAfter())
			}

			if got := handedTo(observed, is.chain); got != observer {
				t.Errorf("the observer was handed the renewed chain: %v, want %v", got, observer)
			}
		})
	}
}

// TestTheTimerRenewsWhatRuns: the renewal timer renews a credential that is due, hands the
// chain to what runs, and goes on keeping it current.
func TestTheTimerRenewsWhatRuns(t *testing.T) {
	is := newIssuer(t)
	d := machine(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour))
	anchor, _ := renewedInto(t)

	s := &Supervisor{Dirs: d, ctl: fakeCtl(t)}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})

	go func() {
		s.renewLoop(ctx)
		close(done)
	}()

	eventually(t, "the timer's renewal reaching the anchor", func() bool { return handedTo(anchor, is.chain) })

	select {
	case <-done:
		t.Error("the timer stopped once it had renewed")
	default:
	}

	cancel()
	returns(t, "the timer, cancelled", func() { <-done })

	if n := is.calls.Load(); n != 1 {
		t.Errorf("the issuer was asked %d times, want the one renewal that was due", n)
	}
}

// TestTheTimerStopsOnACredentialThatDoesNotRenew: a credential that names nowhere to renew it
// ends the timer, which asking every minute could not change, and asks the issuer nothing.
func TestTheTimerStopsOnACredentialThatDoesNotRenew(t *testing.T) {
	is := newIssuer(t)
	d := machine(t, is, time.Now().Add(-5*24*time.Hour), time.Now().Add(2*24*time.Hour))

	saveDoc(t, d, map[string]any{
		"formatVersion": 1, "kind": "anchor", "identity": "aa", "genesis": "bb",
		"chain":    base64.StdEncoding.EncodeToString([]byte("a node's chain")),
		"issuedAt": time.Now().Add(-5 * 24 * time.Hour).UTC().Format(enrol.ManifestTime),
		"notAfter": time.Now().Add(2 * 24 * time.Hour).UTC().Format(enrol.ManifestTime),
		"taints":   []string{"t"},
	})

	s := &Supervisor{Dirs: d, ctl: fakeCtl(t)}

	returns(t, "the timer, on a credential that does not renew", func() { s.renewLoop(t.Context()) })

	if n := is.calls.Load(); n != 0 {
		t.Errorf("the issuer was asked %d times, want none", n)
	}
}

// TestTheTimerWaitsQuietlyForAnAnchorID: a renewal names the identity by the AnchorID what
// runs reported, so before anything has -- a credential imported under a running service --
// there is nothing to renew yet, and the timer says nothing about it, rather than "renewal
// failed" every minute.
func TestTheTimerWaitsQuietlyForAnAnchorID(t *testing.T) {
	is := newIssuer(t)
	d := machine(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour))

	if err := config.SaveState(d, &config.State{}); err != nil {
		t.Fatal(err)
	}

	r := &recorder{}
	s := &Supervisor{Dirs: d, Reporter: r, ctl: fakeCtl(t)}

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	s.renewLoop(ctx)

	if _, warns := r.said(); len(warns) > 0 {
		t.Errorf("the timer warned %q with nothing to renew yet", warns)
	}

	if n := is.calls.Load(); n != 0 {
		t.Errorf("the issuer was asked %d times, want none", n)
	}
}

// TestAWaitForTheStateLockEndsWithItsContext: every writer of the manifest and the state -- a bring-up, a
// renewal, the record of an anchor the supervisor gave up on -- waits for the state's lock while another
// holds it, and stops waiting, with its context's error, once that context ends: the supervisor's as the
// service stops, the watcher's and the renewal timer's as their cycle ends, and renew's, enrol's and
// down's on Ctrl+C.
func TestAWaitForTheStateLockEndsWithItsContext(t *testing.T) {
	d := dirs(t)
	ctl := fakeCtl(t)

	unlock, err := flock.AcquireContext(t.Context(), d.LockFile(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	for name, write := range map[string]func(context.Context) error{
		"a bring-up": func(ctx context.Context) error {
			_, err := bringUp(ctx, d, ctl, nopReporter{}, d.RootAnchorDir(), false, parts{anchor: true})

			return err
		},
		"a renewal":               func(ctx context.Context) error { return RenewNow(ctx, d, ctl, nil) },
		"the record of a refusal": func(ctx context.Context) error { return ForgetRefusal(ctx, d) },
	} {
		ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)

		returned := make(chan error, 1)
		go func() { returned <- write(ctx) }()

		select {
		case err := <-returned:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("%s, waiting for the state's lock, ended %v, want its context's deadline", name, err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("%s, waiting for the state's lock, had not stopped 10s after its context ended", name)
		}

		cancel()
	}
}
