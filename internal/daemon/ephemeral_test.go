package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
)

// handed is a credential an ephemeral run is handed, issued and expiring when asked, renewing
// against is.
func handed(t *testing.T, is *issuer, issued, expires time.Time) config.Envelope {
	t.Helper()

	b, err := json.Marshal(map[string]any{
		"formatVersion": 1, "kind": "anchor", "identity": "aa", "genesis": "bb",
		"chain":      base64.StdEncoding.EncodeToString([]byte("the first chain")),
		"issuedAt":   issued.UTC().Format(enrol.ManifestTime),
		"notAfter":   expires.UTC().Format(enrol.ManifestTime),
		"taints":     []string{"t"},
		"bootstrap":  []string{"genesis.veilnet.com.au:4700"},
		"renewalUrl": is.srv.URL + "/ghosts/alpha/renew", "renewalAuth": "anchor-id",
	})
	if err != nil {
		t.Fatal(err)
	}

	return config.Envelope(base64.StdEncoding.EncodeToString(b))
}

// ephemeralRig is one ephemeral run against the stand-ins, started in the background.
type ephemeralRig struct {
	root     string
	ups      chan EphemeralUp
	finished chan struct{} // closed once Run has returned, with err its answer
	err      error
	cancel   context.CancelFunc
}

func runEphemeral(t *testing.T, is *issuer, env config.Envelope) *ephemeralRig {
	t.Helper()
	t.Setenv(fakeAnchordEnv, "serve")
	t.Setenv(fakeAnchordListenEnv, "1")
	t.Setenv(fakeAnchorctlStatusEnv, "running")

	fakeCtl(t) // the stand-in anchorctl's environment

	root := filepath.Join(dirs(t).State, "e")

	r := &ephemeralRig{root: root, ups: make(chan EphemeralUp, 1), finished: make(chan struct{})}

	e := &Ephemeral{
		Dirs:       paths.EphemeralDirs(root),
		Config:     &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, APIBaseURL: is.srv.URL},
		Manifest:   env,
		Up:         func(u EphemeralUp) { r.ups <- u },
		tools:      &libexec.Tools{Anchord: os.Args[0], Anchorctl: os.Args[0]},
		watchEvery: 100 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(t.Context())
	r.cancel = cancel

	go func() {
		r.err = e.Run(ctx)
		close(r.finished)
	}()

	t.Cleanup(func() {
		cancel()

		select {
		case <-r.finished:
		case <-time.After(30 * time.Second):
			t.Error("the ephemeral run did not end")
		}
	})

	return r
}

// up waits for the run's anchor, or fails the test with how the run ended.
func (r *ephemeralRig) up(t *testing.T) EphemeralUp {
	t.Helper()

	select {
	case u := <-r.ups:
		return u
	case <-r.finished:
		t.Fatalf("the ephemeral run ended before its anchor was up: %v", r.err)
	case <-time.After(15 * time.Second):
		t.Fatal("the ephemeral run's anchor did not come up")
	}

	return EphemeralUp{}
}

// ended waits for the run to end, and returns why.
func (r *ephemeralRig) ended(t *testing.T) error {
	t.Helper()

	select {
	case <-r.finished:
		return r.err
	case <-time.After(30 * time.Second):
		t.Fatal("the ephemeral run did not end")

		return nil
	}
}

// TestAnEphemeralRunWritesNothingAndLeavesNothing: while it runs, its root holds what a
// running anchord needs reached and nothing of the credential -- no manifest, no
// configuration, no state, no anchor directory, not one file with the chain in it -- and
// anchord, started with a parent-death signal, is still running seconds after it started.
// (Whether a thread that started it and then ended would have fired that signal depends on
// which thread the runtime ran it on -- one ended, the main thread parked -- so this does not
// always catch a start that lets its thread go; startProcess holds it whatever the runtime
// does.) Cancelled, the run stops anchord and the root is gone.
func TestAnEphemeralRunWritesNothingAndLeavesNothing(t *testing.T) {
	is := newIssuer(t)
	r := runEphemeral(t, is, handed(t, is, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour)))

	if u := r.up(t); u.Started.ID != fakeAnchorID {
		t.Errorf("the run reported anchor %q, want %q", u.Started.ID, fakeAnchorID)
	}

	select {
	case <-r.finished:
		t.Fatalf("the run ended a moment after its anchor came up: %v", r.err)
	case <-time.After(2 * time.Second):
	}

	allowed := map[string]bool{"serve.lock": true, "run": true, "anchord.priv": true}

	err := filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == r.root {
			return err
		}

		rel, _ := filepath.Rel(r.root, path)
		if top := strings.Split(rel, string(filepath.Separator))[0]; !allowed[top] {
			t.Errorf("the run wrote %s", path)
		}

		if d.Type().IsRegular() {
			if b, err := os.ReadFile(path); err == nil && bytes.Contains(b, []byte("the first chain")) {
				t.Errorf("%s holds the credential's chain", path)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	r.cancel()

	if err := r.ended(t); err != nil {
		t.Errorf("a cancelled run ended with %v, want nil", err)
	}

	if _, err := os.Stat(r.root); !os.IsNotExist(err) {
		t.Errorf("the root is still there after the run ended: %v", err)
	}
}

// TestAnEphemeralRunEndsWithItsDaemon: anchord ending ends the run, for good -- nothing
// restarts it -- and the root goes with it.
func TestAnEphemeralRunEndsWithItsDaemon(t *testing.T) {
	is := newIssuer(t)
	r := runEphemeral(t, is, handed(t, is, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour)))
	r.up(t)

	b, err := os.ReadFile(paths.EphemeralDirs(r.root).DaemonPIDFile())
	if err != nil {
		t.Fatal(err)
	}

	pid, err := strconv.Atoi(strings.SplitN(string(b), "\n", 2)[0])
	if err != nil {
		t.Fatal(err)
	}

	p, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Kill(); err != nil {
		t.Fatal(err)
	}

	if err := r.ended(t); err == nil || !strings.Contains(err.Error(), "anchord exited") {
		t.Errorf("the run ended with %v, want anchord's exit", err)
	}

	if _, err := os.Stat(r.root); !os.IsNotExist(err) {
		t.Errorf("the root is still there after anchord ended: %v", err)
	}
}

// TestAnEphemeralRunRenewsInMemory: a credential that is due is renewed by the AnchorID the
// started anchor reported, and the chain reaches anchorctl on its stdin -- with nothing
// written anywhere in between.
func TestAnEphemeralRunRenewsInMemory(t *testing.T) {
	is := newIssuer(t)

	sent := filepath.Join(t.TempDir(), "sent")
	t.Setenv(fakeAnchorctlRenewedEnv, sent)

	r := runEphemeral(t, is, handed(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour)))
	r.up(t)

	eventually(t, "the renewed chain reaching anchorctl", func() bool {
		b, err := os.ReadFile(sent)

		return err == nil && bytes.Equal(b, is.chain)
	})

	if got := is.asked(t).AnchorID; got != fakeAnchorID {
		t.Errorf("the renewal named anchor %q, want the started one, %q", got, fakeAnchorID)
	}
}

// TestASecondEphemeralRunIsRefused: one ephemeral run per root, refused before it touches the
// one already running.
func TestASecondEphemeralRunIsRefused(t *testing.T) {
	is := newIssuer(t)

	root := filepath.Join(dirs(t).State, "e")
	if err := paths.EphemeralDirs(root).EnsureAll(); err != nil {
		t.Fatal(err)
	}

	unlock, ok, err := flock.TryAcquire(filepath.Join(root, "serve.lock"))
	if err != nil || !ok {
		t.Fatalf("could not hold the lock: %v", err)
	}
	defer unlock()

	e := &Ephemeral{
		Dirs:     paths.EphemeralDirs(root),
		Config:   &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, APIBaseURL: is.srv.URL},
		Manifest: handed(t, is, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour)),
		tools:    &libexec.Tools{Anchord: os.Args[0], Anchorctl: os.Args[0]},
	}

	err = e.Run(t.Context())
	if err == nil || !strings.Contains(err.Error(), "already running") || !Permanent(err) {
		t.Errorf("a second run = %v, want a permanent refusal saying one is already running", err)
	}

	if _, err := os.Stat(filepath.Join(root, "serve.lock")); err != nil {
		t.Errorf("the refused run removed the running one's root: %v", err)
	}
}

// TestAnExpiredHandedCredentialIsRefused: nothing could renew it before it starts -- a
// renewal names the anchor it reported once started -- so it is refused for good, and
// nothing is started.
func TestAnExpiredHandedCredentialIsRefused(t *testing.T) {
	is := newIssuer(t)

	_, err := handedCredential(handed(t, is, time.Now().Add(-40*24*time.Hour), time.Now().Add(-time.Hour)),
		&config.Config{Taints: []string{"t"}})
	if err == nil || !Permanent(err) || !strings.Contains(err.Error(), "expired") {
		t.Errorf("handedCredential(expired) = %v, want a permanent refusal", err)
	}

	if is.calls.Load() != 0 {
		t.Errorf("the issuer was asked %d times", is.calls.Load())
	}
}

// ephemeralRunnerArg makes the test binary one ephemeral run rooted at the next argument, the
// credential and the API it is handed in the environment, for a test that kills it.
const (
	ephemeralRunnerArg      = "-ephemeral-runner"
	ephemeralRunnerManifest = "CONFLUX_TEST_EPHEMERAL_MANIFEST"
	ephemeralRunnerAPI      = "CONFLUX_TEST_EPHEMERAL_API"
)

func ephemeralRunner(root string) int {
	e := &Ephemeral{
		Dirs:     paths.EphemeralDirs(root),
		Config:   &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, APIBaseURL: os.Getenv(ephemeralRunnerAPI)},
		Manifest: config.Envelope(os.Getenv(ephemeralRunnerManifest)),
		tools:    &libexec.Tools{Anchord: os.Args[0], Anchorctl: os.Args[0]},
	}

	if err := e.Run(context.Background()); err != nil {
		return 1
	}

	return 0
}
