package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/veil-net/conflux/internal/wintun"
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

	root := filepath.Join(dirs(t).Root, "e")

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

	// Up, and saying so to the readers that wait for it, in the root that goes with it.
	if !IsReady(paths.EphemeralDirs(r.root)) {
		t.Error("the run is up and has not marked itself ready")
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

// TestAnEphemeralRootGoesWhileItsLockIsHeld: a run's root is cleared while the run still holds
// its lock, so a run that starts the moment the lock is let go is not emptied out from under
// itself: what it made, its own lock among it, is left as it is.
func TestAnEphemeralRootGoesWhileItsLockIsHeld(t *testing.T) {
	is := newIssuer(t)

	var (
		root string
		next func()
	)

	// The next run, starting where the lock has just been let go.
	ephemeralUnlocked = func() {
		d := paths.EphemeralDirs(root)
		if err := d.EnsureAll(); err != nil {
			t.Errorf("the next run could not make its root: %v", err)

			return
		}

		unlock, ok, err := flock.TryAcquire(d.ServeLockFile())
		if err != nil || !ok {
			t.Errorf("the next run could not take the lock: ok %v, %v", ok, err)

			return
		}

		next = unlock

		if err := os.WriteFile(filepath.Join(root, "next"), nil, 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { ephemeralUnlocked = func() {} })

	r := runEphemeral(t, is, handed(t, is, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour)))
	root = r.root

	r.up(t)
	r.cancel()

	if err := r.ended(t); err != nil {
		t.Errorf("a cancelled run ended with %v, want nil", err)
	}

	if next == nil {
		t.Fatal("the next run never started")
	}
	defer next()

	for _, p := range []string{filepath.Join(root, "next"), paths.EphemeralDirs(root).ServeLockFile()} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("the ended run removed the next one's %s: %v", filepath.Base(p), err)
		}
	}
}

// TestAnEphemeralRootTakesTheDriverWithIt: RemoveEphemeralRoot, which a run's end and
// uninstall's removal of a killed run's root both go through, asks once for the Wintun driver
// to go through the root's own library, while that library is still there, and then removes
// the root whatever the driver's answer was, which it hands back to be said.
func TestAnEphemeralRootTakesTheDriverWithIt(t *testing.T) {
	is := newIssuer(t)

	var (
		asked   []string
		library string // the root's wintun.dll, which must still be there when the driver goes
	)

	inUse := errors.New("an adapter is in use")
	deleteDriver = func(d paths.Dirs) error {
		asked = append(asked, d.Root)

		if library != "" {
			if _, err := os.Stat(library); err != nil {
				t.Errorf("the driver was asked to go after the root's library had: %v", err)
			}
		}

		return inUse
	}
	t.Cleanup(func() { deleteDriver = wintun.DeleteDriver })

	// A run's end, once and not twice.
	r := runEphemeral(t, is, handed(t, is, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour)))
	r.up(t)
	r.cancel()

	if err := r.ended(t); err != nil {
		t.Errorf("a cancelled run ended with %v, want nil: a driver kept in use is a warning", err)
	}

	if len(asked) != 1 || asked[0] != r.root {
		t.Errorf("an ended run asked for the driver to go through %q, want once through its root, %s", asked, r.root)
	}

	// uninstall's, for the root a killed TUN run left, its library still in its set.
	d := paths.EphemeralDirs(filepath.Join(t.TempDir(), "killed"))
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	library = filepath.Join(d.Libexec(), "0123456789abcdef", wintun.DLLName)
	if err := os.MkdirAll(filepath.Dir(library), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(library, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}

	unlock, ok, err := flock.TryAcquire(d.ServeLockFile())
	if err != nil || !ok {
		t.Fatalf("the killed run's lock: ok %v, %v", ok, err)
	}

	if err := RemoveEphemeralRoot(d, unlock); !errors.Is(err, inUse) {
		t.Errorf("RemoveEphemeralRoot = %v, want the driver's answer, %v", err, inUse)
	}

	if len(asked) != 2 || asked[1] != d.Root {
		t.Errorf("removing a killed run's root asked for the driver to go through %q, want %s after the run's", asked, d.Root)
	}

	if _, err := os.Stat(d.Root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the killed run's root is still there with the driver kept: %v", err)
	}
}

// TestTheEphemeralTimerWaitsAfterARenewal: as the supervisor's timer does, an ephemeral run's
// waits minSleep at least after a renewal that succeeds, so an issuer answering with a window
// already gone is not asked again at once, and again.
func TestTheEphemeralTimerWaitsAfterARenewal(t *testing.T) {
	is := newIssuer(t)
	is.lapsed = true

	m, err := enrol.Decode(handed(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, APIBaseURL: is.srv.URL}
	s := &Supervisor{ctl: fakeCtl(t), tail: newRing(tailLines)}

	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()

	if err := s.keepEphemeral(ctx, &child{exited: make(chan struct{})}, cfg, m, fakeAnchorID, time.Hour); err != nil {
		t.Errorf("keepEphemeral = %v, want nil once cancelled", err)
	}

	if n := is.calls.Load(); n != 1 {
		t.Errorf("the ephemeral timer renewed %d times in 500ms, want once, then minSleep", n)
	}
}

// TestASecondEphemeralRunIsRefused: one ephemeral run per root, refused before it touches the
// one already running.
func TestASecondEphemeralRunIsRefused(t *testing.T) {
	is := newIssuer(t)

	root := filepath.Join(dirs(t).Root, "e")
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
