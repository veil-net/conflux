package daemon

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
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

	return envelope(manifestDoc([]byte("the first chain"), issued, expires, []string{"t"}, is.srv.URL+"/ghosts/alpha/renew"))
}

// decoded is env as the caller of an ephemeral run hands it over, decoded; nil for none.
func decoded(t *testing.T, env config.Envelope) *enrol.Manifest {
	t.Helper()

	if env == nil {
		return nil
	}

	m, err := enrol.Decode(env)
	if err != nil {
		t.Fatal(err)
	}

	return m
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

	return runEphemeralOf(t, &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, APIBaseURL: is.srv.URL}, env)
}

// runEphemeralOf is runEphemeral for a run of cfg.
func runEphemeralOf(t *testing.T, cfg *config.Config, env config.Envelope) *ephemeralRig {
	t.Helper()
	t.Setenv(fakeAnchordEnv, "serve")
	t.Setenv(fakeAnchordListenEnv, "1")
	t.Setenv(fakeAnchorctlStatusEnv, "running")

	fakeCtl(t) // the stand-in anchorctl's environment

	root := filepath.Join(dirs(t).State, "e")

	r := &ephemeralRig{root: root, ups: make(chan EphemeralUp, 1), finished: make(chan struct{})}

	e := &Ephemeral{
		Dirs:       paths.EphemeralDirs(root),
		Config:     cfg,
		Manifest:   decoded(t, env),
		Envelope:   env,
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

	allowed := map[string]bool{"serve.lock": true, "run": true, "bin": true, "anchord.priv": true}

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

// TestAnEphemeralObserverRunsOnTheRunsCredential: beside an ephemeral anchor the observer runs
// under the run's own credential, which comes first -- here enrolled, into memory alone -- and
// is handed to it on stdin before the anchor starts, as the supervisor's is.
func TestAnEphemeralObserverRunsOnTheRunsCredential(t *testing.T) {
	observed := filepath.Join(t.TempDir(), "observed")
	t.Setenv(fakeAnchorctlObservedEnv, observed)

	log := filepath.Join(t.TempDir(), "anchorctl.log")
	t.Setenv(fakeAnchorctlLogEnv, log)

	api, _, calls := enroller(t, []string{"t"})

	r := runEphemeralOf(t, &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, APIBaseURL: api.URL,
		Proxies: []string{"8080=127.0.0.1:1"}, Observer: &config.Observer{}}, nil)
	r.up(t)

	b, err := os.ReadFile(observed)
	if err != nil {
		t.Fatalf("the observer was handed no credential: %v", err)
	}

	if m, err := enrol.Decode(config.Envelope(bytes.TrimSpace(b))); err != nil || !slices.Equal(m.Taints(), []string{"t"}) {
		t.Errorf("the observer was handed %q (%v), want the run's enrolment", b, err)
	}

	if calls.Load() != 1 {
		t.Errorf("enrolled %d times, want once", calls.Load())
	}

	if cmds := ran(t, log); slices.Index(cmds, "observe") < 0 || slices.Index(cmds, "observe") > slices.Index(cmds, "start") {
		t.Errorf("anchorctl ran %v; want the observer started, then the anchor", cmds)
	}
}

// TestAnEphemeralRunRenewsItsObserverInMemory: beside an ephemeral anchor, a renewed chain
// reaches the observer too, on its stdin, since a renewal of the anchor's does not.
func TestAnEphemeralRunRenewsItsObserverInMemory(t *testing.T) {
	t.Setenv(fakeAnchorctlObserverEnv, "running")

	is := newIssuer(t)
	anchor, observer := renewedInto(t)

	r := runEphemeralOf(t, &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, APIBaseURL: is.srv.URL,
		Proxies: []string{"8080=127.0.0.1:1"}, Observer: &config.Observer{}},
		handed(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour)))
	r.up(t)

	eventually(t, "the renewed chain reaching the anchor and the observer", func() bool {
		return handedTo(anchor, is.chain) && handedTo(observer, is.chain)
	})
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

	env := handed(t, is, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	e := &Ephemeral{
		Dirs:     paths.EphemeralDirs(root),
		Config:   &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, APIBaseURL: is.srv.URL},
		Manifest: decoded(t, env),
		Envelope: env,
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

	err := checkHanded(decoded(t, handed(t, is, time.Now().Add(-40*24*time.Hour), time.Now().Add(-time.Hour))))
	if err == nil || !Permanent(err) || !strings.Contains(err.Error(), "expired") {
		t.Errorf("checkHanded(expired) = %v, want a permanent refusal", err)
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
	env := config.Envelope(os.Getenv(ephemeralRunnerManifest))

	m, err := enrol.Decode(env)
	if err != nil {
		return 1
	}

	e := &Ephemeral{
		Dirs:     paths.EphemeralDirs(root),
		Config:   &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, APIBaseURL: os.Getenv(ephemeralRunnerAPI)},
		Manifest: m,
		Envelope: env,
		tools:    &libexec.Tools{Anchord: os.Args[0], Anchorctl: os.Args[0]},
	}

	if err := e.Run(context.Background()); err != nil {
		return 1
	}

	return 0
}

// TestARunsWayGoesWithItsRoot: the folders an ephemeral run made on the way to its root under a
// CONFLUX_DIR -- the CONFLUX_DIR, and the installation's root, .conflux, by its name -- go with its root,
// as a killed run's root is removed, whole, whatever anybody put in them; but a .conflux an installation
// was made in since stays, with the CONFLUX_DIR that holds it.
func TestARunsWayGoesWithItsRoot(t *testing.T) {
	for name, c := range map[string]struct {
		put  func(made string) string
		kept []string
	}{
		"nothing put in it": {},
		"a file put in the CONFLUX_DIR it made": {put: func(made string) string {
			return filepath.Join(made, "notes")
		}},
		"an installation made in its .conflux": {put: func(made string) string {
			return paths.Default().ConfigFile()
		}, kept: []string{"made", filepath.Join("made", paths.DirName)}},
	} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			made := filepath.Join(base, "made")
			t.Setenv("CONFLUX_DIR", made)

			e := paths.EphemeralDirs(paths.EphemeralCandidates()[0])
			if err := e.EnsureAll(); err != nil {
				t.Fatal(err)
			}

			var put string
			if c.put != nil {
				put = c.put(made)
				if err := os.WriteFile(put, []byte("somebody's"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			unlock, ok, err := flock.TryAcquire(e.ServeLockFile())
			if err != nil || !ok {
				t.Fatalf("could not hold the lock: %v", err)
			}

			if err := RemoveEphemeral(e, unlock, nil); err != nil {
				t.Errorf("RemoveEphemeral: %v", err)
			}

			var left []string

			_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
				if rel, _ := filepath.Rel(base, p); err == nil && d.IsDir() && rel != "." {
					left = append(left, rel)
				}

				return nil
			})

			if !slices.Equal(left, c.kept) {
				t.Errorf("RemoveEphemeral, %s, left %q, want %q", name, left, c.kept)
			}

			if _, err := os.Stat(put); put != "" && (err == nil) != (c.kept != nil) {
				t.Errorf("RemoveEphemeral, %s, left %s %v, want it kept only with the installation (Stat: %v)", name,
					put, err == nil, err)
			}
		})
	}
}

// TestARunStartingAsAnotherEndsKeepsItsRoot: a run's root is emptied while its lock is held and
// then removed, so a run that takes the lock the moment it is let go -- one starting as another
// ends, or as uninstall clears a killed one's root -- is not emptied out from under itself; and
// with none, nothing of the root is left.
func TestARunStartingAsAnotherEndsKeepsItsRoot(t *testing.T) {
	for name, racing := range map[string]bool{"alone": false, "with a run starting": true} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(dirs(t).State, "e")
			e := paths.EphemeralDirs(root)

			if err := e.EnsureAll(); err != nil {
				t.Fatal(err)
			}

			unlock, ok, err := flock.TryAcquire(e.ServeLockFile())
			if err != nil || !ok {
				t.Fatalf("could not hold the lock: %v", err)
			}

			// What the ending run left.
			if err := os.WriteFile(e.TokenFile(), []byte("the old run's"), 0o600); err != nil {
				t.Fatal(err)
			}

			// The next run, which takes the lock as soon as it is let go, and makes its own.
			letGo := func() {
				unlock()

				if !racing {
					return
				}

				next, ok, err := flock.TryAcquire(e.ServeLockFile())
				if err != nil || !ok {
					t.Fatalf("the next run could not take the lock: %v", err)
				}

				t.Cleanup(next)

				if err := e.EnsureAll(); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(e.TokenFile(), []byte("the next run's"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			if err := RemoveEphemeral(e, letGo, nil); err != nil {
				t.Errorf("RemoveEphemeral: %v", err)
			}

			if !racing {
				if _, err := os.Stat(root); !os.IsNotExist(err) {
					t.Errorf("the root is still there: %v", err)
				}

				return
			}

			if b, err := os.ReadFile(e.TokenFile()); err != nil || string(b) != "the next run's" {
				t.Errorf("the next run's token reads %q (%v): its root was emptied under it", b, err)
			}
		})
	}
}
