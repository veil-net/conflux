package daemon

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths"
)

// ErrNotConfigured means there is nothing to start. The boot service exits 78 on it
// so that systemd stops rather than restarting every five seconds forever.
var ErrNotConfigured = errors.New("this machine has no conflux configuration")

// Reporter is how bringUp says what it is doing.
type Reporter interface {
	Step(format string, a ...any)
	Warn(format string, a ...any)
}

// permanentError is a refusal no retry changes: mostly a file conflux refuses to start from.
type permanentError struct {
	path string
	err  error
}

func (e *permanentError) Error() string {
	if e.path == "" {
		return e.err.Error()
	}

	return e.path + ": " + e.err.Error()
}
func (e *permanentError) Unwrap() error { return e.err }

// loadConfig reads conflux.json for the supervisor, and decides what a failure means, the
// same way for every reader of it: none at all is nothing to start (ErrNotConfigured); one
// that will not parse, that this build cannot read, or that Validate refuses is refused
// for good, since no restart changes a file; and one that could not be read at all is the
// next attempt's to try again.
func loadConfig(d paths.Dirs) (*config.Config, error) {
	cfg, err := config.Load(d)

	var read *fs.PathError

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, ErrNotConfigured
	case errors.As(err, &read):
		return nil, err
	case err != nil:
		return nil, &permanentError{err: err} // names the file already
	}

	if err := cfg.Validate(); err != nil {
		return nil, &permanentError{path: d.ConfigFile(), err: err}
	}

	return cfg, nil
}

type nopReporter struct{}

func (nopReporter) Step(string, ...any) {}
func (nopReporter) Warn(string, ...any) {}

// MaxSkew is how far this machine's clock may be from the enrolment API's before
// conflux stops rather than starting an anchor that cannot connect.
//
// anchor's realm.CredSkew, the tightest of the clock checks anchor makes. A credential
// starts when the issuer signs it, and anchor refuses one that starts more than ten
// minutes ahead of its own clock -- so a machine that far slow cannot start on a
// freshly enrolled or renewed chain, and the refusal names the credential rather than
// the clock. Further out, the hourly ALPN tag makes it a TLS alert indistinguishable
// from a wrong realm. Refused here, either way, naming the clock.
const MaxSkew = 10 * time.Minute

// parts is what a bring-up starts: the observer, the anchor, or both. The watcher starts one
// again while the other runs on.
type parts struct{ observer, anchor bool }

// everything is every part cfg runs.
func everything(cfg *config.Config) parts {
	return parts{observer: cfg.Observer != nil, anchor: cfg.Anchor()}
}

// brought is what a bring-up started.
type brought struct {
	// id is the identity's AnchorID, as what started reported it: the observer's `as` row, or
	// the anchor's start, which name the same identity.
	id string

	// observing and anchor say which started.
	observing, anchor bool
}

// bringUp takes a daemon that is up and answering, and leaves it running what this machine
// is configured for, of what start asks: the credential first, then the observer, then the
// anchor.
//
// One function, shared verbatim by `conflux up`, `conflux proxy`, `conflux observe` and every
// boot, so that they cannot drift into starting subtly different things. Everything that
// differs between them is in the config file by the time this runs.
//
// The observer runs under the machine's own credential, as the anchor does, so a credential
// that cannot be had -- an enrolment the API does not answer -- starts neither. The observer
// before the anchor, because an anchor that then cannot come up must not keep it from
// observing: beside an anchor, an observer that will not start is said, and the anchor starts
// without it; observing alone, it is the error.
//
// dir is the anchor directory the daemon's identity was given (see Supervisor.anchorDir).
// reopened counts the start as an uplink rebuilt, in the same state write as the rest,
// once it has succeeded.
func bringUp(
	ctx context.Context, d paths.Dirs, ctl *anchorctl.Ctl, r Reporter, dir string, reopened bool, start parts,
) (up brought, err error) {
	// Against `conflux renew` and the renewal timer, which read and rewrite the same
	// manifest and state this does.
	unlock, err := flock.Acquire(d.LockFile())
	if err != nil {
		return up, err
	}
	defer unlock()

	cfg, err := loadConfig(d)
	if err != nil {
		return up, err
	}

	// Of what was asked, what this configuration runs: the file may have changed since the
	// caller read it.
	start.observer = start.observer && cfg.Observer != nil
	start.anchor = start.anchor && cfg.Anchor()

	if !start.observer && !start.anchor {
		return up, &permanentError{path: d.ConfigFile(), err: errors.New(
			"it changed under the running service, and no longer runs what was to be started; conflux start starts what it runs")}
	}

	st, err := config.LoadState(d)

	switch {
	case errors.Is(err, config.ErrStateCorrupt):
		return up, &permanentError{err: err} // names the file already
	case err != nil:
		return up, err
	}

	// The window of the chain what runs holds now, and why it still holds it where a renewal
	// on the way could not be installed in it.
	ranFrom, ranUntil := st.IssuedAt, st.NotAfter

	var stale error

	// Whatever happens below -- an enrolment, a renewal, a measured clock, an observer that
	// started beside an anchor that did not -- is worth keeping even if a start then fails.
	// The next start re-learns all of it, but status reads it in between.
	defer func() {
		if reopened && err == nil {
			st.LinkReopens++
			st.LastLinkReopen = time.Now().UTC()
		}

		// Something runs on the old chain, so the state keeps describing it and the renewal
		// stays due, as RenewNow leaves one it could not install.
		if stale != nil {
			st.IssuedAt, st.NotAfter, st.LastRenewalError = ranFrom, ranUntil, stale.Error()
		}

		if err := config.SaveState(d, st); err != nil {
			r.Warn("could not write %s: %v", d.StateFile(), err)
		}
	}()

	h, err := credential(ctx, d, st, cfg, r)
	if err != nil {
		return up, err
	}

	// A renewal on the way replaced the chain that what this bring-up does not start runs on:
	// the watcher's other part, which is handed it in place.
	if h.chain != nil {
		if err := installRenewal(ctx, ctl, cfg, h.chain, start); err != nil {
			stale = fmt.Errorf("install the renewed credential: %w", err)
			r.Warn("%v", stale)
		}
	}

	// What runs holds this credential now, under this identity, from these binaries. Its window
	// is the state's only where this starts everything the configuration runs: a part started
	// beside one that runs on leaves the window that one holds, which a renewal on the way has
	// moved already where it was installed in it, and leaves due where it was not (stale).
	whole := start == everything(cfg)

	running := func(id string) {
		st.AnchorID, st.BinSetID = id, ctl.SetID

		if whole {
			st.IssuedAt, st.NotAfter = h.m.IssuedAt(), h.m.NotAfter()
		}
	}

	if start.observer {
		o, err := startObserver(ctx, ctl, r, cfg, h.env)

		switch {
		case err == nil:
			up.id, up.observing = o.ID, true
			running(o.ID)
		case !start.anchor:
			return up, err
		default:
			r.Warn("the observer did not start, and the anchor starts without it: %v", err)
		}
	}

	if !start.anchor {
		return up, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return up, fmt.Errorf("create %s: %w", dir, err)
	}

	started, err := ctl.Start(ctx, h.env, anchorctl.ModeFromConfig(cfg, dir))
	if err != nil {
		return up, err
	}

	up.id, up.anchor = started.ID, true
	running(started.ID)

	return up, nil
}

// startObserver starts the daemon's observer under the credential env carries, with what cfg
// asks of it, and says where its records go. anchord keeps no observer across a restart, so
// every daemon is asked afresh.
func startObserver(
	ctx context.Context, ctl *anchorctl.Ctl, r Reporter, cfg *config.Config, env config.Envelope,
) (anchorctl.Observed, error) {
	start, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()

	o, err := ctl.ObserveStart(start, env, *cfg.Observer)
	if err != nil {
		return o, fmt.Errorf("starting the observer: %w", err)
	}

	where := "kept in the daemon's inventory"
	if cfg.Exports() {
		where = "each sent to " + cfg.Export.Endpoint + " as it is made"
	}

	r.Step("observing as %s; the records are %s", o.ID, where)

	return o, nil
}

// credential returns the manifest to start from, enrolling or renewing as needed.
//
// The order matters. Renewal happens before start rather than after, so a start -- the
// anchor's or the observer's -- always receives a chain that is current, which is why the
// boot path needs no separate renewal call at all.
//
// The taints are checked before either: the credential grants them, anchorctl starts
// the anchor under the manifest's, and a machine configured for others -- one enrolled
// before alpha granted taints, a hand-edited conflux.json, an issuer that answered with
// another set -- is refused for good here, naming the way out, before it costs a call.
func credential(
	ctx context.Context, d paths.Dirs, st *config.State, cfg *config.Config, r Reporter,
) (held, error) {
	client := &enrol.Client{BaseURL: cfg.APIBase()}

	env, err := config.LoadManifest(d)

	switch {
	case err == nil:
		// Have one.
	case errors.Is(err, fs.ErrNotExist):
		// Never the shared compartment. `up`, `proxy` and `observe` mint a taint for a
		// machine with none, so this is a conflux.json somebody emptied; no retry changes it.
		if len(cfg.Taints) == 0 {
			return held{}, &permanentError{path: d.ConfigFile(), err: fmt.Errorf(
				"%w; run conflux up, proxy or observe, which mint one", enrol.ErrNoTaints)}
		}

		r.Step("enrolling")

		env, err = client.Enrol(ctx, cfg.Taints)
		if err != nil {
			return held{}, err
		}

		// Written before anything else touches it, decoding included. Enrolment stores
		// nothing on the server and the response is the only copy that will ever
		// exist, so an enrolment that succeeds and then loses the bytes -- to a crash,
		// or to a document this build cannot read -- costs this machine its identity
		// permanently.
		if err := config.SaveManifest(d, env); err != nil {
			return held{}, fmt.Errorf(
				"enrolled, but could not save the credential -- it is now lost and a new one must be drawn: %w", err)
		}

		// Nothing this state said about an identity holds for the new one; see NewIdentity.
		st.NewIdentity()
	default:
		return held{}, err
	}

	m, err := enrol.Decode(env)
	if err != nil {
		return held{}, &permanentError{path: d.ManifestFile(), err: err}
	}

	// The raw chain a renewal below replaced, for what runs on the old one.
	var chain []byte

	if err := m.CheckTaints(cfg.Taints); err != nil {
		return held{}, &permanentError{path: d.ManifestFile(), err: err}
	}

	// Renewed when due, and also when the clock was last measured wrong: that
	// measurement is the only thing that refuses a start below, so it is taken again
	// rather than trusted from however long ago it was taken.
	//
	// Except a credential that names nowhere to renew it, which is asked nothing: it
	// runs to its notAfter, and past that anchor will not build an anchor on it, so it is
	// refused here for good rather than retried.
	switch {
	case !m.Renews():
		if lapsed := time.Since(m.NotAfter()); lapsed > 0 {
			return held{}, &permanentError{path: d.ManifestFile(), err: fmt.Errorf(
				"the credential expired %s ago, and anchor will not start on an expired one: %w; "+
					"it has to be replaced", lapsed.Round(time.Minute), enrol.ErrDoesNotRenew)}
		}
	case st.AnchorID == "" && !m.NotAfter().IsZero() && time.Now().After(m.NotAfter()):
		// A renewal names the identity by the AnchorID its anchor or observer reported when it
		// started, and neither starts on an expired credential: with none recorded, nothing
		// here can bring this one back, however often it is tried.
		return held{}, &permanentError{path: d.ManifestFile(), err: fmt.Errorf(
			"the credential expired %s ago, and no AnchorID is recorded to renew it with -- "+
				"neither an anchor nor the observer ever started on it, or %s was lost -- so it has to be replaced",
			time.Since(m.NotAfter()).Round(time.Minute), d.StateFile())}
	case st.AnchorID != "" && (dueAt(m.IssuedAt(), m.NotAfter(), time.Now()) || st.ClockSkew > MaxSkew):
		h := renewBeforeStart(ctx, d, st, client, held{m: m, env: env}, r)
		m, env, chain = h.m, h.env, h.chain
	}

	if skew, measured := client.Skew(); measured {
		st.ClockSkew = skew

		if err := enrol.CheckSkew(skew, MaxSkew); err != nil {
			return held{}, err
		}
	}

	return held{m: m, env: env, chain: chain}, nil
}

// renewBeforeStart replaces the chain, or explains why it could not and carries on with
// what it has.
//
// A failed renewal is never fatal here and never falls back to enrolling. Enrolling
// again draws a different identity, a different AnchorID and a different overlay
// address, and orphans every peer that had the old one -- and it is not needed,
// because a renewal works after expiry: the alpha route asks only for the AnchorID and
// the taints the manifest names, and a guardian's for the bearer the manifest carries
// as well. So: try, say what happened, and start with what we have -- which anchor and
// its observer refuse once it has expired, and the restart loop brings this round again.
func renewBeforeStart(
	ctx context.Context,
	d paths.Dirs,
	st *config.State,
	client *enrol.Client,
	have held,
	r Reporter,
) held {
	r.Step("renewing the credential")

	got, err := renewStored(ctx, d, st, client, have.m)
	if err == nil {
		return got
	}

	m := have.m

	if left := time.Until(m.NotAfter()); left > 0 {
		r.Warn("could not renew: %v\n  the credential is still valid for %s; conflux will keep trying",
			err, left.Round(time.Minute))
	} else {
		r.Warn("could not renew, and the credential expired %s ago: %v\n"+
			"  neither the anchor nor the observer starts on it, so conflux tries again until this succeeds",
			time.Since(m.NotAfter()).Round(time.Minute), err)
	}

	return have
}
