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

// permanentError is a file conflux refuses to start from, which no retry changes.
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

// bringUp takes a daemon that is up and answering, and leaves it running what this machine
// is configured for: the observer, where observe is given, and the anchor.
//
// One function, shared verbatim by `conflux up`, `conflux proxy` and every boot, so
// that the three cannot drift into starting subtly different anchors. Everything
// that differs between them is in the config file by the time this runs.
//
// The credential comes first, enrolled or renewed as needed, because both run under it: the
// observer as the identity it names, and the anchor. observe starts the observer under it and
// returns the AnchorID it observes as. Observing alone, that is all there is, and the ID is
// what the state records for the next renewal; beside an anchor, an observer that does not
// start is said, and the anchor starts without it. A rebuild gives no observe: the observer the
// cycle started runs on, and a renewal made here is installed on it.
//
// dir is the anchor directory the daemon's identity was given (see Supervisor.anchorDir).
// reopened counts the start as an uplink rebuilt, in the same state write as the rest,
// once it has succeeded.
func bringUp(
	ctx context.Context, d paths.Dirs, ctl *anchorctl.Ctl, r Reporter, dir string, reopened bool,
	observe func(config.Envelope) (string, error),
) (started anchorctl.Started, err error) {
	// Against `conflux renew` and the renewal timer, which read and rewrite the same
	// manifest and state this does.
	unlock, err := flock.Acquire(d.LockFile())
	if err != nil {
		return anchorctl.Started{}, err
	}
	defer unlock()

	cfg, err := loadConfig(d)
	if err != nil {
		return anchorctl.Started{}, err
	}

	st, err := config.LoadState(d)
	if err != nil {
		return anchorctl.Started{}, err
	}

	// Whatever happens below -- an enrolment, a renewal, a measured clock -- is worth
	// keeping even if the start then fails. The next start re-learns all of it, but
	// status reads it in between.
	defer func() {
		if reopened && err == nil {
			st.LinkReopens++
			st.LastLinkReopen = time.Now().UTC()
		}

		if err := config.SaveState(d, st); err != nil {
			r.Warn("could not write %s: %v", d.StateFile(), err)
		}
	}()

	env, m, renewed, err := credential(ctx, d, st, cfg, r)
	if err != nil {
		return anchorctl.Started{}, err
	}

	st.BinSetID = ctl.SetID

	switch {
	case observe == nil && renewed != nil && cfg.Observer != nil:
		// The observer holds its credential apart from the anchor's, so a rebuild's renewal is
		// installed on it as the timer's is. Before the anchor starts: none runs yet to take the
		// chain, and the one about to starts on it.
		if err := installRenewal(ctx, ctl, cfg, renewed); err != nil {
			r.Warn("could not install the renewed credential on the observer: %v", err)
		}
	case observe != nil:
		id, err := observe(env)

		switch {
		case err == nil:
			if id != "" {
				st.AnchorID = id
			}

			st.IssuedAt, st.NotAfter = m.IssuedAt(), m.NotAfter()
		case !cfg.Anchor():
			return anchorctl.Started{}, err
		default:
			r.Warn("the observer did not start, and the anchor starts without it: %v", err)
		}
	}

	if !cfg.Anchor() {
		return anchorctl.Started{}, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return anchorctl.Started{}, fmt.Errorf("create %s: %w", dir, err)
	}

	started, err = ctl.Start(ctx, env, anchorctl.ModeFromConfig(cfg, dir))
	if err != nil {
		return anchorctl.Started{}, err
	}

	st.AnchorID = started.ID
	st.IssuedAt, st.NotAfter = m.IssuedAt(), m.NotAfter()

	return started, nil
}

// credential returns the manifest to start from, enrolling or renewing as needed, and the
// chain it renewed to, or nil where it renewed none.
//
// The order matters. Renewal happens before start rather than after, so `start`
// always receives a chain that is current -- which is why the boot path needs no
// separate `anchorctl renew` call at all.
//
// The taints are checked before either: the credential grants them, anchorctl starts
// the anchor under the manifest's, and a machine configured for others -- one enrolled
// before alpha granted taints, a hand-edited conflux.json, an issuer that answered with
// another set -- is refused for good here, naming the way out, before it costs a call.
func credential(
	ctx context.Context, d paths.Dirs, st *config.State, cfg *config.Config, r Reporter,
) (config.Envelope, *enrol.Manifest, []byte, error) {
	client := &enrol.Client{BaseURL: cfg.APIBase()}

	env, err := config.LoadManifest(d)

	switch {
	case err == nil:
		// Have one.
	case errors.Is(err, fs.ErrNotExist):
		// The identity this machine had, gone: the manifest is its only copy, and enrolling
		// again would draw a new AnchorID and a new overlay address, which every peer that
		// knew this one would have to learn. Refused for good rather than replaced; drawing
		// a new identity is a person's decision.
		if st.AnchorID != "" {
			return nil, nil, nil, &permanentError{path: d.ManifestFile(), err: fmt.Errorf(
				"the credential is gone, and %s records the anchor it was, %s; enrolling again would draw "+
					"a new identity and overlay address. Put the manifest back, or start over: conflux uninstall, "+
					"which removes conflux as well, then install conflux again and run conflux up, proxy or observe",
				d.StateFile(), st.AnchorID)}
		}

		// Never the shared compartment. `up` and `proxy` mint a taint for a machine with
		// none, so this is a conflux.json somebody emptied; no retry changes it.
		if len(cfg.Taints) == 0 {
			return nil, nil, nil, &permanentError{path: d.ConfigFile(), err: fmt.Errorf(
				"%w; run conflux up or conflux proxy, which mint one", enrol.ErrNoTaints)}
		}

		r.Step("enrolling")

		env, err = client.Enrol(ctx, cfg.Taints)
		if err != nil {
			return nil, nil, nil, err
		}

		// Written before anything else touches it, decoding included. Enrolment stores
		// nothing on the server and the response is the only copy that will ever
		// exist, so an enrolment that succeeds and then loses the bytes -- to a crash,
		// or to a document this build cannot read -- costs this machine its identity
		// permanently.
		if err := config.SaveManifest(d, env); err != nil {
			return nil, nil, nil, fmt.Errorf(
				"enrolled, but could not save the credential -- it is now lost and a new one must be drawn: %w", err)
		}

		// Nothing this state said about an identity holds for the new one; see NewIdentity.
		st.NewIdentity()
	default:
		return nil, nil, nil, err
	}

	m, err := enrol.Decode(env)
	if err != nil {
		return nil, nil, nil, &permanentError{path: d.ManifestFile(), err: err}
	}

	if err := m.CheckTaints(cfg.Taints); err != nil {
		return nil, nil, nil, &permanentError{path: d.ManifestFile(), err: err}
	}

	// Renewed when due, and also when the clock was last measured wrong: that
	// measurement is the only thing that refuses a start below, so it is taken again
	// rather than trusted from however long ago it was taken.
	//
	// Except a credential that names nowhere to renew it, which is asked nothing: it
	// runs to its notAfter, and past that anchor will not build an anchor on it, so it is
	// refused here for good rather than retried.
	var renewed []byte

	switch {
	case !m.Renews():
		if lapsed := time.Since(m.NotAfter()); lapsed > 0 {
			return nil, nil, nil, &permanentError{path: d.ManifestFile(), err: fmt.Errorf(
				"the credential expired %s ago, and anchor will not start on an expired one: %w; "+
					"it has to be replaced", lapsed.Round(time.Minute), enrol.ErrDoesNotRenew)}
		}
	case st.AnchorID == "" && !m.NotAfter().IsZero() && time.Now().After(m.NotAfter()):
		// A renewal names the anchor by the AnchorID it reported when it started, and anchor
		// will not start one on an expired credential: with none recorded, nothing here can
		// bring this one back, however often it is tried.
		return nil, nil, nil, &permanentError{path: d.ManifestFile(), err: fmt.Errorf(
			"the credential expired %s ago, and no AnchorID is recorded to renew it with -- "+
				"the anchor never started on it, or %s was lost -- so it has to be replaced",
			time.Since(m.NotAfter()).Round(time.Minute), d.StateFile())}
	case st.AnchorID != "" && (dueAt(m.IssuedAt(), m.NotAfter(), time.Now()) || st.ClockSkew > MaxSkew):
		env, renewed = renewBeforeStart(ctx, d, st, client, m, env, r)
	}

	if skew, measured := client.Skew(); measured {
		st.ClockSkew = skew

		if err := enrol.CheckSkew(skew, MaxSkew); err != nil {
			return nil, nil, nil, err
		}
	}

	return env, m, renewed, nil
}

// renewBeforeStart replaces the chain, and returns the renewed envelope and its chain; or
// explains why it could not, and carries on with env and no chain.
//
// A failed renewal is never fatal here and never falls back to enrolling. Enrolling
// again draws a different identity, a different AnchorID and a different overlay
// address, and orphans every peer that had the old one -- and it is not needed,
// because a renewal works after expiry: the alpha route asks only for the AnchorID and
// the taints the manifest names, and a guardian's for the bearer the manifest carries
// as well. So: try, say what happened,
// and start with what we have -- which anchor refuses once it has expired, and the
// restart loop brings this round again.
func renewBeforeStart(
	ctx context.Context,
	d paths.Dirs,
	st *config.State,
	client *enrol.Client,
	m *enrol.Manifest,
	env config.Envelope,
	r Reporter,
) (config.Envelope, []byte) {
	r.Step("renewing the credential")

	got, err := renewStored(ctx, d, st, client, m)
	if err == nil {
		*m = *got.m

		return got.env, got.chain
	}

	if left := time.Until(m.NotAfter()); left > 0 {
		r.Warn("could not renew: %v\n  the credential is still valid for %s; conflux will keep trying",
			err, left.Round(time.Minute))
	} else {
		r.Warn("could not renew, and the credential expired %s ago: %v\n"+
			"  anchor will not start on it, so conflux tries again until this succeeds",
			time.Since(m.NotAfter()).Round(time.Minute), err)
	}

	return env, nil
}
