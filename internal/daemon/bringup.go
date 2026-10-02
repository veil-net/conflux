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

// Reporter is how BringUp says what it is doing. Nil is silence.
type Reporter interface {
	Step(format string, a ...any)
	Warn(format string, a ...any)
}

// permanentError is a file conflux refuses to start from, which no retry changes.
type permanentError struct {
	path string
	err  error
}

func (e *permanentError) Error() string { return e.path + ": " + e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

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

// BringUp takes a daemon that is up and answering, and leaves it hosting the anchor
// this machine is configured for.
//
// One function, shared verbatim by `conflux up`, `conflux proxy` and every boot, so
// that the three cannot drift into starting subtly different anchors. Everything
// that differs between them is in the config file by the time this runs.
func BringUp(ctx context.Context, d paths.Dirs, ctl *anchorctl.Ctl, r Reporter) (anchorctl.Started, error) {
	if r == nil {
		r = nopReporter{}
	}

	// Against `conflux renew` and the renewal timer, which read and rewrite the same
	// manifest and state this does.
	unlock, err := flock.Acquire(d.LockFile())
	if err != nil {
		return anchorctl.Started{}, err
	}
	defer unlock()

	cfg, err := config.Load(d)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return anchorctl.Started{}, ErrNotConfigured
		}

		return anchorctl.Started{}, err
	}

	if err := cfg.Validate(); err != nil {
		return anchorctl.Started{}, &permanentError{path: d.ConfigFile(), err: err}
	}

	st, err := config.LoadState(d)
	if err != nil {
		return anchorctl.Started{}, err
	}

	// Whatever happens below -- an enrolment, a renewal, a measured clock -- is worth
	// keeping even if the start then fails. The next start re-learns all of it, but
	// status reads it in between.
	defer func() {
		if err := config.SaveState(d, st); err != nil {
			r.Warn("could not write %s: %v", d.StateFile(), err)
		}
	}()

	env, m, err := credential(ctx, d, st, cfg.APIBase(), r)
	if err != nil {
		return anchorctl.Started{}, err
	}

	if err := os.MkdirAll(d.AnchorDir(), 0o700); err != nil {
		return anchorctl.Started{}, fmt.Errorf("create %s: %w", d.AnchorDir(), err)
	}

	started, err := ctl.Start(ctx, env, anchorctl.ModeFromConfig(cfg, d.AnchorDir()))
	if err != nil {
		return anchorctl.Started{}, err
	}

	st.AnchorID = started.ID
	st.IssuedAt, st.NotAfter = m.IssuedAt(), m.NotAfter()
	st.BinSetID = ctl.SetID

	return started, nil
}

// credential returns the manifest to start from, enrolling or renewing as needed.
//
// The order matters. Renewal happens before start rather than after, so `start`
// always receives a chain that is current -- which is why the boot path needs no
// separate `anchorctl renew` call at all.
func credential(
	ctx context.Context, d paths.Dirs, st *config.State, apiBase string, r Reporter,
) (config.Envelope, *enrol.Manifest, error) {
	client := &enrol.Client{BaseURL: apiBase}

	env, err := config.LoadManifest(d)

	switch {
	case err == nil:
		// Have one.
	case errors.Is(err, fs.ErrNotExist):
		r.Step("enrolling")

		env, err = client.Enrol(ctx)
		if err != nil {
			return nil, nil, err
		}

		// Written before anything else touches it, decoding included. Enrolment stores
		// nothing on the server and the response is the only copy that will ever
		// exist, so an enrolment that succeeds and then loses the bytes -- to a crash,
		// or to a document this build cannot read -- costs this machine its identity
		// permanently.
		if err := config.SaveManifest(d, env); err != nil {
			return nil, nil, fmt.Errorf(
				"enrolled, but could not save the credential -- it is now lost and a new one must be drawn: %w", err)
		}

		st.EnrolledAt = time.Now().UTC()
	default:
		return nil, nil, err
	}

	m, err := enrol.Decode(env)
	if err != nil {
		return nil, nil, &permanentError{path: d.ManifestFile(), err: err}
	}

	// Renewed when due, and also when the clock was last measured wrong: that
	// measurement is the only thing that refuses a start below, so it is taken again
	// rather than trusted from however long ago it was taken.
	//
	// Except a credential that names nowhere to renew it, which is asked nothing: it
	// runs to its notAfter, and past that it is said once rather than retried.
	switch {
	case !m.Renews():
		if lapsed := time.Since(m.NotAfter()); lapsed > 0 {
			r.Warn("the credential expired %s ago and names nowhere to renew it: %v\n"+
				"  the anchor will start but no peer will accept it until it is replaced",
				lapsed.Round(time.Minute), enrol.ErrDoesNotRenew)
		}
	case st.AnchorID != "" && (DueAt(m.IssuedAt(), m.NotAfter(), time.Now()) || st.ClockSkew > MaxSkew):
		env = renewBeforeStart(ctx, d, st, client, m, env, r)
	}

	if skew, measured := client.Skew(); measured {
		st.ClockSkew = skew

		if err := enrol.CheckSkew(skew, MaxSkew); err != nil {
			return nil, nil, err
		}
	}

	return env, m, nil
}

// renewBeforeStart replaces the chain, or explains why it could not and carries on.
//
// A failed renewal is never fatal here and never falls back to enrolling. Enrolling
// again draws a different identity, a different AnchorID and a different overlay
// address, and orphans every peer that had the old one -- and it is not needed,
// because a renewal works after expiry: the alpha route asks only for the AnchorID,
// and a guardian's for the bearer the manifest carries. So: try, say what happened,
// and start with what we have.
func renewBeforeStart(
	ctx context.Context,
	d paths.Dirs,
	st *config.State,
	client *enrol.Client,
	m *enrol.Manifest,
	env config.Envelope,
	r Reporter,
) config.Envelope {
	r.Step("renewing the credential")

	got, err := renewStored(ctx, d, st, client, m)
	if err == nil {
		*m = *got.m

		return got.env
	}

	if left := time.Until(m.NotAfter()); left > 0 {
		r.Warn("could not renew: %v\n  the credential is still valid for %s; conflux will keep trying",
			err, left.Round(time.Minute))
	} else {
		r.Warn("could not renew, and the credential expired %s ago: %v\n"+
			"  the anchor will start but no peer will accept it until this succeeds",
			time.Since(m.NotAfter()).Round(time.Minute), err)
	}

	return env
}
