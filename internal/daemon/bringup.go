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

type nopReporter struct{}

func (nopReporter) Step(string, ...any) {}
func (nopReporter) Warn(string, ...any) {}

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

	cfg, err := config.Load(d)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return anchorctl.Started{}, ErrNotConfigured
		}

		return anchorctl.Started{}, err
	}

	if err := cfg.Validate(); err != nil {
		return anchorctl.Started{}, fmt.Errorf("%s: %w", d.ConfigFile(), err)
	}

	st, err := config.LoadState(d)
	if err != nil {
		return anchorctl.Started{}, err
	}

	client := &enrol.Client{BaseURL: cfg.APIBase()}

	env, m, err := credential(ctx, d, st, client, r)
	if err != nil {
		return anchorctl.Started{}, err
	}

	if err := os.MkdirAll(d.AnchorDir(), 0o700); err != nil {
		return anchorctl.Started{}, fmt.Errorf("create %s: %w", d.AnchorDir(), err)
	}

	mode := anchorctl.ModeFromConfig(cfg, d.AnchorDir())

	started, err := ctl.Start(ctx, env, mode)
	if err != nil {
		return anchorctl.Started{}, err
	}

	st.AnchorID = started.ID
	st.NotAfter = m.NotAfter()
	st.IssuedAt = m.IssuedAt()
	st.RenewalURL = m.RenewalURL()
	st.BinSetID = ctl.SetID

	if err := config.SaveState(d, st); err != nil {
		// The anchor is up. Failing to record that is worth a warning and not a
		// rollback, because the next start re-learns all of it.
		r.Warn("could not write %s: %v", d.StateFile(), err)
	}

	return started, nil
}

// credential returns the manifest to start from, enrolling or renewing as needed.
//
// The order matters. Renewal happens before start rather than after, so `start`
// always receives a chain that is current -- which is why the boot path needs no
// separate `anchorctl renew` call at all.
func credential(
	ctx context.Context, d paths.Dirs, st *config.State, client *enrol.Client, r Reporter,
) (config.Envelope, *enrol.Manifest, error) {
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

		// Written before anything else touches it. Enrolment stores nothing on the
		// server and the response is the only copy that will ever exist, so an
		// enrolment that succeeds and then loses the bytes to a crash costs this
		// machine its identity permanently.
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
		return nil, nil, err
	}

	if !DueAt(m.IssuedAt(), m.NotAfter(), time.Now()) {
		return env, m, nil
	}

	env, m = renewInPlace(ctx, d, st, client, m, env, r)

	return env, m, nil
}

// renewInPlace replaces the chain, or explains why it could not and carries on.
//
// A failed renewal is never fatal here and never falls back to enrolling. Enrolling
// again draws a different identity, a different AnchorID and a different overlay
// address, and orphans every peer that had the old one -- and it is not even
// necessary, because the renewal route is gated on nothing and works after expiry.
// A machine that has been off for a month renews on its next launch and keeps its
// address. So: try, say what happened, and start with what we have.
func renewInPlace(
	ctx context.Context,
	d paths.Dirs,
	st *config.State,
	client *enrol.Client,
	m *enrol.Manifest,
	env config.Envelope,
	r Reporter,
) (config.Envelope, *enrol.Manifest) {
	anchorID := st.AnchorID
	if anchorID == "" {
		// Nothing has started yet, so there is no id to renew against. The stored
		// credential is whatever enrolment handed over, which is current.
		return env, m
	}

	r.Step("renewing the credential")

	url := m.RenewalURL()
	if url == "" {
		url = st.RenewalURL
	}

	renewal, err := client.Renew(ctx, url, anchorID)
	if err != nil {
		st.LastRenewalError = err.Error()
		st.LastRenewalTry = time.Now().UTC()

		if left := time.Until(m.NotAfter()); left > 0 {
			r.Warn("could not renew: %v\n  the credential is still valid for %s; conflux will keep trying",
				err, left.Round(time.Minute))
		} else {
			r.Warn("could not renew, and the credential expired %s ago: %v\n"+
				"  the anchor will start but no peer will accept it until this succeeds",
				time.Since(m.NotAfter()).Round(time.Minute), err)
		}

		return env, m
	}

	if err := m.SetChain(renewal.Chain, renewal.NotAfter); err != nil {
		r.Warn("could not apply the renewed credential: %v", err)

		return env, m
	}

	next, err := m.Encode()
	if err != nil {
		r.Warn("could not encode the renewed credential: %v", err)

		return env, m
	}

	if err := config.SaveManifest(d, next); err != nil {
		r.Warn("could not save the renewed credential: %v", err)

		return env, m
	}

	st.LastRenewalError = ""
	st.NotAfter = renewal.NotAfter
	st.IssuedAt = time.Now().UTC()

	return next, m
}
