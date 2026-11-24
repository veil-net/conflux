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
	"github.com/veil-net/conflux/internal/wintun"
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
// next attempt's to try again. It returns the bytes it read with the configuration they
// hold, which the start hands to config.Canonical rather than reading the file again.
func loadConfig(d paths.Dirs) (*config.Config, []byte, error) {
	cfg, raw, err := config.LoadBytes(d)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil, ErrNotConfigured
	case err != nil:
		return nil, nil, fileErr(err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, nil, &permanentError{path: d.ConfigFile(), err: err}
	}

	return cfg, raw, nil
}

// fileErr is what reading one of conflux's files failed with, decided the same way for every
// file and every reader: a read that failed is the next attempt's to try again, and anything
// else -- a file that does not parse, or that this build cannot read -- is refused for good,
// since no restart changes a file. err names the file already.
func fileErr(err error) error {
	if read := (*fs.PathError)(nil); errors.As(err, &read) {
		return err
	}

	return &permanentError{err: err}
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
// start is said, and the anchor starts without it, unless a stop cut the observer's start short,
// which ends the start there. A rebuild gives no observe: the observer the cycle started runs
// on, and a renewal made here is installed on it.
//
// dir is the anchor directory the daemon's identity was given (see Supervisor.anchorDir).
// reopened counts the start as an uplink rebuilt, in the same state write as the rest,
// once it has succeeded. driver is what fetching Windows' driver came to (FetchDriver), before
// the lock this takes: one that could not be had is the anchor's start's failure, after the
// observer's start.
func bringUp(
	ctx context.Context, d paths.Dirs, ctl *anchorctl.Ctl, r Reporter, dir string, reopened bool,
	driver error, observe func(config.Envelope) (string, error),
) (started anchorctl.Started, err error) {
	// A stop that came while the driver was fetched ends the start here, rather than after
	// waiting out the lock for a start nothing wants: an observer started under a cancelled
	// context only to warn that it did not, and a state write.
	if err := ctx.Err(); err != nil {
		return anchorctl.Started{}, err
	}

	// Against `conflux renew` and the renewal timer, which read and rewrite the same
	// manifest and state this does.
	unlock, err := flock.Acquire(d.LockFile())
	if err != nil {
		return anchorctl.Started{}, err
	}
	defer unlock()

	// And one that came while this waited for the lock, which Acquire is not told of, ends it
	// as soon as the lock is had, for the same reasons.
	if err := ctx.Err(); err != nil {
		return anchorctl.Started{}, err
	}

	cfg, _, err := loadConfig(d)
	if err != nil {
		return anchorctl.Started{}, err
	}

	// One this build cannot read is refused, never started past: a start writes the state
	// back, and the AnchorID in it is what a lapsed credential renews by.
	st, err := config.LoadState(d)
	if err != nil {
		return anchorctl.Started{}, fileErr(err)
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

	// conflux.json mirrors the grant, and a list emptied by hand asked for nothing, which
	// CheckTaints took as the grant: it gets the grant back, as up writes it, under the lock
	// held here, so the file says again what the machine is in.
	if len(cfg.Taints) == 0 && len(m.Taints()) > 0 {
		cfg.Taints = m.Taints()

		if err := config.Save(d, cfg); err != nil {
			r.Warn("could not write the taints the credential grants back to %s: %v", d.ConfigFile(), err)
		}
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
		case !cfg.Anchor(), ctx.Err() != nil:
			// Observing alone, the observer is all there is. Beside an anchor, an observer's
			// start that a stop cut short ends the start there, warning of nothing: the cycle is
			// ending, and an anchor started without the observer is a start nothing wants.
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

	// Part of the anchor's start, after the observer's: a driver that cannot be had is an anchor
	// that does not come up, which never takes the observer down. Asked of the configuration read
	// under the lock, which an edit since the fetch was decided may have taken out of TUN mode.
	if cfg.Mode == config.ModeTUN && driver != nil {
		return anchorctl.Started{}, driver
	}

	started, err = ctl.Start(ctx, env, anchorctl.ModeFromConfig(cfg, dir))
	if err != nil {
		return anchorctl.Started{}, err
	}

	st.AnchorID = started.ID
	st.IssuedAt, st.NotAfter = m.IssuedAt(), m.NotAfter()

	return started, nil
}

// FetchDriver fetches Windows' driver where cfg runs an interface, and says what came of it:
// nil where it was had or none is needed. Windows needs it beside anchord before an interface
// can exist, downloaded rather than embedded: it is GPLv2, and a driver extracted from a
// program's own resources is the shape of a DLL hijack. It lives in the content-addressed set
// directory: an upgraded conflux extracts a new set with no wintun.dll in it, and a boot, or a
// rebuild, must not need somebody to run `up`. The one decision of when it is fetched: the cli's
// bring, the tail of `up`, `proxy` and `observe`, asks it before it installs the service, an
// ephemeral run before its anchor's start, and the supervisor, at a start and at every rebuild,
// hands bringUp what it came to, for the anchor's start.
//
// The supervisor's is before bringUp takes conflux.lock, never under it: a first download
// takes up to wintun's 90-second timeout, which `conflux renew` and up's save of the
// configuration would wait out, for a fetch that writes nothing the lock guards.
func FetchDriver(ctx context.Context, d paths.Dirs, cfg *config.Config) error {
	if cfg.Mode != config.ModeTUN {
		return nil
	}

	return ensureDriver(ctx, d)
}

// ensureDriver is wintun.Ensure, which tests replace: only Windows has a driver to fetch.
var ensureDriver = wintun.Ensure

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
					"which removes conflux as well, then install conflux again and run conflux up, proxy or observe "+
					"with --taint T, T the network's taint, which conflux status names before the uninstall; without it a "+
					"new taint is minted, for a network of its own",
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
		// One that could not be read is tried again; one with nothing in it is refused for
		// good, naming it, and not enrolled over: no retry fills it.
		return nil, nil, nil, fileErr(err)
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
