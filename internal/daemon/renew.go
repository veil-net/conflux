package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
)

// renewal is one successful exchange with the issuer, already on disk.
type renewal struct {
	m     *enrol.Manifest
	env   config.Envelope
	chain []byte
}

// renewStored asks the manifest's issuer for a fresh chain and writes it into the
// manifest on disk, recording the attempt and the clock in st for the caller to save.
//
// The one body every renewal goes through -- before a start, on the timer, and from
// `conflux renew` -- so none of them grows its own ordering. The caller holds the lock.
func renewStored(
	ctx context.Context, d paths.Dirs, st *config.State, client *enrol.Client, m *enrol.Manifest,
) (renewal, error) {
	st.LastRenewalTry = time.Now().UTC()

	fail := func(err error) (renewal, error) {
		st.LastRenewalError = err.Error()

		return renewal{}, err
	}

	// A scheme this build does not implement is refused rather than downgraded to
	// sending nothing, and names the value; see enrol.Auth.
	auth, err := m.Auth()
	if err != nil {
		return fail(err)
	}

	client.Auth = auth

	got, err := client.Renew(ctx, m.RenewalURL(), st.AnchorID)

	if skew, measured := client.Skew(); measured {
		st.ClockSkew = skew
	}

	if err != nil {
		return fail(err)
	}

	next, err := m.WithChain(got.Chain, got.NotAfter, time.Now())
	if err != nil {
		return fail(err)
	}

	env, err := next.Encode()
	if err != nil {
		return fail(err)
	}

	// On disk before it is installed anywhere. If the process dies between the two,
	// the next start uses the newer chain, which is correct; the other order would
	// leave a running anchor holding a credential no file records, and a reboot would
	// silently go back to the old one.
	if err := config.SaveManifest(d, env); err != nil {
		return fail(fmt.Errorf("save the renewed credential: %w", err))
	}

	st.LastRenewalError = ""
	st.IssuedAt, st.NotAfter = next.IssuedAt(), next.NotAfter()

	return renewal{m: next, env: env, chain: got.Chain}, nil
}

// renewOnce is the timer's renewal. See RenewNow, which is all of it.
func (s *Supervisor) renewOnce(ctx context.Context) error {
	return RenewNow(ctx, s.Dirs, s.ctl, s.report())
}

// RenewNow fetches a fresh chain and installs it on the running anchor.
//
// Hot, via anchorctl renew, which calls SetRealmCred: the identity does not change
// and not one session is lost. A restart would cost every connection the anchor is
// holding, for a swap that needs none of that.
//
// A free function rather than a Supervisor method because two callers want it and
// only one of them is a supervisor: the timer inside `conflux serve`, and `conflux
// renew`, which is a separate process that only needs the socket of the one running.
func RenewNow(ctx context.Context, dirs paths.Dirs, ctl *anchorctl.Ctl, rep Reporter) error {
	// Against the supervisor's own timer and a bring-up, either of which may be doing
	// exactly this. Two renewals cost a credential each and can install them out of
	// order, which shows up later as an expiry moving backwards.
	unlock, err := flock.Acquire(dirs.LockFile())
	if err != nil {
		return err
	}

	defer unlock()

	if rep == nil {
		rep = nopReporter{}
	}

	cfg, err := config.Load(dirs)
	if err != nil {
		return err
	}

	st, err := config.LoadState(dirs)
	if err != nil {
		return err
	}

	if st.AnchorID == "" {
		return errors.New("no AnchorID recorded; the anchor has to have started at least once")
	}

	env, err := config.LoadManifest(dirs)
	if err != nil {
		return err
	}

	m, err := enrol.Decode(env)
	if err != nil {
		return err
	}

	got, err := renewStored(ctx, dirs, st, &enrol.Client{BaseURL: cfg.APIBase()}, m)
	if err == nil {
		err = install(ctx, dirs, ctl, got.chain)
	}

	if serr := config.SaveState(dirs, st); serr != nil {
		rep.Warn("could not record the renewal: %v", serr)
	}

	if err != nil {
		return err
	}

	rep.Step("credential renewed, valid until %s (%s)",
		st.NotAfter.Format(time.RFC3339), ui.Until(st.NotAfter))

	return nil
}

// install hands the renewed chain to the running anchor.
//
// The bytes are raw here, not base64: the API sends base64 and the client decoded
// it on the way in, because the file `-cred` reads wants the credential itself.
// Getting that backwards produces a credential the daemon silently refuses.
//
// Through a file because that is what anchorctl reads, with -inline so that anchorctl
// sends the contents and the daemon never opens a path a caller named. The chain is
// public -- it is worth nothing without the identity -- and the file is gone as soon
// as anchorctl has read it, so it is written plainly rather than atomically.
func install(ctx context.Context, dirs paths.Dirs, ctl *anchorctl.Ctl, chain []byte) error {
	f, err := os.CreateTemp(dirs.State, ".renewed-*.cred")
	if err != nil {
		return err
	}

	defer os.Remove(f.Name())

	if _, err := f.Write(chain); err != nil {
		f.Close()

		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	return ctl.Renew(ctx, f.Name())
}
