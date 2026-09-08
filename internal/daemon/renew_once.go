package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths"
)

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
// renew`, which is a separate process that has no supervisor and only needs the
// socket of the one already running. Sharing the body is what keeps the manual path
// from growing its own subtly different ordering -- the same reason BringUp is
// shared verbatim between up, proxy and serve.
func RenewNow(ctx context.Context, dirs paths.Dirs, ctl *anchorctl.Ctl, rep Reporter) error {
	// Against the supervisor's own timer, which may be a few seconds from doing
	// exactly this. Two renewals are not harmful -- the second supersedes the
	// first -- but they cost a credential each and can install them out of order,
	// which shows up later as an expiry moving backwards.
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

	url := m.RenewalURL()
	if url == "" {
		url = st.RenewalURL
	}

	client := &enrol.Client{BaseURL: cfg.APIBase()}

	renewal, err := client.Renew(ctx, url, st.AnchorID)
	if err != nil {
		st.LastRenewalError = err.Error()
		st.LastRenewalTry = time.Now().UTC()
		_ = config.SaveState(dirs, st)

		return err
	}

	// Persist first, then install. If the process dies between the two, the next
	// start uses the newer chain -- which is correct. The other order would leave
	// a running anchor holding a credential no file on disk records, and a reboot
	// would silently go back to the old one.
	if err := m.SetChain(renewal.Chain, renewal.NotAfter); err != nil {
		return err
	}

	next, err := m.Encode()
	if err != nil {
		return err
	}

	if err := config.SaveManifest(dirs, next); err != nil {
		return fmt.Errorf("save the renewed credential: %w", err)
	}

	if err := install(ctx, dirs, ctl, renewal.Chain); err != nil {
		return err
	}

	st.NotAfter = renewal.NotAfter
	st.IssuedAt = time.Now().UTC()
	st.LastRenewalError = ""
	st.LastRenewalTry = time.Now().UTC()

	if err := config.SaveState(dirs, st); err != nil {
		rep.Warn("could not record the renewal: %v", err)
	}

	rep.Step("credential renewed, valid until %s (in %s)",
		renewal.NotAfter.Format(time.RFC3339), time.Until(renewal.NotAfter).Round(time.Hour))

	return nil
}

// install writes the chain where anchorctl can read it and hands it over.
//
// The bytes are raw here, not base64: the API sends base64 and the client decoded
// it on the way in, because the file `-cred` reads wants the credential itself.
// Getting that backwards produces a credential the daemon silently refuses.
//
// -inline makes anchorctl read the file and send the contents, so the daemon never
// opens a path a caller named. The file is removed either way.
func install(ctx context.Context, dirs paths.Dirs, ctl *anchorctl.Ctl, chain []byte) error {
	path := filepath.Join(dirs.State, "renewed.cred")

	if err := config.WriteFileAtomic(path, chain, 0o600); err != nil {
		return err
	}

	defer os.Remove(path)

	return ctl.Renew(ctx, path)
}
