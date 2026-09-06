package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/enrol"
)

// renewOnce fetches a fresh chain and installs it on the running anchor.
//
// Hot, via anchorctl renew, which calls SetRealmCred: the identity does not change
// and not one session is lost. A restart would cost every connection the anchor is
// holding, for a swap that needs none of that.
func (s *Supervisor) renewOnce(ctx context.Context) error {
	cfg, err := config.Load(s.Dirs)
	if err != nil {
		return err
	}

	st, err := config.LoadState(s.Dirs)
	if err != nil {
		return err
	}

	if st.AnchorID == "" {
		return errors.New("no AnchorID recorded; the anchor has to have started at least once")
	}

	env, err := config.LoadManifest(s.Dirs)
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
		_ = config.SaveState(s.Dirs, st)

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

	if err := config.SaveManifest(s.Dirs, next); err != nil {
		return fmt.Errorf("save the renewed credential: %w", err)
	}

	if err := s.install(ctx, renewal.Chain); err != nil {
		return err
	}

	st.NotAfter = renewal.NotAfter
	st.IssuedAt = time.Now().UTC()
	st.LastRenewalError = ""
	st.LastRenewalTry = time.Now().UTC()

	if err := config.SaveState(s.Dirs, st); err != nil {
		s.report().Warn("could not record the renewal: %v", err)
	}

	s.report().Step("credential renewed, valid until %s (in %s)",
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
func (s *Supervisor) install(ctx context.Context, chain []byte) error {
	path := filepath.Join(s.Dirs.State, "renewed.cred")

	if err := config.WriteFileAtomic(path, chain, 0o600); err != nil {
		return err
	}

	defer os.Remove(path)

	return s.ctl.Renew(ctx, path)
}
