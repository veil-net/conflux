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
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/wintun"
)

// An ephemeral run is one anchor, in the foreground, from a credential held only in memory.
//
//	conflux up --ephemeral                    the terminal, or whatever started it
//	  └── anchord -socket …                   no -config; ends with conflux (Linux: a
//	                                          parent-death signal; Windows: its job)
//
// It is the Supervisor's opposite at every point the Supervisor exists for. Nothing is read
// from the machine's configuration and nothing is written to it: the enrolment response, or
// the manifest handed in, goes from this process's memory to anchorctl's stdin and from
// there inline to anchord, and is never a file. anchord gets no -dir, so the anchor keeps
// nothing either. When anchord ends, however it ends, the run ends: it is not restarted,
// the anchor is not rebuilt, and the root the run kept its socket and binaries in is
// removed. The one thing it shares with the Supervisor is the plumbing of a process: the
// spawn, the wait for readiness, the shutdown, the account anchord is handed to -- its own,
// conflux-ephemeral, which the installed supervisor never touches.

// Ephemeral runs one anchor until the context is cancelled or anchord ends.
type Ephemeral struct {
	// Dirs is the run's root (paths.Ephemeral), made and removed by Run.
	Dirs paths.Dirs

	// Config is what to run, built for this run and never saved.
	Config *config.Config

	// Manifest is a credential handed in, or nil to enrol in memory with Config's taints.
	Manifest config.Envelope

	Reporter Reporter

	// Drop hands anchord to the ephemeral account where conflux runs as root and the mode
	// and the host allow it, as the Supervisor hands it to the installation's.
	Drop bool

	// Up is told once the anchor is up.
	Up func(EphemeralUp)

	// tools and watchEvery are the tests': stand-ins for the extracted pair, and a watcher
	// that looks sooner than every 30 seconds.
	tools      *libexec.Tools
	watchEvery time.Duration
}

// EphemeralUp is what an ephemeral run started, and what its anchor said of itself once it
// had: the status, where the daemon answered for it.
type EphemeralUp struct {
	Started   anchorctl.Started
	Status    anchorctl.Status
	Manifest  *enrol.Manifest
	Privilege Privilege
}

// Run starts anchord, brings the anchor up, keeps its credential current in memory, and
// returns when the context is cancelled (nil) or anchord or its anchor ends (why). Either
// way it stops anchord and removes the run's root before returning.
func (e *Ephemeral) Run(ctx context.Context) error {
	// First, before anything holding the credential can crash: a core dump would put the
	// identity seed on disk, which is the one thing this mode promises never happens.
	noCoreDumps()

	d := e.Dirs

	if err := d.EnsureAll(); err != nil {
		return err
	}

	unlock, ok, err := flock.TryAcquire(d.ServeLockFile())
	if err != nil {
		return err
	}

	if !ok {
		return &permanentError{err: fmt.Errorf("an ephemeral anchor is already running from %s; stop it first", d.State)}
	}

	// The root and the lock in it go last, after anchord has gone, so a second run is refused
	// until there is nothing left of this one.
	defer func() {
		unlock()

		if err := os.RemoveAll(d.State); err != nil {
			e.report().Warn("could not remove %s: %v", d.State, err)
		}
	}()

	if err := d.CheckSocketLen(); err != nil {
		return &permanentError{err: err}
	}

	s := &Supervisor{Dirs: d, Reporter: e.Reporter, Drop: e.Drop, ephemeral: true}

	// What a run killed before it could clean up left behind: its anchord, where nothing
	// ended it with that run (macOS and the BSDs), and the rest of its root.
	switch pid, err := ReapOrphan(d); {
	case err != nil:
		e.report().Warn("%v", err)
	case pid != 0:
		e.report().Warn("stopped anchord (pid %d), left running by an ephemeral run that ended without stopping it", pid)
	}

	s.killLeftovers()

	// And the directories made again, emptied of whatever it was.
	if err := clearExcept(d.State, d.ServeLockFile()); err != nil {
		return err
	}

	if err := d.EnsureAll(); err != nil {
		return err
	}

	// A credential handed in is checked before anything starts, and its port read: the port
	// decides what anchord is given.
	env, m := e.Manifest, (*enrol.Manifest)(nil)
	if env != nil {
		if m, err = handedCredential(env, e.Config); err != nil {
			return err
		}
	}

	tools := e.tools
	if tools == nil {
		if tools, err = libexec.Ensure(d); err != nil {
			return err
		}
	}

	s.tools = tools
	s.tail = newRing(tailLines)

	token, err := s.freshToken()
	if err != nil {
		return err
	}

	s.ctl = &anchorctl.Ctl{Bin: tools.Anchorctl, Socket: d.Socket(), Token: token, SetID: tools.SetID}

	port := 0
	if m != nil {
		port = m.ListenPort()
	}

	p := s.privilegeFor(e.Config, port)

	if err := s.freshDaemonRun(p); err != nil {
		return fmt.Errorf("prepare %s: %w", d.DaemonRun(), err)
	}

	c, err := s.exec(p, ephemeralArgs(d, e.Config), e.Config.Observer != nil)
	if err != nil {
		return err
	}

	defer s.shutdown(c)

	if err := s.waitReady(ctx, c); err != nil {
		return err
	}

	if e.Config.Observer != nil {
		if err := s.startObserver(ctx, e.Config); err != nil {
			return err
		}
	}

	if x := e.Config.Export; x != nil && x.Enabled {
		if err := s.ctl.Export(ctx, x.Endpoint, x.Insecure, exportSignals(x)); err != nil {
			return fmt.Errorf("pointing the export at %s: %w", x.Endpoint, err)
		}
	}

	if !e.Config.Anchor() {
		return errors.New("an ephemeral run is an anchor: up or proxy")
	}

	if env == nil {
		if env, m, err = enrolInMemory(ctx, e.Config, e.report()); err != nil {
			return err
		}
	}

	// Windows needs the driver beside anchord before an interface can exist.
	if e.Config.Mode == config.ModeTUN {
		if err := wintun.Ensure(ctx, d); err != nil {
			return err
		}
	}

	started, err := s.ctl.Start(ctx, env, anchorctl.ModeFromConfig(e.Config, ""))
	if err != nil {
		return err
	}

	// Only now may another conflux reach the run, by status or pass-through: before it, the
	// root may still hold what a killed run left, and be being cleared of it. The marker goes
	// with the root.
	if err := MarkReady(d, started.ID); err != nil {
		return err
	}

	if e.Up != nil {
		up := EphemeralUp{Started: started, Manifest: m, Privilege: p}
		if st := s.status(ctx); st != nil {
			up.Status = *st
		}

		e.Up(up)
	}

	every := e.watchEvery
	if every == 0 {
		every = checkInterval(e.Config)
	}

	return s.keepEphemeral(ctx, c, e.Config, m, started.ID, every)
}

func (e *Ephemeral) report() Reporter {
	if e.Reporter == nil {
		return nopReporter{}
	}

	return e.Reporter
}

// ephemeralArgs is what an ephemeral anchord is started with: the socket, and no -config,
// since nothing of the run is written; the export, where there is one, goes over the socket.
func ephemeralArgs(d paths.Dirs, cfg *config.Config) []string {
	args := []string{"-socket", d.Socket()}

	if cfg.Observer != nil {
		args = append(args, "-allow-observer")
	}

	if os.Getenv("CONFLUX_DEBUG") == "1" {
		args = append(args, "-v")
	}

	return args
}

// exportSignals are the signals an export block turns on, as anchorctl export names them.
func exportSignals(x *config.Export) []string {
	var signals []string

	for _, s := range []struct {
		on   bool
		name string
	}{{x.Metrics, "metrics"}, {x.Traces, "traces"}, {x.Logs, "logs"}, {x.Flows, "flows"}} {
		if s.on {
			signals = append(signals, s.name)
		}
	}

	return signals
}

// handedCredential is a credential an ephemeral run was handed, checked as a start checks
// one: readable, granting the taints the run asks for, and current, since nothing here could
// renew an expired one before it starts -- a renewal names the anchor by the AnchorID it
// reports once it has.
func handedCredential(env config.Envelope, cfg *config.Config) (*enrol.Manifest, error) {
	m, err := enrol.Decode(env)
	if err != nil {
		return nil, &permanentError{err: err}
	}

	if err := m.CheckTaints(cfg.Taints); err != nil {
		return nil, &permanentError{err: err}
	}

	if !m.NotAfter().IsZero() && !m.NotAfter().After(time.Now()) {
		return nil, &permanentError{err: fmt.Errorf(
			"the credential expired %s ago, and anchor will not start on an expired one; get a fresh one from its issuer",
			time.Since(m.NotAfter()).Round(time.Minute))}
	}

	return m, nil
}

// enrolInMemory draws a credential in cfg's taints and keeps it here: the response is the
// only copy, as it always is, and an ephemeral run means it to be lost with the run.
func enrolInMemory(ctx context.Context, cfg *config.Config, r Reporter) (config.Envelope, *enrol.Manifest, error) {
	if len(cfg.Taints) == 0 {
		return nil, nil, &permanentError{err: enrol.ErrNoTaints}
	}

	client := &enrol.Client{BaseURL: cfg.APIBase()}

	r.Step("enrolling, into memory alone")

	env, err := client.Enrol(ctx, cfg.Taints)
	if err != nil {
		return nil, nil, err
	}

	m, err := enrol.Decode(env)
	if err != nil {
		return nil, nil, &permanentError{err: err}
	}

	if err := m.CheckTaints(cfg.Taints); err != nil {
		return nil, nil, &permanentError{err: err}
	}

	if skew, measured := client.Skew(); measured {
		if err := enrol.CheckSkew(skew, MaxSkew); err != nil {
			return nil, nil, err
		}
	}

	return env, m, nil
}

// keepEphemeral keeps the credential current until the context is cancelled, anchord ends,
// or its anchor does: renewing at two thirds of the window by the same body every renewal
// goes through, with the renewed manifest kept here and the chain handed to anchorctl on
// its stdin, and a failed renewal tried again every minute until the credential has run out.
// A credential that names nowhere to renew it runs to its expiry, and the run with it.
func (s *Supervisor) keepEphemeral(
	ctx context.Context, c *child, cfg *config.Config, m *enrol.Manifest, id string, every time.Duration,
) error {
	client := &enrol.Client{BaseURL: cfg.APIBase()}
	device := devicePath(cfg.Uplink)

	var zeroSince time.Time

	// One ticker for the watcher and one timer for the credential, each running on its own,
	// so neither restarts the other: a renewal is not put off by every look at the anchor.
	watch := time.NewTicker(every)
	defer watch.Stop()

	renewal := time.NewTimer(untilRenewal(m))
	defer renewal.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.exited:
			return c.gone("unexpectedly", s.tail)
		case <-watch.C:
			if why, _, _ := s.lost(ctx, cfg.Uplink, device, &zeroSince); why != "" {
				return fmt.Errorf("%s, and an ephemeral run does not bring one back", why)
			}
		case <-renewal.C:
			now := time.Now()

			switch {
			case !m.Renews() && !now.Before(m.NotAfter()):
				return &permanentError{err: fmt.Errorf("the credential ran out at %s, and it names nowhere to renew it",
					m.NotAfter().UTC().Format(time.RFC3339))}
			case !m.Renews() || !dueAt(m.IssuedAt(), m.NotAfter(), now):
				// Woken early by the clamp, to look at the clock again rather than trust a
				// timer set hours ago.
				renewal.Reset(untilRenewal(m))

				continue
			}

			next, chain, err := renewChain(ctx, client, m, id)
			if err == nil {
				err = s.ctl.Renew(ctx, chain)
			}

			if err != nil {
				if !time.Now().Before(m.NotAfter()) {
					return fmt.Errorf("the credential ran out before it could be renewed: %w", err)
				}

				s.report().Warn("renewal failed; trying again in %s: %v", minSleep, err)
				renewal.Reset(minSleep)

				continue
			}

			m = next
			s.report().Step("renewed, in memory; valid until %s", m.NotAfter().UTC().Format(time.RFC3339))
			renewal.Reset(untilRenewal(m))
		}
	}
}

// untilRenewal is how long until m is next due -- at two thirds of its window, or for one
// that does not renew at its expiry -- and never longer than maxSleep, so a clock that jumps
// is read again within hours.
func untilRenewal(m *enrol.Manifest) time.Duration {
	at := renewAt(m.IssuedAt(), m.NotAfter())
	if !m.Renews() {
		at = m.NotAfter()
	}

	return min(max(time.Until(at), 0), maxSleep)
}

// clearExcept removes everything in dir but keep: what a run killed before it could clean up
// left in the root, which the next run starts without.
func clearExcept(dir, keep string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, e := range entries {
		if p := filepath.Join(dir, e.Name()); p != keep {
			if err := os.RemoveAll(p); err != nil {
				return fmt.Errorf("clear %s: %w", p, err)
			}
		}
	}

	return nil
}
