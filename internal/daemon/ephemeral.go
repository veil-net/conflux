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

	// Manifest is a credential handed in, and Envelope what it was read from, which goes to
	// anchorctl on stdin; both nil to enrol in memory with Config's taints. The caller has
	// decoded it and checked its taints against Config's, as up and proxy do.
	Manifest *enrol.Manifest
	Envelope config.Envelope

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

	// A killed run's readiness marker is withdrawn before anything else: a reader that finds
	// the lock held takes the marker beside it for this run's. IsLiveReady refuses one whose
	// writer has gone anyway; this is for a writer's pid that something since was given.
	if err := ClearReady(d); err != nil {
		return err
	}

	// The root and the lock in it go last, after anchord has gone, so a second run is refused
	// until there is nothing left of this one. Emptied, and nothing more: what a killed run left
	// running is stopped below, before anything starts, and what this run starts, its shutdown
	// stops.
	defer func() {
		if err := emptyEphemeral(d, unlock); err != nil {
			e.report().Warn("could not empty %s: %v", d.State, err)
		}
	}()

	if err := d.CheckSocketLen(); err != nil {
		return &permanentError{err: err}
	}

	s := &Supervisor{Dirs: d, Reporter: e.Reporter, Drop: e.Drop, ephemeral: true}

	// What a run killed before it could clean up left behind, and the directories made again,
	// emptied of whatever it was.
	switch pid, err := s.reapLeftovers(); {
	case err != nil:
		e.report().Warn("%v", err)
	case pid != 0:
		e.report().Warn("stopped anchord (pid %d), left running by an ephemeral run that ended without stopping it", pid)
	}

	if _, err := paths.ClearExcept(d.State, d.ServeLockFile()); err != nil {
		return err
	}

	if err := d.EnsureAll(); err != nil {
		return err
	}

	// A credential handed in is checked before anything starts, and its port read: the port
	// decides what anchord is given.
	env, m := e.Envelope, e.Manifest
	if m != nil {
		if err := checkHanded(m); err != nil {
			return err
		}
	}

	// Into the root just made again above.
	tools := e.tools
	if tools == nil {
		if tools, err = libexec.Extract(d); err != nil {
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

	c, err := s.exec(p, e.Config.Observer != nil)
	if err != nil {
		return err
	}

	defer s.shutdown(c)

	if err := s.waitReady(ctx, c); err != nil {
		return err
	}

	// The credential, then the observer, then the anchor, as the supervisor's bring-up: the
	// observer runs under the run's own credential, held here alone.
	if env == nil {
		if env, m, err = enrolInMemory(ctx, e.Config, e.report()); err != nil {
			return err
		}
	}

	if e.Config.Observer != nil {
		if _, err := startObserver(ctx, s.ctl, s.report(), e.Config, env); err != nil {
			return err
		}
	}

	if x := e.Config.Export; x != nil && x.Enabled {
		if err := s.ctl.Export(ctx, x.Endpoint, x.Insecure, x.Signals()); err != nil {
			return fmt.Errorf("pointing the export at %s: %w", x.Endpoint, err)
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

// checkHanded refuses a credential an ephemeral run was handed that has expired, since nothing
// here could renew it before it starts: a renewal names the anchor by the AnchorID it reports
// once it has.
func checkHanded(m *enrol.Manifest) error {
	if !m.NotAfter().IsZero() && !m.NotAfter().After(time.Now()) {
		return &permanentError{err: fmt.Errorf(
			"the credential expired %s ago, and anchor will not start on an expired one; get a fresh one from its issuer",
			time.Since(m.NotAfter()).Round(time.Minute))}
	}

	return nil
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
// its stdin, for the anchor and the observer beside it, and a failed renewal tried again
// every minute until the credential has run out.
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
			if l := s.lost(ctx, cfg.Uplink, device, &zeroSince); l.why != "" {
				return fmt.Errorf("%s, and an ephemeral run does not bring one back", l.why)
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
				err = installRenewal(ctx, s.ctl, cfg, chain, parts{})
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

// RemoveEphemeral removes a killed ephemeral run's root e, as tidy and uninstall clear it, whose lock
// the caller holds and lets go of with unlock: whatever the run left running is stopped first, and
// then the root is emptied and removed (emptyEphemeral).
func RemoveEphemeral(e paths.Dirs, unlock func(), r Reporter) error {
	_, reapErr := (&Supervisor{Dirs: e, Reporter: r, ephemeral: true}).reapLeftovers()

	return errors.Join(reapErr, emptyEphemeral(e, unlock))
}

// emptyEphemeral empties an ephemeral run's root e but for its lock while the lock is held, so a run that
// takes it the moment it is let go is never emptied out from under itself; then lets go of the lock with
// unlock, and removes the lock file and the root, which is empty unless such a run has taken it, nothing
// more. The root is conflux's, made as conflux makes one, so nobody else can have put anything in it, nor
// a link at its name. It says why the root could not be emptied.
func emptyEphemeral(e paths.Dirs, unlock func()) error {
	_, err := paths.ClearExcept(e.State, e.ServeLockFile())

	unlock()

	_ = os.Remove(e.ServeLockFile())
	_ = os.Remove(e.State)

	return err
}

// reapLeftovers stops what a run killed before it could clean up left running from the root --
// its anchord, where nothing ended it with that run (macOS and the BSDs), and whatever runs as
// the ephemeral account -- and says which anchord it stopped, or why it could not.
func (s *Supervisor) reapLeftovers() (pid int, err error) {
	pid, err = ReapOrphan(s.Dirs)

	s.killLeftovers()

	return pid, err
}
