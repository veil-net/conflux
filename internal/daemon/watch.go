package daemon

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
)

// The watcher, and why it has to exist.
//
// The supervisor watches the anchord *process*, and two things strand an anchor without
// that process exiting. anchord can lose the anchor it holds -- an anchor that closes on
// its own empties the slot -- and carry on serving a socket with nothing behind it.
// (A realm's block is not one of them: a blocked anchor keeps running, outside the
// realm, and rebuilding it would change nothing.) And an anchor on an uplink reaches
// the realm over a link rather than a socket, and anchor does not reopen a link that
// ends: an unplugged adapter, a cable pulled, a far end power-cycled, and the anchor
// stays up holding a medium that carries nothing. Restarting it is the documented
// answer.
//
// Nothing else here would notice either. So on a desk somebody eventually types
// `conflux up`, and on the unattended deployments this exists for, nobody does.
const (
	// anchorCheckInterval is how often a daemon on the host's network is asked whether
	// it still holds an anchor: one status call, a fork and a socket round trip.
	anchorCheckInterval = 30 * time.Second

	// linkCheckInterval is how often an uplink's gauge is read instead. The metrics call
	// answers the status call's question as well -- a daemon with no anchor has no
	// metrics -- so a link costs no second poll.
	linkCheckInterval = 10 * time.Second

	// linkGrace is how long the connection count must stay at zero before the link
	// is called dead.
	//
	// Above anchor's own uplink dial timeout (45s) -- it starts a dial at most every five
	// seconds and up to one of jitter while it holds no connection, timed from the start
	// of the one before, so one that never answers is followed at once by the next -- so
	// a link still dialling is never mistaken for one that has ended, and above the ~25s a realm
	// handshake needs on a 9600-baud line -- the slowest speed conflux accepts. The cost
	// of being wrong is one restart; the cost of being hasty is a restart that
	// interrupts a handshake that was about to succeed.
	linkGrace = 90 * time.Second

	// rebuildBackoffMin and rebuildBackoffMax bound how fast a failed rebuild is
	// retried. A link whose far end is simply switched off would otherwise restart every
	// 90 seconds forever.
	rebuildBackoffMin = 1 * time.Second
	rebuildBackoffMax = 30 * time.Second

	// rebuildRefusals is how many rebuilds in a row may be refused for good before the
	// watcher stops: the supervisor's own allowance for a start, for the same reason.
	rebuildRefusals = 3
)

// watch keeps an anchor in the daemon, rebuilding it when it has gone or its link has
// ended, and the observer observing, starting it again when its capture has ended; and
// reports true once it has given up on what the configuration runs.
//
// It gives up on a configuration that will not build an anchor, which a rebuild refused
// for good rebuildRefusals times in a row is -- a conflux.json edited under a running
// service, a credential that no longer grants its taints. Retrying that every thirty
// seconds for ever would fill the journal and change nothing; a restart of the service --
// `conflux start`, a reboot -- tries again, as it always would. An observer the host will
// not let capture is given up on the same way: beside an anchor the anchor is still kept,
// and observing alone there is nothing left to keep.
//
// An anchor and an observer are kept apart: each has its own backoff and its own count of
// refusals, so one that keeps failing neither slows the other's retries nor counts against
// it. One status call a look answers both.
//
// every is how often it looks: checkInterval(cfg), which only a test shortens.
func (s *Supervisor) watch(ctx context.Context, cfg *config.Config, every time.Duration) bool {
	device := devicePath(cfg.Uplink)

	anchor, observer := newKeeper(), newKeeper()
	observing := cfg.Observer != nil

	// zeroSince is when the connection count was first seen at zero, or the zero
	// time when the link is carrying something.
	var zeroSince time.Time

	for {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(every):
		}

		// What status said this look, so the observer is read off the call the anchor's
		// check already made; nil where none was made or it was not answered.
		var st *anchorctl.Status

		if cfg.Anchor() && anchor.due() {
			why, link, read := s.lost(ctx, cfg.Uplink, device, &zeroSince)
			st = read

			if why == "" {
				anchor.backoff = rebuildBackoffMin
			} else {
				switch s.rebuildAnchor(ctx, why, link, anchor) {
				case respawned:
					return false
				case gaveUp:
					return true
				case kept:
					// Whatever the state was, it is a fresh anchor now.
					zeroSince = time.Time{}
				}

				st = nil
			}
		}

		if observing && observer.due() {
			if st == nil {
				st = s.status(ctx)
			}

			if st == nil || !st.Observer.Failed() {
				continue
			}

			if !s.restartObserver(ctx, cfg, st.Observer, observer) {
				continue
			}

			if !cfg.Anchor() {
				return true
			}

			observing = false
		}
	}
}

// outcome is what one attempt to bring something back came to.
type outcome int

const (
	kept      outcome = iota // it is back
	retrying                 // it is not, and is tried again after the backoff
	gaveUp                   // it has been refused for good too many times in a row
	respawned                // the decision no longer fits; the cycle starts anchord again
)

// rebuildAnchor rebuilds an anchor that is lost, and says what came of it.
func (s *Supervisor) rebuildAnchor(ctx context.Context, why string, link bool, k *keeper) outcome {
	s.clearReady()
	s.report().Warn("%s; rebuilding the anchor", why)

	err := s.rebuild(ctx, link)
	if err == nil {
		s.report().Step("the anchor is back")
		k.ok()

		return kept
	}

	// A rebuild the decision no longer fits -- an uplink's device that has appeared with a
	// group anchord was not given -- is the cycle's to start again.
	if s.redecided() {
		s.report().Warn("could not rebuild the anchor: %v", err)
		s.requestRespawn()

		return respawned
	}

	if k.failed(err) {
		s.report().Warn("this configuration will not build an anchor: %v\n"+
			"  conflux stops rebuilding it until the service is started again", err)

		return gaveUp
	}

	s.report().Warn("could not rebuild the anchor: %v", err)

	return retrying
}

// restartObserver starts an observer whose capture ended again, and says whether to give
// up on it.
func (s *Supervisor) restartObserver(ctx context.Context, cfg *config.Config, was anchorctl.Observer, k *keeper) bool {
	s.report().Warn("the observer stopped (%s); starting it again", strings.TrimPrefix(was.Note, "not observing: "))

	err := s.startObserver(ctx, cfg)
	if err == nil {
		s.report().Step("the observer is back")
		k.ok()

		return false
	}

	if k.failed(err) {
		s.report().Warn("this host will not let anchord observe: %v\n"+
			"  conflux stops starting the observer until the service is started again", err)

		return true
	}

	s.report().Warn("could not start the observer again: %v", err)

	return false
}

// keeper is what the watcher holds for one thing it keeps running: how long to wait before
// trying it again, when it may be tried, and how many tries in a row were refused for good.
type keeper struct {
	backoff   time.Duration
	refusals  int
	notBefore time.Time
}

func newKeeper() *keeper { return &keeper{backoff: rebuildBackoffMin} }

// due says whether it may be looked at and tried again now.
func (k *keeper) due() bool { return !time.Now().Before(k.notBefore) }

// ok records that it is back.
func (k *keeper) ok() { *k = *newKeeper() }

// failed records a try that failed with err, holds the next off for the backoff, and says
// whether the tries refused for good have reached rebuildRefusals.
func (k *keeper) failed(err error) bool {
	if Permanent(err) {
		k.refusals++
	} else {
		k.refusals = 0
	}

	k.notBefore = time.Now().Add(k.backoff)
	k.backoff = min(2*k.backoff, rebuildBackoffMax)

	return k.refusals >= rebuildRefusals
}

// checkInterval is how often the watcher looks: the gauge on a link, status otherwise.
func checkInterval(cfg *config.Config) time.Duration {
	if cfg.Uplink != "" && cfg.Anchor() {
		return linkCheckInterval
	}

	return anchorCheckInterval
}

// status asks the daemon what it is doing, and is nil where it does not answer: that is
// the restart loop's business, not the watcher's.
func (s *Supervisor) status(ctx context.Context) *anchorctl.Status {
	probe, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()

	st, err := s.ctl.Status(probe)
	if err != nil {
		return nil
	}

	return &st
}

// lost says why the anchor needs rebuilding, and whether its link is the reason; "" while
// it does not. And what status said, where it was asked and answered.
//
// A daemon that does not answer is the restart loop's business rather than this one's:
// rebuilding an anchor over a problem with the process would fix nothing.
func (s *Supervisor) lost(ctx context.Context, uplink, device string, zeroSince *time.Time) (string, bool, *anchorctl.Status) {
	if uplink != "" {
		dead, reason, err := s.linkIsDead(ctx, device, zeroSince)
		if dead {
			return "the uplink " + uplink + " " + reason, true, nil
		}

		if err == nil {
			return "", false, nil
		}
	}

	// Asked when the gauge could not be read, or on the host's network at every tick: a
	// daemon holding no anchor answers status and nothing else.
	st := s.status(ctx)
	if st == nil || st.Running {
		return "", false, st
	}

	return "anchord holds no anchor any more", false, st
}

// linkIsDead decides whether the link has ended, and says why. Its error is the gauge
// that could not be read, which says nothing about the link either way.
//
// Two signals. A device that has gone from the filesystem is unambiguous and
// immediate -- a USB serial adapter that was unplugged is simply not there any more.
// A connection count held at zero past the grace period is the general case, and the
// one that catches a device still present whose line has died.
func (s *Supervisor) linkIsDead(ctx context.Context, device string, zeroSince *time.Time) (bool, string, error) {
	if device != "" {
		if _, err := os.Stat(device); errors.Is(err, fs.ErrNotExist) {
			return true, "is gone from this machine", nil
		}
	}

	probe, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()

	conns, _, err := s.ctl.Metric(probe, anchorctl.MetricConnections)
	if err != nil {
		return false, "", err
	}

	if conns > 0 {
		*zeroSince = time.Time{}

		return false, "", nil
	}

	now := time.Now()
	if zeroSince.IsZero() {
		*zeroSince = now

		return false, "", nil
	}

	if now.Sub(*zeroSince) < linkGrace {
		return false, "", nil
	}

	return true, "has carried nothing for " + now.Sub(*zeroSince).Truncate(time.Second).String(), nil
}

// rebuild stops whatever anchor is left and builds it again from the configuration.
//
// bringUp rather than anything of its own: it is the path `up`, `proxy` and every
// boot already take, so a rebuilt anchor cannot be a subtly different one from the one
// a reboot would start. The daemon is untouched, so this costs one anchor's sessions
// and not the process.
func (s *Supervisor) rebuild(ctx context.Context, link bool) error {
	stopCtx, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()

	// Best effort, and nothing at all when the anchor is already gone. One holding a
	// medium that carries nothing is not worth keeping for a stop that cannot be
	// delivered.
	_ = s.ctl.Stop(stopCtx)

	// An ended link's rebuild is counted in the state bringUp writes anyway, where status
	// reads it: a machine reopening its anchor every few minutes has a failing cable.
	started, err := bringUp(ctx, s.Dirs, s.ctl, s.report(), s.priv.Dir, link)
	if err != nil {
		return err
	}

	s.signalReady(started.ID)

	return nil
}

// devicePath is the device an uplink spec names, or "" for a spec that names none.
//
// fd:N adopts a descriptor rather than opening anything, so there is no path to
// watch -- and conflux refuses that form anyway, since its own supervisor is what
// starts anchord and hands it nothing to adopt.
func devicePath(spec string) string {
	parsed, err := config.ParseUplinkSpec(spec)
	if err != nil {
		return ""
	}

	return parsed.Path
}
