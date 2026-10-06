package daemon

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/flock"
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
// ended, and reports true once it has given up.
//
// It gives up on a configuration that will not build an anchor, which a rebuild refused
// for good rebuildRefusals times in a row is -- a conflux.json edited under a running
// service, a credential that no longer grants its taints. Retrying that every thirty
// seconds for ever would fill the journal and change nothing; a restart of the service --
// `conflux start`, a reboot -- tries again, as it always would.
//
// every is how often it looks: checkInterval(uplink), which only a test shortens.
func (s *Supervisor) watch(ctx context.Context, uplink string, every time.Duration) bool {
	device := devicePath(uplink)

	backoff, refusals := rebuildBackoffMin, 0

	// zeroSince is when the connection count was first seen at zero, or the zero
	// time when the link is carrying something.
	var zeroSince time.Time

	for {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(every):
		}

		why, link := s.lost(ctx, uplink, device, &zeroSince)
		if why == "" {
			backoff = rebuildBackoffMin

			continue
		}

		s.clearReady()
		s.report().Warn("%s; rebuilding the anchor", why)

		if err := s.rebuild(ctx); err != nil {
			if isPermanent(err) {
				refusals++
			} else {
				refusals = 0
			}

			if refusals >= rebuildRefusals {
				s.report().Warn("this configuration will not build an anchor: %v\n"+
					"  conflux stops rebuilding it until the service is started again", err)

				return true
			}

			s.report().Warn("could not rebuild the anchor: %v", err)

			select {
			case <-ctx.Done():
				return false
			case <-time.After(backoff):
			}

			backoff = min(2*backoff, rebuildBackoffMax)

			continue
		}

		if link {
			s.recordReopen()
		}

		s.report().Step("the anchor is back")

		// Whatever the state was, it is a fresh anchor now.
		zeroSince = time.Time{}
		backoff, refusals = rebuildBackoffMin, 0
	}
}

// checkInterval is how often the watcher looks: the gauge on a link, status otherwise.
func checkInterval(uplink string) time.Duration {
	if uplink != "" {
		return linkCheckInterval
	}

	return anchorCheckInterval
}

// lost says why the anchor needs rebuilding, and whether its link is the reason; "" while
// it does not.
//
// A daemon that does not answer is the restart loop's business rather than this one's:
// rebuilding an anchor over a problem with the process would fix nothing.
func (s *Supervisor) lost(ctx context.Context, uplink, device string, zeroSince *time.Time) (string, bool) {
	if uplink != "" {
		dead, reason, err := s.linkIsDead(ctx, device, zeroSince)
		if dead {
			return "the uplink " + uplink + " " + reason, true
		}

		if err == nil {
			return "", false
		}
	}

	// Asked when the gauge could not be read, or on the host's network at every tick: a
	// daemon holding no anchor answers status and nothing else.
	probe, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()

	if st, err := s.ctl.Status(probe); err != nil || st.Running {
		return "", false
	}

	return "anchord holds no anchor any more", false
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
// BringUp rather than anything of its own: it is the path `up`, `proxy` and every
// boot already take, so a rebuilt anchor cannot be a subtly different one from the one
// a reboot would start. The daemon is untouched, so this costs one anchor's sessions
// and not the process.
func (s *Supervisor) rebuild(ctx context.Context) error {
	stopCtx, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()

	// Best effort, and nothing at all when the anchor is already gone. One holding a
	// medium that carries nothing is not worth keeping for a stop that cannot be
	// delivered.
	_ = s.ctl.Stop(stopCtx)

	started, err := BringUp(ctx, s.Dirs, s.ctl, s.report())
	if err != nil {
		return err
	}

	s.signalReady(started.ID)

	return nil
}

// recordReopen notes an uplink reopen where another process can see it.
//
// Best effort throughout: the anchor is back, which is the part that mattered, and
// losing the count is not worth failing that. BringUp has just rewritten the state
// file, so this reads it back rather than holding a stale copy across the restart,
// under the lock every other writer of it holds.
func (s *Supervisor) recordReopen() {
	unlock, err := flock.Acquire(s.Dirs.LockFile())
	if err != nil {
		return
	}
	defer unlock()

	st, err := config.LoadState(s.Dirs)
	if err != nil {
		return
	}

	st.LinkReopens++
	st.LastLinkReopen = time.Now().UTC()

	if err := config.SaveState(s.Dirs, st); err != nil {
		s.report().Warn("could not record the uplink reopen: %v", err)
	}
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
