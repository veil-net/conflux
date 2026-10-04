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
// that process exiting. anchord can lose the anchor it holds -- a realm admin's kill
// order empties the slot, and so does an anchor that closes for any other reason -- and
// carry on serving a socket with nothing behind it. And an anchor on an uplink reaches
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
	// Above anchor's own uplink dial timeout (45s) plus the five seconds and up to one of
	// jitter it waits between dials while it holds no connection, so a link still
	// dialling is never mistaken for one that has ended, and above the ~25s a realm
	// handshake needs on a 9600-baud line -- the slowest speed conflux accepts. The cost
	// of being wrong is one restart; the cost of being hasty is a restart that
	// interrupts a handshake that was about to succeed.
	linkGrace = 90 * time.Second

	// rebuildBackoffMin and rebuildBackoffMax bound how fast a failed rebuild is
	// retried. A link whose far end is simply switched off would otherwise restart every
	// 90 seconds forever.
	rebuildBackoffMin = 1 * time.Second
	rebuildBackoffMax = 30 * time.Second
)

// watch keeps an anchor in the daemon, rebuilding it when it has gone or its link has
// ended, and reports true once an admin's kill order has stopped it.
//
// A killed anchor is left stopped, because rebuilding it would undo the order within the
// minute, and the watch ends there. The service is still up and the kill is recorded for
// `conflux status`; a restart of the service -- `conflux start`, a reboot -- builds it
// again, as it always would.
func (s *Supervisor) watch(ctx context.Context, uplink string) bool {
	interval, device := anchorCheckInterval, ""
	if uplink != "" {
		interval, device = linkCheckInterval, devicePath(uplink)
	}

	backoff := rebuildBackoffMin

	// zeroSince is when the connection count was first seen at zero, or the zero
	// time when the link is carrying something.
	var zeroSince time.Time

	for {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(interval):
		}

		why, link := s.lost(ctx, uplink, device, &zeroSince)

		switch {
		case why == "":
			backoff = rebuildBackoffMin

			continue
		case why == adminStopLine:
			s.clearReady()
			s.recordAdminStop()
			s.report().Warn("an admin credential stopped this anchor; conflux leaves it stopped until the service is started again")

			return true
		}

		s.clearReady()
		s.report().Warn("%s; rebuilding the anchor", why)

		if err := s.rebuild(ctx); err != nil {
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
		backoff = rebuildBackoffMin
	}
}

// lost says why the anchor needs rebuilding, and whether its link is the reason; "" while
// it does not. adminStopLine means it must not be rebuilt at all.
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

	switch st, err := s.ctl.Status(probe); {
	case err != nil, st.Running:
		return "", false
	case s.adminStopped.Load():
		return adminStopLine, false
	default:
		return "anchord holds no anchor any more", false
	}
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
	s.updateState("the uplink reopen", func(st *config.State) {
		st.LinkReopens++
		st.LastLinkReopen = time.Now().UTC()
	})
}

// recordAdminStop notes the kill order for `conflux status`, which is the only way
// somebody looking at the machine learns why it holds no anchor. The next BringUp
// clears it.
func (s *Supervisor) recordAdminStop() {
	s.updateState("the admin's stop", func(st *config.State) { st.AdminStoppedAt = time.Now().UTC() })
}

// updateState changes the state file under the lock, best effort.
func (s *Supervisor) updateState(what string, change func(*config.State)) {
	unlock, err := flock.Acquire(s.Dirs.LockFile())
	if err != nil {
		return
	}
	defer unlock()

	st, err := config.LoadState(s.Dirs)
	if err != nil {
		return
	}

	change(st)

	if err := config.SaveState(s.Dirs, st); err != nil {
		s.report().Warn("could not record %s: %v", what, err)
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
