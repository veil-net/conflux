package daemon

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"runtime"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
)

// The link watcher, and why it has to exist.
//
// An anchor on an uplink reaches the realm over a link rather than a socket, and
// anchor does not reopen a link that ends: an unplugged adapter, a cable pulled, a
// far end power-cycled, and the anchor stays up holding a medium that carries
// nothing. Restarting it is the documented answer.
//
// Nothing else here would notice. The supervisor watches the anchord *process*, and
// anchord does not exit -- it has no reason to, the daemon is fine and only the
// anchor inside it is stranded. So on a desk somebody eventually types `conflux up`,
// and on the unattended serial deployments this pathway exists for, nobody does.
const (
	// linkCheckInterval is how often the gauge is read. Cheap: one control-socket
	// round trip to a daemon on the same machine.
	linkCheckInterval = 10 * time.Second

	// linkGrace is how long the connection count must stay at zero before the link
	// is called dead.
	//
	// Above anchor's own UplinkDialTimeout (45s) plus its two-second keeper tick, so
	// a link still dialling is never mistaken for one that has ended, and above the
	// ~25s a realm handshake needs on a 9600-baud line -- the slowest speed conflux
	// accepts. The cost of being wrong is one restart; the cost of being hasty is a
	// restart that interrupts a handshake that was about to succeed.
	linkGrace = 90 * time.Second

	// linkBackoffMin and linkBackoffMax bound how fast reopening is retried. A link
	// whose far end is simply switched off would otherwise restart every 90 seconds
	// forever.
	linkBackoffMin = 1 * time.Second
	linkBackoffMax = 30 * time.Second
)

// linkLoop watches an uplink and restarts the anchor when the link has ended.
//
// Only runs for an anchor configured with one. On the host's IP network this whole
// question belongs to anchor, which handles a network change in-process by rebinding
// and migrating its connections, and needs nothing from conflux.
func (s *Supervisor) linkLoop(ctx context.Context, spec string) {
	// Windows has no uplink at all: anchor cannot open a link there, and `conflux up`
	// refuses --uplink rather than letting a service fail at boot on it.
	if runtime.GOOS == "windows" || spec == "" {
		return
	}

	device := devicePath(spec)
	backoff := linkBackoffMin

	// zeroSince is when the connection count was first seen at zero, or the zero
	// time when the link is carrying something.
	var zeroSince time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(linkCheckInterval):
		}

		dead, reason := s.linkIsDead(ctx, device, &zeroSince)
		if !dead {
			backoff = linkBackoffMin

			continue
		}

		s.report().Warn("the uplink %s %s; restarting the anchor", spec, reason)

		if err := s.reopenLink(ctx); err != nil {
			s.report().Warn("could not restart the anchor on %s: %v", spec, err)

			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}

			if backoff *= 2; backoff > linkBackoffMax {
				backoff = linkBackoffMax
			}

			continue
		}

		s.links.Add(1)
		s.recordReopen()
		s.report().Step("the anchor is back on %s", spec)

		// Whatever the state was, it is a fresh link now.
		zeroSince = time.Time{}
		backoff = linkBackoffMin
	}
}

// linkIsDead decides whether the link has ended, and says why.
//
// Two signals. A device that has gone from the filesystem is unambiguous and
// immediate -- a USB serial adapter that was unplugged is simply not there any more.
// A connection count held at zero past the grace period is the general case, and the
// one that catches a device still present whose line has died.
func (s *Supervisor) linkIsDead(ctx context.Context, device string, zeroSince *time.Time) (bool, string) {
	if device != "" {
		if _, err := os.Stat(device); errors.Is(err, fs.ErrNotExist) {
			return true, "is gone from this machine"
		}
	}

	probe, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()

	metrics, err := s.ctl.Metrics(probe)
	if err != nil {
		// The daemon not answering is the restart loop's business, not this one's.
		// Treating it as a dead link would restart an anchor over a problem that
		// has nothing to do with the medium.
		return false, ""
	}

	if metrics[anchorctl.MetricConnections] > 0 {
		*zeroSince = time.Time{}

		return false, ""
	}

	now := time.Now()
	if zeroSince.IsZero() {
		*zeroSince = now

		return false, ""
	}

	if now.Sub(*zeroSince) < linkGrace {
		return false, ""
	}

	return true, "has carried nothing for " + now.Sub(*zeroSince).Truncate(time.Second).String()
}

// reopenLink stops the stranded anchor and builds it again from the configuration.
//
// BringUp rather than anything of its own: it is the path `up`, `proxy` and every
// boot already take, so a link that came back cannot start a subtly different anchor
// from the one a reboot would. The daemon is untouched, so this costs one anchor's
// sessions and not the process.
func (s *Supervisor) reopenLink(ctx context.Context) error {
	stopCtx, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()

	// Best effort. The anchor being stopped is holding a medium that carries
	// nothing, so a stop that cannot be delivered is not a reason to keep it.
	_ = s.ctl.Stop(stopCtx)

	_, err := BringUp(ctx, s.Dirs, s.ctl, s.report())

	return err
}

// recordReopen notes the reopen where another process can see it.
//
// Best effort throughout: the anchor is back, which is the part that mattered, and
// losing the count is not worth failing that. BringUp has just rewritten the state
// file, so this reads it back rather than holding a stale copy across the restart.
func (s *Supervisor) recordReopen() {
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
// watch -- and conflux refuses that form at the CLI anyway, since its own supervisor
// is what starts anchord and hands it nothing to adopt.
func devicePath(spec string) string {
	parsed, err := config.ParseUplinkSpec(spec)
	if err != nil {
		return ""
	}

	return parsed.Path
}
