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

	// rebuildBackoffMax caps how long the watcher holds off trying again what failed: a
	// rebuild, a rebuilt link that brought no connection, an observer that would not start
	// again. The first try waits for the next look, and each after that twice as long as the
	// one before, up to this. On the host's network, which is looked at every 30 seconds, that
	// is every look. On a link it is 10 seconds, then 20, then 30: a far end that is simply
	// switched off, where every rebuild works and none brings a connection, is reopened once
	// its 90-second grace has run and then 30 seconds at most after that, about every two
	// minutes, while anchor's own redial, every few seconds, finds one that comes back.
	rebuildBackoffMax = 30 * time.Second

	// rebuildRefusals is how many rebuilds in a row may be refused for good before the
	// watcher stops, and how many starts of the daemon before the supervisor does: a
	// configuration that will not build an anchor is refused again on every try.
	rebuildRefusals = 3
)

// linkGrace is how long the connection count must stay at zero before the link is called
// dead: a variable only so a test can wait less than this for one.
//
// Above anchor's own uplink dial timeout (45s) -- it starts a dial at most every five
// seconds and up to one of jitter while it holds no connection, timed from the start
// of the one before, so one that never answers is followed at once by the next -- so
// a link still dialling is never mistaken for one that has ended, and above the ~25s a realm
// handshake needs on a 9600-baud line -- the slowest speed conflux accepts. The cost
// of being wrong is one restart; the cost of being hasty is a restart that
// interrupts a handshake that was about to succeed.
var linkGrace = 90 * time.Second

// watch keeps an anchor in the daemon, rebuilding it when it has gone or its link has
// ended, and the observer observing, starting it again when its capture has ended or, beside
// an anchor, its start failed (up, what the bring-up started); and reports true once it has
// given up on what the configuration runs.
//
// It gives up on a configuration that will not build an anchor, which a rebuild refused
// for good rebuildRefusals times in a row is -- a conflux.json edited under a running
// service, a credential that no longer grants its taints. Retrying that for ever, however
// far apart, would fill the journal and change nothing; a restart of the service --
// `conflux start`, a reboot -- tries again, as it always would. An observer the host will
// not let capture is given up on the same way: beside an anchor the anchor is still kept,
// and observing alone there is nothing left to keep.
//
// An anchor and an observer are kept apart: each has its own backoff and its own count of
// refusals, so one that keeps failing neither slows the other's retries nor counts against
// it. One status call a look answers both.
//
// A link's rebuild has worked only once the link carries something: found ended again first,
// it brought no connection, and counts as a rebuild that failed, so the next waits out the
// backoff.
//
// every is how often it looks, and the least a failure holds the next try off:
// checkInterval(cfg), which only a test shortens.
func (s *Supervisor) watch(ctx context.Context, cfg *config.Config, up brought, every time.Duration) bool {
	device := devicePath(cfg.Uplink)

	anchor, observer := newKeeper(every, rebuildBackoffMax), newKeeper(every, rebuildBackoffMax)
	observing := cfg.Observer != nil

	// down is an observer the bring-up did not start: status reads it only as not observing,
	// as it reads one stopped by hand, which is left alone.
	down := observing && !up.observing

	// zeroSince is when the connection count was first seen at zero, or the zero
	// time when the link is carrying something.
	var zeroSince time.Time

	// unproven is a link rebuilt and not yet seen carrying anything.
	var unproven bool

	// gone is a link whose device has left the filesystem. Nothing is built on a device that
	// is not there, so the anchor on it is stopped, and only the filesystem is asked -- no
	// bring-up, no state written -- until the device is back to be rebuilt on.
	var gone bool

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
			var l look

			switch {
			case !gone:
				l = s.lost(ctx, cfg.Uplink, device, &zeroSince)
			case present(device):
				gone, l = false, look{why: "the uplink " + cfg.Uplink + " is back on this machine", link: true}
			}

			st = l.status

			switch {
			case gone:
				// Still not there.
			case l.gone:
				gone, unproven = true, false
				s.stopLost(ctx, l.why)
			case l.why == "" && (cfg.Uplink == "" || l.carrying):
				// Doing its job, so whatever failed before has stopped failing.
				anchor.backoff, unproven = anchor.least, false
			case l.why == "":
				// A link carrying nothing yet, inside its grace: nothing to say either way.
			case unproven:
				unproven = false
				anchor.failed(errNoConnection)
				s.report().Warn("%s, and has carried nothing since it was rebuilt; rebuilding it in %s",
					l.why, time.Until(anchor.notBefore).Round(time.Second))
			default:
				switch s.rebuildAnchor(ctx, l.why, l.link, anchor) {
				case respawned:
					return false
				case gaveUp:
					return true
				case kept:
					// Whatever the state was, it is a fresh anchor now.
					zeroSince, unproven = time.Time{}, l.link
				}

				st = nil
			}
		}

		if observing && observer.due() {
			why := "the observer did not start"

			if !down {
				if st == nil {
					st = s.status(ctx)
				}

				if st == nil || !st.Observer.Failed() {
					continue
				}

				why = "the observer stopped (" + strings.TrimPrefix(st.Observer.Note, "not observing: ") + ")"
			}

			switch s.restartObserver(ctx, why, observer) {
			case kept:
				down = false
			case gaveUp:
				if !cfg.Anchor() {
					return true
				}

				observing = false
			}
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

// stopLost stops an anchor whose link's device has gone, to be rebuilt once the device is back.
func (s *Supervisor) stopLost(ctx context.Context, why string) {
	s.clearReady()
	s.report().Warn("%s; the anchor is stopped until it is back", why)

	stop, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()

	// Best effort, as a rebuild's: an anchor holding a device that has gone carries nothing.
	_ = s.ctl.Stop(stop)
}

// errNoConnection is a rebuilt link that ended again with nothing carried: the rebuild it
// counts against the backoff as failed, which a retry may yet fix.
var errNoConnection = errors.New("the rebuilt link carried no connection")

// rebuildAnchor rebuilds an anchor that is lost, and says what came of it. A link rebuilt
// keeps its backoff until it carries something (watch).
func (s *Supervisor) rebuildAnchor(ctx context.Context, why string, link bool, k *keeper) outcome {
	s.clearReady()
	s.report().Warn("%s; rebuilding the anchor", why)

	err := s.rebuild(ctx, link)
	if err == nil {
		s.report().Step("the anchor is back")

		if k.refusals = 0; !link {
			k.ok()
		}

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

// restartObserver starts the observer again, under the credential bringUp holds for it, and
// says what came of it. why is why it is not running.
func (s *Supervisor) restartObserver(ctx context.Context, why string, k *keeper) outcome {
	s.report().Warn("%s; starting it again", why)

	_, err := bringUp(ctx, s.Dirs, s.ctl, s.report(), s.priv.Dir, false, parts{observer: true})
	if err == nil {
		s.report().Step("the observer is back")
		k.ok()

		return kept
	}

	if k.failed(err) {
		s.report().Warn("this host will not let anchord observe: %v\n"+
			"  conflux stops starting the observer until the service is started again", err)

		return gaveUp
	}

	s.report().Warn("could not start the observer again: %v", err)

	return retrying
}

// keeper is what the watcher holds for one thing it keeps running, and the supervisor's
// restart loop for the daemon: how long to wait before trying it again, between least and
// most, when it may be tried, and how many tries in a row were refused for good.
type keeper struct {
	least, most time.Duration
	backoff     time.Duration
	refusals    int
	notBefore   time.Time
}

func newKeeper(least, most time.Duration) *keeper {
	return &keeper{least: least, most: most, backoff: least}
}

// due says whether it may be looked at and tried again now.
func (k *keeper) due() bool { return !time.Now().Before(k.notBefore) }

// ok records that it is back.
func (k *keeper) ok() { *k = *newKeeper(k.least, k.most) }

// failed records a try that failed with err, holds the next off for the backoff, and says
// whether the tries refused for good have reached rebuildRefusals.
func (k *keeper) failed(err error) bool {
	if Permanent(err) {
		k.refusals++
	} else {
		k.refusals = 0
	}

	k.notBefore = time.Now().Add(k.backoff)
	k.backoff = min(2*k.backoff, k.most)

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

// look is what one look at the anchor found.
type look struct {
	// why is why the anchor needs rebuilding, and link whether its link is the reason; why is
	// "" while it does not.
	why  string
	link bool

	// carrying is a link that carries a connection now, and gone one whose device has left
	// the filesystem.
	carrying, gone bool

	// status is what status said, where it was asked and answered.
	status *anchorctl.Status
}

// lost looks at the anchor: whether it needs rebuilding, and why.
//
// A daemon that does not answer is the restart loop's business rather than this one's:
// rebuilding an anchor over a problem with the process would fix nothing.
func (s *Supervisor) lost(ctx context.Context, uplink, device string, zeroSince *time.Time) look {
	if uplink != "" {
		dead, carrying, reason, err := s.linkIsDead(ctx, device, zeroSince)
		if dead {
			return look{why: "the uplink " + uplink + " " + reason, link: true, gone: reason == deviceGone}
		}

		if err == nil {
			return look{carrying: carrying}
		}
	}

	// Asked when the gauge could not be read, or on the host's network at every tick: a
	// daemon holding no anchor answers status and nothing else.
	st := s.status(ctx)
	if st == nil || st.Running {
		return look{status: st}
	}

	return look{why: "anchord holds no anchor any more", status: st}
}

// linkIsDead decides whether the link has ended, and says why, or whether it carries a
// connection now. Its error is the gauge that could not be read, which says nothing about the
// link either way.
//
// Two signals. A device that has gone from the filesystem is unambiguous and
// immediate -- a USB serial adapter that was unplugged is simply not there any more.
// A connection count held at zero past the grace period is the general case, and the
// one that catches a device still present whose line has died.
func (s *Supervisor) linkIsDead(ctx context.Context, device string, zeroSince *time.Time) (dead, carrying bool, why string, err error) {
	if device != "" && !present(device) {
		return true, false, deviceGone, nil
	}

	probe, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()

	conns, _, err := s.ctl.Metric(probe, anchorctl.MetricConnections)
	if err != nil {
		return false, false, "", err
	}

	if conns > 0 {
		*zeroSince = time.Time{}

		return false, true, "", nil
	}

	now := time.Now()
	if zeroSince.IsZero() {
		*zeroSince = now

		return false, false, "", nil
	}

	if now.Sub(*zeroSince) < linkGrace {
		return false, false, "", nil
	}

	return true, false, "has carried nothing for " + now.Sub(*zeroSince).Truncate(time.Second).String(), nil
}

// deviceGone is why a link whose device has left the filesystem has ended.
const deviceGone = "is gone from this machine"

// present reports whether the device at path is on the filesystem.
func present(path string) bool {
	_, err := os.Stat(path)

	return !errors.Is(err, fs.ErrNotExist)
}

// rebuild stops whatever anchor is left and builds it again from the configuration.
//
// bringUp rather than anything of its own: it is the path `up`, `proxy`, `observe` and
// every boot already take, so a rebuilt anchor cannot be a subtly different one from the one
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
	up, err := bringUp(ctx, s.Dirs, s.ctl, s.report(), s.priv.Dir, link, parts{anchor: true})
	if err != nil {
		return err
	}

	s.signalReady(up.id)

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
