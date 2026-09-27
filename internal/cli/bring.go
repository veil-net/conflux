package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/service"
	"github.com/veil-net/conflux/internal/ui"
	"github.com/veil-net/conflux/internal/wintun"
)

// bring is the tail both `up` and `proxy` share: validate, persist, register the
// boot service, start, and report.
//
// The order is deliberate. The configuration is written before the service is
// registered and before anything starts, so that a machine which fails halfway
// through still comes back to the right state at its next boot rather than to
// nothing.
func bring(ctx context.Context, d paths.Dirs, cfg *config.Config, verb string) int {
	if err := cfg.Validate(); err != nil {
		return fail(err)
	}

	if err := config.Save(d, cfg); err != nil {
		return fail(err)
	}

	// Windows needs the driver before an interface can exist. Downloaded rather
	// than embedded: it is GPLv2, and a driver extracted from a program's own
	// resources is the shape of a DLL hijack.
	if cfg.Mode == config.ModeTUN {
		if err := wintun.Ensure(ctx, d); err != nil {
			return fail(err)
		}
	}

	if code := install(ctx, d, false); code != ExitOK {
		return code
	}

	ui.Printf("\nStarting.\n")

	if err := restartService(d); err != nil {
		return fail(err)
	}

	started, err := waitForAnchor(ctx, d)
	if err != nil {
		return fail(err)
	}

	report(cfg, started, verb)

	return ExitOK
}

// restartService hands the machine to the boot service rather than running an
// anchor from this process.
//
// One supervisor, whatever started it. A `conflux up` that ran its own daemon would
// leave two ideas of what is running -- the service manager's and ours -- and they
// would disagree the moment either changed.
func restartService(d paths.Dirs) error {
	mgr, err := service.New()
	if err != nil {
		return err
	}

	return restartWith(d, mgr)
}

// restartWith withdraws the readiness marker and then restarts, in that order.
//
// The order is the whole of what makes the marker worth reading. A marker left by the
// supervisor that is about to be replaced would let waitForAnchor return a status for
// an anchor on its way out -- reporting success for one that is seconds from being torn
// down. Removing it first means the marker that appears afterwards can only have been
// written by the instance this restart started.
//
// One function so the two callers cannot drift: every path that restarts the service and
// then waits for an anchor goes through here.
func restartWith(d paths.Dirs, mgr service.Manager) error {
	if err := daemon.ClearReady(d); err != nil {
		// Not fatal. A marker that will not go costs waitForAnchor one status call it
		// was going to make anyway, which is exactly what the fallback is for.
		ui.Warnf("could not clear the readiness marker: %v", err)
	}

	return mgr.Restart()
}

// waitForAnchor waits until the supervisor has an anchor up, or says why not.
//
// Two signals, and having both is the point. The supervisor writes a readiness marker the
// instant the anchor is up, which a stat notices within a tick; the status call is the
// fallback, kept at one a second because it forks anchorctl and because it is the only
// thing that still works if a marker never arrives at all. systemd's Type=notify makes
// `systemctl restart` return only once the anchor is up, so on Linux the first call
// already succeeds; launchd, rc and the Windows SCM give no such signal.
func waitForAnchor(ctx context.Context, d paths.Dirs) (anchorctl.Status, error) {
	ctl, err := runCtl(d)
	if err != nil {
		return anchorctl.Status{}, err
	}

	// tick is how often the marker is looked for; fallback is how often anchorctl is
	// asked when it is not there.
	const (
		tick     = 100 * time.Millisecond
		fallback = time.Second
	)

	deadline := time.Now().Add(90 * time.Second)

	var (
		marked   bool
		nextPoll = time.Now()
	)

	for {
		// The marker only ever pulls the next status call forward, and only once. If it
		// appears and the call behind it fails anyway, the cadence stays at one a second
		// rather than becoming ten.
		if !marked && daemon.IsReady(d) {
			marked = true
			nextPoll = time.Now()
		}

		if !time.Now().Before(nextPoll) {
			nextPoll = time.Now().Add(fallback)

			// The token is rewritten by the supervisor on every start, so re-read it
			// rather than trusting the one runCtl picked up a moment ago.
			ctl.Token = readToken(d)

			st, err := ctl.Status(ctx)
			if err == nil && st.Running {
				return st, nil
			}
		}

		if time.Now().After(deadline) {
			return anchorctl.Status{}, fmt.Errorf(
				"the service started but no anchor came up within 90s.\n"+
					"  see what it said:  %s", journalHint())
		}

		select {
		case <-ctx.Done():
			return anchorctl.Status{}, ctx.Err()
		case <-time.After(tick):
		}
	}
}

// exitNote describes this machine's exit settings, or "" when it has neither.
func exitNote(cfg *config.Config) string {
	switch {
	case cfg.ServeExit && cfg.UseExit:
		return "serving a way out, and sending its own traffic over the overlay"
	case cfg.ServeExit:
		return "serving a way out to the public internet for the realm"
	case cfg.UseExit:
		return "sending this machine's internet traffic over the overlay"
	default:
		return ""
	}
}

// report is what a person sees when it worked.
func report(cfg *config.Config, st anchorctl.Status, verb string) {
	mgr, _ := service.New()

	ui.Println()
	ui.Field("anchor", st.ID)

	for _, a := range st.Overlay {
		ui.Field("overlay", a)
	}

	// anchor lists the IPv4 apart from the overlay addresses: it never reaches the
	// overlay, which carries it translated.
	if ip := cfg.OverlayIPv4(); ip != "" {
		ui.Field("ipv4", ip)
	}

	// Before the mode, because it is what the mode is running over, and because on
	// a link the absence of an underlay address is the surprising part: an anchor
	// here advertises no way to be reached, which is the truth about a cable.
	if cfg.Uplink != "" {
		ui.Field("uplink", cfg.Uplink+" — no socket bound, no address advertised")
	}

	if cfg.Mode == config.ModeTUN {
		ui.Field("interface", cfg.TUNInterface())
	} else {
		for _, p := range cfg.Proxies {
			ui.Field("serving", p)
		}
	}

	for _, s := range cfg.Subnets {
		ui.Field("forwarding", s)
	}

	// Said whenever it is true, never when it is false. conflux goes to some trouble
	// not to become an internet exit by accident, and a machine that is one should
	// not need a config file read to find out.
	if note := exitNote(cfg); note != "" {
		ui.Field("exit", note)
	}

	ui.Field("taint", joinTaints(cfg.Taints))

	if len(cfg.Peers) > 0 {
		ui.Field("peers", strings.Join(cfg.Peers, ", ")+" — overriding the enrolled list")
	}

	if !st.WorksUntil.IsZero() {
		ui.Field("credential", fmt.Sprintf("valid until %s (%s)",
			st.WorksUntil.Format(time.RFC3339), ui.Until(st.WorksUntil)))
	}

	if mgr != nil {
		ui.Field("service", mgr.Describe())
	}

	ui.Println()

	// Only after a command that just decided the taint. `install` is a restart of
	// something already configured, and telling somebody how to join a network they
	// are already on is noise. One --taint per name: the flag takes one, and a comma
	// inside one is refused.
	if verb == "up" || verb == "proxy" {
		ui.Printf("Reachable from any machine that runs:  conflux up --taint %s\n",
			strings.Join(cfg.Taints, " --taint "))
	}
}

// joinTaints is the taint set for a status line.
func joinTaints(t []string) string {
	if len(t) == 0 {
		return "(none)"
	}

	return strings.Join(t, ",")
}

// journalHint names where the supervisor's output is.
func journalHint() string {
	if mgr, err := service.New(); err == nil {
		return mgr.LogHint()
	}

	return "sudo conflux serve --foreground"
}
