package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
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

	if err := restartService(); err != nil {
		return fail(err)
	}

	started, err := waitForAnchor(ctx, d)
	if err != nil {
		return fail(err)
	}

	report(d, cfg, started, verb)

	return ExitOK
}

// restartService hands the machine to the boot service rather than running an
// anchor from this process.
//
// One supervisor, whatever started it. A `conflux up` that ran its own daemon would
// leave two ideas of what is running -- the service manager's and ours -- and they
// would disagree the moment either changed.
func restartService() error {
	mgr, err := service.New()
	if err != nil {
		return err
	}

	return mgr.Restart()
}

// waitForAnchor polls until the supervisor has an anchor up, or says why not.
func waitForAnchor(ctx context.Context, d paths.Dirs) (anchorctl.Status, error) {
	ctl, err := runCtl(d)
	if err != nil {
		return anchorctl.Status{}, err
	}

	deadline := time.Now().Add(90 * time.Second)

	for {
		// The token is rewritten by the supervisor on every start, so re-read it
		// rather than trusting the one runCtl picked up a moment ago.
		if fresh, err := runCtl(d); err == nil {
			ctl = fresh
		}

		st, err := ctl.Status(ctx)
		if err == nil && st.Running {
			return st, nil
		}

		if time.Now().After(deadline) {
			return anchorctl.Status{}, fmt.Errorf(
				"the service started but no anchor came up within 90s.\n"+
					"  see what it said:  %s", journalHint())
		}

		select {
		case <-ctx.Done():
			return anchorctl.Status{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// report is what a person sees when it worked.
func report(d paths.Dirs, cfg *config.Config, st anchorctl.Status, verb string) {
	mgr, _ := service.New()

	ui.Println()
	ui.Field("anchor", st.ID)

	for _, a := range st.Overlay {
		ui.Field("overlay", a)
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

	ui.Field("taint", joinTaints(cfg.Taints))

	if !st.WorksUntil.IsZero() {
		ui.Field("credential", fmt.Sprintf("valid until %s (%s)",
			st.WorksUntil.Format(time.RFC3339), until(st.WorksUntil)))
	}

	if mgr != nil {
		ui.Field("service", mgr.Describe())
	}

	ui.Println()

	// Only after a command that just decided the taint. `install` is a restart of
	// something already configured, and telling somebody how to join a network they
	// are already on is noise.
	if verb == "up" || verb == "proxy" {
		ui.Printf("Reachable from any machine that runs:  conflux up --taint %s\n", joinTaints(cfg.Taints))
	}
}

func joinTaints(t []string) string {
	if len(t) == 0 {
		return "(none)"
	}

	out := t[0]
	for _, v := range t[1:] {
		out += "," + v
	}

	return out
}

func until(t time.Time) string {
	d := time.Until(t)
	if d < 0 {
		return "expired"
	}

	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24

	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}

	return fmt.Sprintf("%dh", hours)
}

// journalHint names where this platform keeps the supervisor's output.
func journalHint() string {
	switch runtimeOS() {
	case "linux":
		return "journalctl -u conflux -n 50"
	case "darwin":
		return "tail -n 50 /var/log/conflux.log"
	case "windows":
		return "Event Viewer, under Windows Logs > Application, source conflux"
	default:
		return "conflux serve --foreground"
	}
}
