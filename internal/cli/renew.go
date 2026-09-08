package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/ui"
)

// runRenew fetches a fresh credential now and installs it on the running anchor.
//
// Renewal is otherwise automatic in two places -- once on every start, and on a
// timer at two thirds of the credential's life -- and neither is reachable by hand.
// That is fine until it is not: a machine whose renewals have been failing shows
// "renewal: failing since ..." in conflux status and offers nothing to do about it
// but restart the service, which costs every session the anchor is holding for a
// swap that needs none of them. This is that swap, on demand.
//
// It does not enrol. A machine with no manifest has nothing to renew, and inventing
// an identity for it here would silently replace the one a reboot expects.
func runRenew(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("renew", flag.ContinueOnError)
	fs.SetOutput(ui.Errw)

	fs.Usage = func() {
		ui.Printf("conflux renew — install a fresh credential on the running anchor\n\n" +
			"  conflux renew\n\n" +
			"Renewal is automatic: once at every start, and again on a timer at two thirds\n" +
			"of the credential's life. This forces one now, which is what a machine whose\n" +
			"renewals have been failing needs.\n\n" +
			"The swap is hot. The identity does not change and no session is dropped, so\n" +
			"this is not a restart and does not need to be treated as one.\n\n")
		fs.PrintDefaults()
	}

	// anchorctl has a renew of its own, and it is the one that takes -cred: it
	// installs a credential the caller already holds. conflux's fetches one first,
	// which is the whole difference and the reason it takes no arguments. Resolve
	// by shape, the way proxy does, rather than shadowing anchorctl's outright.
	if hint := anchorctlRenewFlag(args); hint != "" {
		ui.Errf("%q is anchorctl's renew, not conflux's.\n\n"+
			"  conflux renew fetches a fresh credential from the enrolment API and installs it:\n\n"+
			"    conflux renew\n\n"+
			"  To install a credential you already hold, that is anchorctl's, one word away:\n\n"+
			"    conflux anchorctl renew %s", hint, strings.Join(args, " "))

		return ExitUsage
	}

	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	if fs.NArg() > 0 {
		ui.Errf("conflux renew takes no arguments, and got %q.\n\n"+
			"  conflux renew", fs.Arg(0))

		return ExitUsage
	}

	if err := privcheck.Require("renewing this machine's credential", "conflux renew"); err != nil {
		return fail(fmt.Errorf("%w: %w", errNeedsRoot, err))
	}

	return renewNow(ctx, paths.Default())
}

// renewNow is the body, split out so the test can drive it against a temporary
// CONFLUX_DIR without going through privcheck.
func renewNow(ctx context.Context, d paths.Dirs) int {
	if _, err := config.Load(d); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			ui.Errf("this machine has never been configured, so there is no credential to renew.\n\n" +
				"  conflux up                          join with a network interface\n" +
				"  conflux proxy 8080=127.0.0.1:3000   publish a port, no interface needed")

			return ExitUnavailable
		}

		return fail(err)
	}

	// Renewal is a hot swap into a running anchor, so "nothing is running" is the
	// likely failure and deserves conflux's own answer rather than a dial error.
	if _, err := os.Stat(d.Socket()); errors.Is(err, fs.ErrNotExist) {
		ui.Errf("nothing is running here, and a credential is installed into a running anchor.\n\n"+
			"  conflux install   start from the configuration this machine already has\n\n"+
			"  The next start renews on its own, so a machine that is meant to be down needs\n"+
			"  nothing done here.\n\n"+
			"  (the control socket would be %s)", d.Socket())

		return ExitUnavailable
	}

	tools, err := libexec.Ensure(d)
	if err != nil {
		return fail(err)
	}

	token, err := os.ReadFile(d.TokenFile())
	if err != nil {
		return fail(fmt.Errorf("read %s, which anchorctl authenticates with: %w", d.TokenFile(), err))
	}

	ctl := &anchorctl.Ctl{
		Bin:    tools.Anchorctl,
		Socket: d.Socket(),
		Token:  strings.TrimSpace(string(token)),
		SetID:  tools.SetID,
	}

	before, _ := config.LoadState(d)

	if err := daemon.RenewNow(ctx, d, ctl, reporter{}); err != nil {
		return fail(err)
	}

	if !before.NotAfter.IsZero() {
		ui.Field("was", fmt.Sprintf("valid until %s (%s)",
			before.NotAfter.Format(time.RFC3339), until(before.NotAfter)))
	}

	return ExitOK
}

// anchorctlRenewFlag reports the first flag that belongs to anchorctl's renew and
// not to conflux's, which takes none.
func anchorctlRenewFlag(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			continue
		}

		switch name, _, _ := strings.Cut(a, "="); name {
		case "-h", "--help", "-help":
			continue
		default:
			return name
		}
	}

	return ""
}
