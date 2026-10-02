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

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/paths"
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
	if hint := anchorctlFlag(args); hint != "" {
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

	if err := needsRoot("renewing this machine's credential", "renew", args); err != nil {
		return fail(err)
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
			"  conflux start     start from the configuration this machine already has\n\n"+
			"  The next start renews on its own, so a machine that is meant to be down needs\n"+
			"  nothing done here.\n\n"+
			"  (the control socket would be %s)", d.Socket())

		return ExitUnavailable
	}

	ctl, err := runCtl(d)
	if err != nil {
		return fail(err)
	}

	if ctl.Token == "" {
		return fail(fmt.Errorf("could not read %s, which anchorctl authenticates with", d.TokenFile()))
	}

	// Only for the line it prints: RenewNow reads the state again, under the lock.
	before, err := config.LoadState(d)
	if err != nil {
		return fail(err)
	}

	// Unavailable rather than an error, like a machine that never enrolled: nothing went
	// wrong, there is just nothing here this verb can do.
	if err := daemon.RenewNow(ctx, d, ctl, reporter{}); errors.Is(err, enrol.ErrDoesNotRenew) {
		ui.Errf("%v", err)

		return ExitUnavailable
	} else if err != nil {
		return fail(err)
	}

	if !before.NotAfter.IsZero() {
		ui.Field("was", fmt.Sprintf("valid until %s (%s)",
			before.NotAfter.Format(time.RFC3339), ui.Until(before.NotAfter)))
	}

	return ExitOK
}

// anchorctlFlag reports the first flag that must belong to anchorctl's version of a
// shadowed verb rather than conflux's, which takes none.
//
// Shared by renew and start, which resolve their collisions the same way and for the
// same reason: conflux's takes no arguments at all, so a flag is the signal, and -h
// is the one that means the caller wants conflux's own usage.
func anchorctlFlag(args []string) string {
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
