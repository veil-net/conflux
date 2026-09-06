// Package cli is conflux's command surface.
//
// Two surfaces in one binary. Conflux owns a short list of verbs, and every other
// argument vector is handed to the embedded anchorctl untouched -- not parsed, not
// rewritten, not validated. That is the whole design, and it is why there is no CLI
// framework here: the previous conflux used one, and a framework owns the entire
// argv and errors on flags it does not know, which is precisely what makes
// pass-through impossible.
package cli

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/veil-net/conflux/internal/ui"
)

// verb is one conflux command.
type verb struct {
	run     func(ctx context.Context, args []string) int
	summary string
	usage   string

	// hidden keeps a verb out of the help listing. Only `serve` is hidden: it is
	// the service manager's entry point and not something to run by hand.
	hidden bool
}

// verbs is the closed set of names conflux keeps for itself. Everything else
// reaches anchorctl.
//
// Three of these shadow an anchorctl command -- proxy, status and help -- and each
// resolves its own collision rather than guessing. See the comment on each.
func verbs() map[string]verb {
	return map[string]verb{
		"up":        {run: runUp, summary: "join the overlay with a network interface", usage: "conflux up [--taint T] [--ipv4 PREFIX | --no-ipv4] [--subnet CIDR]... [--uplink DEV | --no-uplink]"},
		"proxy":     {run: runProxy, summary: "publish a local service on the overlay, without an interface", usage: "conflux proxy PORT[/NETWORK]=BACKEND ... [--uplink DEV | --no-uplink]"},
		"down":      {run: runDown, summary: "stop the anchor now; a reboot brings it back", usage: "conflux down"},
		"install":   {run: runInstall, summary: "register the boot service", usage: "conflux install"},
		"uninstall": {run: runUninstall, summary: "remove the boot service, the configuration and the identity", usage: "conflux uninstall [--yes]"},
		"status":    {run: runStatus, summary: "what conflux and the anchor are doing", usage: "conflux status"},
		"version":   {run: runVersion, summary: "conflux's version, and the anchor build it carries", usage: "conflux version"},
		"help":      {run: runHelp, summary: "this, and anchorctl's usage beneath it", usage: "conflux help"},
		"anchorctl": {run: runEscapeHatch, summary: "run the embedded anchorctl with these arguments, uninterpreted", usage: "conflux anchorctl ARGS..."},
		"serve":     {runServe, "run the supervisor in the foreground", "conflux serve", true},
	}
}

// anchorLifecycleVerbs are anchorctl commands conflux refuses to pass through
// while it owns the configuration.
//
// Passing `start` through would build an anchor conflux does not know about, from
// arguments its config file does not describe, which the next reboot would silently
// replace. Passing `stop` through would stop one conflux believes is running. Both
// are reachable through the escape hatch by anyone who means it.
var anchorLifecycleVerbs = map[string]string{
	"start":   "up",
	"stop":    "down",
	"restart": "up",
}

// Main dispatches. It returns an exit code rather than calling os.Exit so that the
// tests can drive it.
func Main(argv []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(argv) < 2 {
		return runHelp(ctx, nil)
	}

	name, rest := argv[1], argv[2:]

	// Nothing is forwarded from the first position. "conflux -socket X status"
	// would otherwise be ambiguous with conflux's own status, and a rule that is
	// sometimes right is worse here than one that always explains itself.
	if strings.HasPrefix(name, "-") {
		switch name {
		case "-h", "--help", "-help":
			return runHelp(ctx, rest)
		case "-v", "--version", "-version":
			return runVersion(ctx, rest)
		default:
			ui.Errf("%q is not a conflux option.\n"+
				"  conflux help                  what conflux can do\n"+
				"  conflux anchorctl %s ...  pass it to anchorctl instead", name, name)

			return ExitUsage
		}
	}

	if v, ok := verbs()[name]; ok {
		return v.run(ctx, rest)
	}

	if replacement, refused := anchorLifecycleVerbs[name]; refused {
		return refuseLifecycle(name, replacement)
	}

	return passthrough(ctx, argv[1:])
}

// refuseLifecycle explains rather than obeys.
func refuseLifecycle(name, replacement string) int {
	ui.Errf("%q is anchorctl's, and conflux keeps the configuration this machine starts from.\n"+
		"  Running it directly would leave the two disagreeing about what is running.\n\n"+
		"  conflux %s\n"+
		"        the conflux command that does this, and records it\n\n"+
		"  conflux anchorctl %s ...\n"+
		"        anchorctl's own, if that is really what you want",
		name, replacement, name)

	return ExitUsage
}

// fail prints an error and picks an exit code from its kind.
func fail(err error) int {
	if err == nil {
		return ExitOK
	}

	ui.Errf("%v", err)

	switch {
	case errors.Is(err, errNotConfigured):
		return ExitNoConfig
	case errors.Is(err, errNotRunning):
		return ExitUnavailable
	case errors.Is(err, errNeedsRoot):
		return ExitDenied
	default:
		return ExitError
	}
}

var (
	errNotConfigured = errors.New("this machine has no conflux configuration")
	errNotRunning    = errors.New("nothing is running here")
	errNeedsRoot     = errors.New("this needs root")
)
