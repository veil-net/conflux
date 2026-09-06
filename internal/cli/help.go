package cli

import (
	"context"
	"os"
	"slices"
	"strings"

	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
	"github.com/veil-net/conflux/internal/version"
)

const overview = `conflux — put this machine on a VeilNet overlay

  conflux up                          join, with a network interface
  conflux proxy 8080=127.0.0.1:3000   publish a service, without one

The first command enrols this machine, starts it, and registers a boot service, so
a reboot brings it back with nothing typed. The second does the same without asking
the kernel for anything, which is what to use where you cannot get CAP_NET_ADMIN.
`

const collisions = `Two of conflux's names are also anchorctl's, and each is resolved rather than guessed:

  conflux status              conflux's, plus anchorctl's beneath it
  conflux status -watch 5s    anchorctl's, because it was given arguments
  conflux proxy PORT=BACKEND  conflux's: start in userspace mode, serving this
  conflux anchorctl proxy -add PORT=BACKEND
                              anchorctl's: add one to an anchor already running

start, stop and restart are anchorctl's and conflux refuses to pass them through
while it owns the configuration; use up and down, or the escape hatch above.
`

// runHelp prints conflux's own usage and then anchorctl's, so one page covers both
// surfaces and nobody has to know which binary a command belongs to.
func runHelp(ctx context.Context, args []string) int {
	// `conflux help <something>` most likely means a command's own help.
	if len(args) > 0 {
		if _, ours := verbs()[args[0]]; !ours {
			return passthrough(ctx, append([]string{"help"}, args...))
		}
	}

	ui.Printf("%s\n", overview)
	ui.Println("Commands")

	all := verbs()

	names := make([]string, 0, len(all))
	for name, v := range all {
		if !v.hidden {
			names = append(names, name)
		}
	}

	slices.Sort(names)

	for _, name := range names {
		ui.Printf("  %-10s %s\n", name, all[name].summary)
	}

	ui.Printf("\n%s", collisions)
	ui.Printf("\nAnything conflux does not recognise is passed to anchorctl unchanged:\n" +
		"peers, routes, events, metrics, send, inspect, keygen and the rest.\n")

	printAnchorctlUsage(ctx)

	return ExitOK
}

// printAnchorctlUsage appends the embedded anchorctl's own help, under a rule. Best
// effort: a machine where extraction fails still gets conflux's half.
func printAnchorctlUsage(ctx context.Context) {
	tools, err := libexec.Ensure(paths.Default())
	if err != nil {
		return
	}

	out, err := runQuiet(ctx, tools.Anchorctl, os.Environ(), []string{"help"})
	if err != nil && out == "" {
		return
	}

	ui.Printf("\n%s\n\n%s\n", strings.Repeat("─", 72), strings.TrimSpace(out))
}

// runVersion reports conflux and the anchor pair it carries. The digests are here
// so a bug report names the exact binaries, and so a user can check what they got
// against a release note without running it.
func runVersion(_ context.Context, _ []string) int {
	ui.Println(version.String())
	ui.Println(version.Anchor())

	return ExitOK
}
