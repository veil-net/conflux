// Package cli is conflux's command surface.
//
// Two surfaces in one binary. Conflux owns a short list of verbs, and every other
// argument vector is handed to the embedded anchorctl untouched -- not parsed, not
// rewritten, not validated. That is the whole design, and it is why there is no CLI
// framework here: a framework owns the entire argv and errors on flags it does not
// know, which is precisely what makes pass-through impossible.
package cli

import (
	"context"
	"crypto/fips140"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/ui"
)

// verb is one conflux command.
type verb struct {
	run     func(ctx context.Context, args []string) int
	summary string

	// hidden keeps a verb out of the help listing. Only `serve` is hidden: it is
	// the service manager's entry point and not something to run by hand.
	hidden bool
}

// verbs is the closed set of names conflux keeps for itself. Everything else
// reaches anchorctl.
//
// Five of them shadow an anchorctl command -- start, proxy, renew, status and observe --
// and each resolves its own collision rather than guessing. See the comment on
// each, and TestTheCollisionsAreTheDocumentedOnes, which reads the set off the
// embedded binary rather than leaving it to be counted by hand. help is anchorctl's
// too, and is not counted: anchorctl's only prints its usage, which conflux's prints
// whole beneath its own.
func verbs() map[string]verb {
	return map[string]verb{
		"up":        {run: runUp, summary: "join the overlay with a network interface"},
		"enrol":     {run: runEnrol, summary: "install a credential this machine was given, rather than drawing one"},
		"proxy":     {run: runProxy, summary: "publish a local service on the overlay, without an interface"},
		"observe":   {run: runObserve, summary: "inventory the cryptography of this host's traffic, with no anchor"},
		"start":     {run: runStart, summary: "start the anchor now, from the saved configuration"},
		"down":      {run: runDown, summary: "stop the anchor now; a reboot brings it back"},
		"renew":     {run: runRenew, summary: "install a fresh credential on the running anchor and observer, now"},
		"install":   {run: runInstall, summary: "register the boot service"},
		"uninstall": {run: runUninstall, summary: "remove the boot service, the configuration, the identity and conflux itself"},
		"status":    {run: runStatus, summary: "what conflux and the anchor are doing"},
		"version":   {run: runVersion, summary: "conflux's version, and the anchor build it carries"},
		"update":    {run: runUpdate, summary: "replace the installed conflux with the newest build of its channel"},
		"cert":      {run: runCert, summary: "make and check post-quantum keys, certificates and revocation lists"},
		"help":      {run: runHelp, summary: "this, and anchorctl's usage beneath it"},
		"anchorctl": {run: runEscapeHatch, summary: "run the embedded anchorctl with these arguments, uninterpreted"},
		"serve":     {run: runServe, summary: "run the supervisor in the foreground", hidden: true},
	}
}

// configureHint is how a machine is given a configuration, for every message that finds it
// has none: the three commands that decide what it runs.
const configureHint = "  conflux up                          join with a network interface\n" +
	"  conflux proxy 8080=127.0.0.1:3000   publish a port, no interface needed\n" +
	"  conflux observe                     inventory this host's traffic, with no anchor"

// anchorLifecycleVerbs are anchorctl commands conflux refuses to pass through
// while it owns the configuration, each mapped to the conflux verb that does it.
//
// Passing `stop` through would stop an anchor conflux believes is running, and
// `restart` would rebuild one from arguments its config file does not describe, which
// the next reboot would silently replace. `restart` names `start` rather than `up`,
// which re-decides the configuration and on a userspace machine drops the proxies.
// Both are reachable through the escape hatch by anyone who means it.
var anchorLifecycleVerbs = map[string]string{
	"stop":    "down",
	"restart": "start",
}

// Main dispatches. It returns an exit code rather than calling os.Exit so that the
// tests can drive it.
func Main(argv []string) int {
	if err := fipsRefusal(fips140.Version(), fips140.Enabled()); err != nil {
		ui.Errf("%v", err)

		return ExitChildFailed
	}

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
		switch {
		case helpFlag(name):
			return runHelp(ctx, rest)
		case name == "-v", name == "--version", name == "-version":
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

// fipsRefusal refuses a conflux built to run in FIPS 140-3 mode whose mode has been switched
// off, as anchord refuses one.
//
// A build against a frozen Go Cryptographic Module runs in the mode by default, and only a
// GODEBUG fips140=off turns it off. Running anyway would make every claim docs/security.md
// makes about this binary untrue while nothing on the machine said so, so every verb refuses,
// exiting 70: a service manager restarting into the same environment meets the same answer.
// A build against the toolchain's own tree ("latest") has nothing to refuse: OpenBSD's, which
// the module will not run on, and a plain `go build`.
func fipsRefusal(module string, enabled bool) error {
	if module == "latest" || enabled {
		return nil
	}

	return fmt.Errorf("this conflux is built against the Go Cryptographic Module %s to run in FIPS 140-3 mode,\n"+
		"  and GODEBUG has switched that mode off. Unset GODEBUG's fips140", module)
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

// verbFlags is the flag set of conflux NAME. Its usage, head and then the flags, goes whole to
// stdout where -h asked for it, and to stderr beneath a mistake: the flag package says what the
// mistake was, on the set's output, before it prints the usage, and -h it answers with the
// usage alone.
func verbFlags(name, head string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	out := new(flagOutput)
	fs.SetOutput(out)

	fs.Usage = func() {
		w := usageOut(out.mistake)

		fmt.Fprint(w, head)
		fs.SetOutput(w)
		fs.PrintDefaults()
		fs.SetOutput(out)
	}

	return fs
}

// usageOut is where a usage goes, a verb's or a list of commands: stdout where it was asked
// for, and stderr beneath a mistake, which leaves stdout to what the command was asked for.
func usageOut(mistake bool) io.Writer {
	if mistake {
		return ui.Errw
	}

	return ui.Out
}

// flagOutput is a verb's flag set's output: what the flag package says of a mistake, on stderr,
// and whether it has said one, which sends the usage after it there too.
type flagOutput struct{ mistake bool }

func (o *flagOutput) Write(p []byte) (int, error) {
	o.mistake = true

	return ui.Errw.Write(p)
}

// usageMistake prints fs's usage on stderr, for a mistake the flag package did not see: an
// argument too many or too few, or a flag the command cannot do without.
func usageMistake(fs *flag.FlagSet) {
	if out, ok := fs.Output().(*flagOutput); ok {
		out.mistake = true
	}

	fs.Usage()
}

// flagsAlone parses the arguments of a command that takes flags and nothing else, and says
// whether it may go on. An argument left over is a mistake, named on a line of its own with the
// usage beneath it, before anything is asked for or done: `sudo conflux up mynet`, its --taint forgotten, would
// otherwise join a network minted for it. Where it may not go on, exit is the command's status.
func flagsAlone(fs *flag.FlagSet, args []string) (exit int, ok bool) {
	if err := fs.Parse(args); err != nil {
		return usageExit(err), false
	}

	if fs.NArg() > 0 {
		ui.Errf("conflux %s takes no arguments, and got %q.\n", fs.Name(), fs.Arg(0))
		usageMistake(fs)

		return ExitUsage, false
	}

	return ExitOK, true
}

// flagName is the flag arg names, as a flag set reads it: the name after one dash or two, up to
// an "=" and its value. ok is false where arg is no flag's spelling, which a flag set never takes
// for a flag: a word with no dash, or a dash alone, is an argument; two dashes alone end its
// flags, and every word after them is an argument, whatever it looks like; three dashes, or an
// empty name, are bad syntax. The one reading for every verb that looks at its flags before its
// flag set does (start's and renew's anchorctlFlag, observe's anchorctls, proxy's lookup), each
// of which reads no further than the "--", so none of them names a flag the set would not.
func flagName(arg string) (name string, ok bool) {
	name, ok = strings.CutPrefix(arg, "-")
	if !ok {
		return "", false
	}

	name, _, _ = strings.Cut(strings.TrimPrefix(name, "-"), "=")

	return name, name != "" && name[0] != '-'
}

// helpFlag reports whether arg asks for a usage, as a flag set takes it: -h or -help, after one
// dash or two, with a value or without (flagName). The one answer for conflux itself, every verb
// that looks at its flags before its flag set does, the cert command lists, and a pass-through,
// so none of them reads --h, which anchorctl's flag sets answer as -h, as anything else.
func helpFlag(arg string) bool {
	name, ok := flagName(arg)

	return ok && (name == "h" || name == "help")
}

// usageExit is the exit for flags that did not parse: 0 for -h, which asked for the usage it
// was given, and 2 for a mistake.
func usageExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}

	return ExitUsage
}

// fail prints an error and picks an exit code from its kind.
func fail(err error) int {
	if err == nil {
		return ExitOK
	}

	ui.Errf("%v", err)

	if errors.As(err, new(denied)) {
		return ExitDenied
	}

	return ExitError
}

// denied is a verb refused for want of root or Administrator, which exits 13.
type denied struct{ error }

// needsRoot refuses a verb that needs privilege, naming the command to run again: this
// invocation, flags and all. What somebody copies out of the refusal is then what they
// typed, and not `conflux up` without the --taint that decided which network it joins.
func needsRoot(what, verb string, args []string) error {
	if err := privcheck.Require(what, typed("conflux", append([]string{verb}, args...)...)); err != nil {
		return denied{err}
	}

	return nil
}

// typed is a command as it would be typed again, each word quoted where it has to be.
func typed(name string, args ...string) string {
	words := []string{shellWord(name)}
	for _, a := range args {
		words = append(words, shellWord(a))
	}

	return strings.Join(words, " ")
}

// shellWord quotes a word for the shell the refusal will be pasted into, when it holds
// anything but the characters every shell reads literally.
func shellWord(w string) string {
	if w != "" && strings.Trim(w, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_%+=:./-") == "" {
		return w
	}

	// PowerShell, where an Administrator retries, doubles a quote; a POSIX shell closes
	// the quoting around one.
	if runtime.GOOS == "windows" {
		return "'" + strings.ReplaceAll(w, "'", "''") + "'"
	}

	return "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
}
