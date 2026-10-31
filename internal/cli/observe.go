package cli

import (
	"context"
	"flag"
	"fmt"
	"runtime"
	"strings"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
)

// runObserve is conflux's observe, and anchorctl has one too.
//
// conflux's decides what the machine runs: the daemon's observer and no anchor, inventorying
// the cryptography of the host's own traffic -- which services it reaches, serves or passes
// on, over which protocols, and whether each key exchange is post-quantum -- and joining no
// realm, so with no enrolment, no credential and no taint. The observer runs until it is
// stopped and starts again at every boot; each record of a flow is sent to the collector the
// export names as it is made, and kept in the daemon's inventory whether or not one is.
// anchorctl's observe starts and stops the observer of a running daemon, and reports on it.
//
// The collision is resolved by shape, as conflux proxy's is: conflux observe takes its own
// flags and no argument, and every other dash-prefixed word -- anchorctl's -start, -stop,
// -socket -- is answered with where it belongs rather than guessed at. Bare, it is
// conflux's, which is the one shape that matters: an anchorctl user typing it for a report
// would stop an anchor this machine runs, so that switch is confirmed first.
func runObserve(ctx context.Context, args []string) int {
	f := newObserveFlags()

	if hint := f.anchorctls(args); hint != "" {
		ui.Errf("%s", hint)

		return ExitUsage
	}

	if err := f.fs.Parse(args); err != nil {
		return ExitUsage
	}

	if f.fs.NArg() > 0 {
		ui.Errf("conflux observe takes no arguments, and was given %q", f.fs.Args())

		return ExitUsage
	}

	// Before anything is asked or written: where anchor has no capture there is nothing
	// this command could start.
	if err := config.ObserverSupported(hostOS); err != nil {
		ui.Errf("%v", err)

		return ExitUsage
	}

	if err := needsRoot("registering the boot service", "observe", args); err != nil {
		return fail(err)
	}

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		return fail(err)
	}

	cfg, err := loadOrNew(d)
	if err != nil {
		return fail(err)
	}

	typed := typedFlags(f.fs)

	if err := chooseExport(cfg, typed, *f.export, *f.exportInsecure); err != nil {
		return fail(err)
	}

	if cfg.Anchor() && cfg.Mode != "" && !confirmObserving(d, cfg, *f.yes) {
		return ExitUsage
	}

	// What only an anchor in userspace serves, and the next `conflux proxy` names again; up
	// drops them the same way.
	if len(cfg.Proxies) > 0 {
		ui.Errf("the %d proxied service(s) this machine served are dropped: a reverse proxy is an anchor's,\n"+
			"  and this machine runs none. conflux proxy publishes them again.", len(cfg.Proxies))

		cfg.Proxies = nil
	}

	cfg.Mode = config.ModeObserve
	cfg.Observer = &config.Observer{Loopback: *f.loopback, HideNames: *f.hideNames}

	return bring(ctx, d, cfg, "observe", false)
}

// hostOS is the platform the observer's support is decided for: this one, outside a test of
// another's.
var hostOS = runtime.GOOS

// confirmObserving makes the switch from an anchor explicit before it happens: the anchor
// stops and this machine leaves its realm, though its identity and settings are kept for the
// next up or proxy. Asked at a terminal; off one, only --yes says so, so a script that meant
// anchorctl's report never stops an anchor.
func confirmObserving(d paths.Dirs, cfg *config.Config, yes bool) bool {
	if yes {
		return true
	}

	shape := "a network interface"
	if cfg.Mode == config.ModeProxy {
		shape = "userspace"
	}

	what := fmt.Sprintf("this machine runs an anchor (%s). Observing alone stops it: the machine leaves its realm\n"+
		"  until the next conflux up or proxy, which come back with the identity and settings kept.\n"+
		"  conflux up --observe or conflux proxy --observe observes beside the anchor instead,\n"+
		"  and conflux anchorctl observe reports on a running observer.", shape)

	if !ui.IsTerminal() {
		ui.Errf("%s\n  Pass --yes to say so explicitly; a scripted observe will not stop an anchor by default.", what)

		return false
	}

	ui.Printf("\n%s\n\n", strings.Replace(what, "this machine", "This machine", 1))

	return ui.Confirm("Stop the anchor and observe?")
}

// observeFlags is conflux observe's flag set, and the one list of what it takes, which the
// check that hands anchorctl's flags back reads.
type observeFlags struct {
	fs *flag.FlagSet

	loopback, hideNames, exportInsecure, yes *bool
	export                                   *string
}

func newObserveFlags() *observeFlags {
	fs := flag.NewFlagSet("observe", flag.ContinueOnError)
	fs.SetOutput(ui.Errw)

	f := &observeFlags{fs: fs}

	f.loopback = fs.Bool("loopback", false, "observe the loopback interfaces too; Windows' capture never sees them")
	f.hideNames = fs.Bool("hide-names", false,
		"leave the names flows were reached by -- a server name, a DNS answer's -- out of the records and the inventory")
	f.export = fs.String("export", "", exportUsage)
	f.exportInsecure = fs.Bool("export-insecure", false, exportInsecureUsage)
	f.yes = fs.Bool("yes", false, "stop the anchor this machine runs without asking: it leaves its realm, and keeps its identity and settings")

	fs.Usage = func() {
		ui.Printf("conflux observe — inventory the cryptography of this host's traffic, with no anchor\n\n" +
			"  conflux observe [--loopback] [--hide-names] [--export HOST:PORT [--export-insecure]] [--yes]\n\n" +
			"Runs the daemon's observer and nothing else. The host copies the start of every flow\n" +
			"its interfaces carry to it, and it records which services the host reaches, serves\n" +
			"or passes on, over which protocols, and whether each key exchange is post-quantum,\n" +
			"hybrid, classical or none, and which side held it back. It carries nothing, so it\n" +
			"can slow or break nothing, and it joins no realm: nothing is enrolled.\n\n" +
			"It runs until it is stopped, and from every boot. With --export, or an export with\n" +
			"flows in conflux.json, each record goes to that collector as it is made; either way\n" +
			"the daemon keeps an inventory of them, which conflux inventory prints.\n\n" +
			"On a machine running an anchor this stops it, and asks first. To observe beside an\n" +
			"anchor, conflux up --observe or conflux proxy --observe.\n\n")
		fs.PrintDefaults()
	}

	return f
}

// anchorctls returns what to say about the first dash-prefixed argument that is not one of
// conflux observe's own, or "".
func (f *observeFlags) anchorctls(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			continue
		}

		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if name == "h" || name == "help" || f.fs.Lookup(name) != nil {
			continue
		}

		switch name {
		case "start":
			return "-start is anchorctl's observe, which starts the observer of a running daemon until it next starts.\n\n" +
				"  conflux observe                  this machine observes, from now and from every boot\n" +
				"  conflux up --observe             ... beside an anchor with an interface\n" +
				"  conflux anchorctl observe -start anchorctl's own, uninterpreted"
		case "stop":
			return "-stop is anchorctl's observe, which stops the observer until the daemon next starts.\n\n" +
				"  conflux down                     stop everything now; a reboot brings it back\n" +
				"  conflux up --no-observe          keep the anchor, and stop observing for good\n" +
				"  conflux anchorctl observe -stop  anchorctl's own, uninterpreted"
		}

		return fmt.Sprintf("%q is not one of conflux observe's flags, which conflux observe -h lists.\n\n"+
			"  anchorctl's observe, which reports on the observer of a running daemon, is here:\n\n"+
			"    conflux anchorctl observe %s", a, strings.Join(args, " "))
	}

	return ""
}

// The export flags' help, shared by observe, up and proxy.
const (
	exportUsage = "send telemetry, and each record the observer makes, to the OTLP/gRPC collector at `HOST:PORT`; " +
		"conflux.json's export block keeps its headers and TLS settings"
	exportInsecureUsage = "reach the --export collector in plaintext rather than TLS"
)

// registerObserver adds the observer's flags to up and proxy, read through typedFlags.
func registerObserver(fs *flag.FlagSet) {
	fs.Bool("observe", false, "run the observer beside the anchor: an inventory of the cryptography of this host's traffic")
	fs.Bool("no-observe", false, "stop observing")
	fs.Bool("observe-loopback", false, "observe the loopback interfaces too; implies --observe")
	fs.Bool("observe-hide-names", false, "leave the names flows were reached by out of the records; implies --observe")
	fs.String("export", "", exportUsage)
	fs.Bool("export-insecure", false, exportInsecureUsage)
}

// chooseObserver resolves up's and proxy's observer flags against what is configured.
//
// Naming the observer at all -- --observe or either of its options -- says what it is now,
// as anchorctl's observe -start does: an option not given is off. Naming nothing keeps what
// is configured, which is how every re-run keeps its settings, and --no-observe is the way
// back.
func chooseObserver(cfg *config.Config, fs *flag.FlagSet) error {
	typed := typedFlags(fs)
	on := func(name string) bool { return typed[name] && fs.Lookup(name).Value.String() == "true" }

	named := typed["observe"] || typed["observe-loopback"] || typed["observe-hide-names"]

	switch {
	case named && typed["no-observe"]:
		return fmt.Errorf("--no-observe and --observe contradict each other")
	case typed["no-observe"]:
		cfg.Observer = nil
	case named:
		cfg.Observer = &config.Observer{Loopback: on("observe-loopback"), HideNames: on("observe-hide-names")}
	}

	if cfg.Observer != nil {
		if err := config.ObserverSupported(hostOS); err != nil {
			return err
		}
	}

	return chooseExport(cfg, typed, fs.Lookup("export").Value.String(), on("export-insecure"))
}

// chooseExport points the export at --export's collector, with flows -- each record the
// observer makes, and each the anchor's flows make -- and metrics on, keeping everything else
// conflux.json says of it: headers and TLS material, which are credentials and never taken
// on a command line, the other signals, the intervals.
func chooseExport(cfg *config.Config, typed map[string]bool, endpoint string, insecure bool) error {
	if !typed["export"] {
		if typed["export-insecure"] {
			return fmt.Errorf("--export-insecure says how to reach the collector --export names; give --export too")
		}

		return nil
	}

	e := config.Export{}
	if cfg.Export != nil {
		e = *cfg.Export
	}

	e.Enabled, e.Endpoint, e.Flows, e.Metrics = true, endpoint, true, true

	if typed["export-insecure"] {
		e.Insecure = insecure
	}

	if err := e.Validate(); err != nil {
		return fmt.Errorf("--export %s: %w", endpoint, err)
	}

	cfg.Export = &e

	return nil
}
