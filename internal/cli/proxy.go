package cli

import (
	"context"
	"flag"
	"strings"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
)

// runProxy is conflux's proxy, and anchorctl has one too.
//
// The collision is resolved by shape, and the ambiguous case is refused rather than
// guessed. conflux's takes positional PORT=BACKEND specs and its own flags; anything
// else dash-prefixed gets an explanation and a non-zero exit. A "leading dash means
// anchorctl" heuristic was considered and rejected: --taint leads with a dash too,
// and Go's flag package treats -x and --x identically, so the double dash carries no
// signal. A rule that is sometimes right is worse here than one that always explains
// itself.
func runProxy(ctx context.Context, args []string) int {
	if len(args) == 0 {
		ui.Errf("conflux proxy publishes a local service on the overlay, and needs at least one spec:\n\n" +
			"    conflux proxy 8080=127.0.0.1:3000\n" +
			"    conflux proxy 8080=127.0.0.1:3000 53/udp=127.0.0.1:53\n\n" +
			"  To list or change the proxies on an anchor that is already running, that is\n" +
			"  anchorctl's proxy, and it is one word away:\n\n" +
			"    conflux anchorctl proxy\n" +
			"    conflux anchorctl proxy -add 8080=127.0.0.1:3000")

		return ExitUsage
	}

	f := newProxyFlags()

	if hint := f.unknown(args); hint != "" {
		ui.Errf("%q is not one of conflux proxy's flags.\n\n"+
			"  conflux proxy takes port specs and the flags in conflux proxy -h:\n\n"+
			"    conflux proxy 8080=127.0.0.1:3000 --taint mynet\n\n"+
			"  anchorctl's proxy, which adds and removes proxies on a running anchor, is here:\n\n"+
			"    conflux anchorctl proxy %s", hint, strings.Join(args, " "))

		return ExitUsage
	}

	specs, flags := f.split(args)

	if err := f.fs.Parse(flags); err != nil {
		return ExitUsage
	}

	specs = append(specs, f.fs.Args()...)

	if len(specs) == 0 {
		ui.Errf("no port specs given; conflux proxy needs at least one, like 8080=127.0.0.1:3000")

		return ExitUsage
	}

	specsParsed, err := config.ValidateProxies(specs)
	if err != nil {
		return fail(err)
	}

	parsed := make([]string, len(specsParsed))
	for i, spec := range specsParsed {
		parsed[i] = spec.String()
	}

	// Registering the boot service needs root even though userspace mode itself
	// needs nothing, and a proxy that vanishes at the next reboot is not what
	// anyone asked for.
	if err := needsRoot("registering the boot service", "proxy", args); err != nil {
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

	// Before the warning below; see the same move in up.go.
	if err := chooseTuning(cfg, typedFlags(f.fs), *f.port, *f.lanDisco, false); err != nil {
		return fail(err)
	}

	if cfg.Mode == config.ModeTUN {
		ui.Warnf("this machine was running in TUN mode with interface %s.\n"+
			"  Userspace mode replaces that: one daemon holds one anchor, and an anchor with\n"+
			"  a host interface cannot also serve a reverse proxy -- with a TUN the kernel owns\n"+
			"  the overlay address, so a service binds it directly and needs no proxy.",
			cfg.TUNInterface())

		// What the interface was for goes with it: subnets and a served exit need one,
		// and anchor refuses them without. The IPv4 is the machine's and stays.
		cfg.Subnets = nil
		cfg.ServeExit = false
		cfg.UseExit = false
	}

	cfg.Mode = config.ModeProxy
	cfg.Proxies = parsed

	if *f.apiBase != "" {
		cfg.APIBaseURL = *f.apiBase
	}

	if err := chooseUplink(cfg, *f.uplink, *f.noUplink); err != nil {
		return fail(err)
	}

	if err := chooseIPv4(cfg, *f.ipv4, *f.noIPv4); err != nil {
		return fail(err)
	}

	if err := choosePeers(cfg, f.peers, *f.noPeers); err != nil {
		return fail(err)
	}

	if err := chooseTaints(cfg, f.taints); err != nil {
		return fail(err)
	}

	return bring(ctx, d, cfg, "proxy")
}

// proxyFlags is conflux proxy's flag set, and the one list of what it takes: the
// check that hands anchorctl's flags back and the splitter that lets specs and flags
// come in any order both read it, rather than each keeping a copy to drift from it.
type proxyFlags struct {
	fs *flag.FlagSet

	taints, peers                   repeated
	ipv4, uplink, apiBase, lanDisco *string
	noIPv4, noUplink, noPeers       *bool
	port                            *uint
}

func newProxyFlags() *proxyFlags {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(ui.Errw)

	f := &proxyFlags{fs: fs}

	f.ipv4 = fs.String("ipv4", "", ipv4Usage)
	f.noIPv4 = fs.Bool("no-ipv4", false, noIPv4Usage)
	f.uplink = fs.String("uplink", "", "carry the mesh over a link rather than the host network, e.g. /dev/ttyUSB0:115200")
	f.noUplink = fs.Bool("no-uplink", false, "go back to the host's network on a machine configured for a link")
	f.noPeers = fs.Bool("no-peers", false, "forget the bootstrap list and go back to the one enrolment supplies")
	f.apiBase = fs.String("api", "", "enrolment API base URL")
	f.port = fs.Uint("port", 0, "UDP port to bind on every interface; omit to let the kernel pick one")
	f.lanDisco = fs.String("lan-discovery", "auto",
		"find peers on the networks this host is attached to: yes, no, or auto to let enrolment decide")

	// Read through typedFlags rather than by value; see the same block in up.go. The
	// two exit flags are absent on purpose: exits are what an interface is for, and
	// this verb is the one without.
	fs.Bool("no-port", false, "go back to letting the kernel pick the port")
	fs.Bool("low-latency", false, "carry frames on datagrams: no head-of-line blocking, and a lost frame stays lost")
	fs.Bool("no-low-latency", false, "go back to carrying frames on streams")

	fs.Var(&f.taints, "taint", "compartment label; repeat to carry more than one")
	fs.Var(&f.peers, "peers", "bootstrap entry as host:port; repeat for more. Enrolment supplies these, so this is an override")

	fs.Usage = func() {
		ui.Printf("conflux proxy — publish a local service on the overlay, without an interface\n\n" +
			"  conflux proxy PORT[/NETWORK]=BACKEND ... [--taint T] [--ipv4 ADDRESS | --no-ipv4]\n" +
			"                [--uplink DEV | --no-uplink] [--peers HOST:PORT | --no-peers]\n\n" +
			"Runs the anchor entirely in userspace, so it needs no TUN device and no\n" +
			"CAP_NET_ADMIN. Nothing on this host can see the overlay; the only way in is a\n" +
			"service named here.\n\n" +
			"With --uplink the realm is reached over a link rather than the host's network,\n" +
			"which is the pair a machine with neither privilege nor an IP network needs.\n\n")
		fs.PrintDefaults()
	}

	return f
}

// lookup finds the flag a dash-prefixed argument names, in any spelling Go's flag
// package accepts. help is true for -h and -help, which the package answers without
// their being registered.
func (f *proxyFlags) lookup(arg string) (fl *flag.Flag, help bool) {
	name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
	if name == "h" || name == "help" {
		return nil, true
	}

	return f.fs.Lookup(name), false
}

// unknown returns the first dash-prefixed argument that is not one of conflux proxy's
// own, or "".
func (f *proxyFlags) unknown(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			continue
		}

		if fl, help := f.lookup(a); fl == nil && !help {
			return a
		}
	}

	return ""
}

// split separates the specs from the flags, so that they may be written in any order
// -- `conflux proxy --taint x 8080=…` and the reverse both work, which Go's flag
// package on its own does not allow.
//
// A flag written as -taint value, rather than -taint=value, takes the next argument
// with it unless it is a boolean. --lan-discovery is a tristate written as a value, so
// `conflux proxy --lan-discovery no 8080=127.0.0.1:3000` has one spec and not two.
func (f *proxyFlags) split(args []string) (positional, flags []string) {
	expectValue := false

	for _, a := range args {
		switch {
		case expectValue:
			flags = append(flags, a)
			expectValue = false
		case strings.HasPrefix(a, "-"):
			flags = append(flags, a)

			if fl, _ := f.lookup(a); fl != nil && !strings.Contains(a, "=") && !isBoolFlag(fl) {
				expectValue = true
			}
		default:
			positional = append(positional, a)
		}
	}

	return positional, flags
}

// isBoolFlag is how the flag package itself tells a flag that takes no value.
func isBoolFlag(fl *flag.Flag) bool {
	b, ok := fl.Value.(interface{ IsBoolFlag() bool })

	return ok && b.IsBoolFlag()
}
