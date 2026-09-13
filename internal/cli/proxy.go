package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/ui"
)

// runProxy is conflux's proxy, and anchorctl has one too.
//
// The collision is resolved by shape, and the ambiguous case is refused rather than
// guessed. conflux's takes positional PORT=BACKEND specs and one flag; anything else
// dash-prefixed gets an explanation and a non-zero exit. A "leading dash means
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

	if hint := unknownProxyFlag(args); hint != "" {
		ui.Errf("%q is not one of conflux proxy's flags.\n\n"+
			"  conflux proxy takes port specs, --taint and --peers:\n\n"+
			"    conflux proxy 8080=127.0.0.1:3000 --taint mynet\n\n"+
			"  anchorctl's proxy, which adds and removes proxies on a running anchor, is here:\n\n"+
			"    conflux anchorctl proxy %s", hint, strings.Join(args, " "))

		return ExitUsage
	}

	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(ui.Errw)

	var (
		taints repeated
		peers  repeated
	)

	noTaint := fs.Bool("no-taint", false, "join the realm's shared compartment instead of a private one")
	uplink := fs.String("uplink", "", "carry the mesh over a link rather than the host network, e.g. /dev/ttyUSB0:115200")
	noUplink := fs.Bool("no-uplink", false, "go back to the host's network on a machine configured for a link")
	noPeers := fs.Bool("no-peers", false, "forget the bootstrap list and go back to the one enrolment supplies")
	apiBase := fs.String("api", "", "enrolment API base URL")
	port := fs.Uint("port", 0, "UDP port to bind on every interface; omit to let the kernel pick one")
	lanDisco := fs.String("lan-discovery", "auto",
		"find peers on the networks this host is attached to: yes, no, or auto to let enrolment decide")

	// Read through typedFlags rather than by value; see the same block in up.go. The
	// two exit flags are absent on purpose: both need a host interface, which
	// userspace mode does not have.
	fs.Bool("no-port", false, "go back to letting the kernel pick the port")
	fs.Bool("low-latency", false, "carry frames on datagrams: no head-of-line blocking, and a lost frame stays lost")
	fs.Bool("no-low-latency", false, "go back to carrying frames on streams")

	fs.Var(&taints, "taint", "compartment label; repeat to carry more than one")
	fs.Var(&peers, "peers", "bootstrap entry as host:port; repeat for more. Enrolment supplies these, so this is an override")

	fs.Usage = func() {
		ui.Printf("conflux proxy — publish a local service on the overlay, without an interface\n\n" +
			"  conflux proxy PORT[/NETWORK]=BACKEND ... [--taint T] [--uplink DEV | --no-uplink]\n" +
			"                [--peers HOST:PORT | --no-peers]\n\n" +
			"Runs the anchor entirely in userspace, so it needs no TUN device and no\n" +
			"CAP_NET_ADMIN. Nothing on this host can see the overlay; the only way in is a\n" +
			"service named here.\n\n" +
			"With --uplink the realm is reached over a link rather than the host's network,\n" +
			"which is the pair a machine with neither privilege nor an IP network needs.\n\n")
		fs.PrintDefaults()
	}

	specs, flags := splitPositional(args)

	if err := fs.Parse(flags); err != nil {
		return ExitUsage
	}

	specs = append(specs, fs.Args()...)

	if len(specs) == 0 {
		ui.Errf("no port specs given; conflux proxy needs at least one, like 8080=127.0.0.1:3000")

		return ExitUsage
	}

	parsed := make([]string, 0, len(specs))

	seen := map[string]bool{}

	for _, s := range specs {
		spec, err := config.ParseProxySpec(s)
		if err != nil {
			return fail(err)
		}

		key := fmt.Sprintf("%d/%s", spec.Port, spec.Network)
		if seen[key] {
			return fail(fmt.Errorf("overlay port %s is given twice", key))
		}

		seen[key] = true

		parsed = append(parsed, spec.String())
	}

	// Registering the boot service needs root even though userspace mode itself
	// needs nothing, and a proxy that vanishes at the next reboot is not what
	// anyone asked for.
	if err := privcheck.Require("registering the boot service", "conflux proxy "+strings.Join(specs, " ")); err != nil {
		return fail(fmt.Errorf("%w: %w", errNeedsRoot, err))
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
	if err := chooseTuning(cfg, typedFlags(fs), *port, *lanDisco, false); err != nil {
		return fail(err)
	}

	if cfg.Mode == config.ModeTUN {
		ui.Warnf("this machine was running in TUN mode with interface %s.\n"+
			"  Userspace mode replaces that: one daemon holds one anchor, and an anchor with\n"+
			"  a host interface cannot also serve a reverse proxy -- with a TUN the kernel owns\n"+
			"  the overlay address, so a service binds it directly and needs no proxy.",
			cfg.TUNInterface())

		cfg.Subnets = nil
		cfg.IPv4 = ""

		// Both exits need a host interface. Left set they would strand Validate on a
		// setting the operator cannot see and did not type on this run.
		cfg.ServeExit = false
		cfg.UseExit = false
	}

	cfg.Mode = config.ModeProxy
	cfg.Proxies = parsed

	if *apiBase != "" {
		cfg.APIBaseURL = *apiBase
	}

	if err := chooseUplink(cfg, *uplink, *noUplink); err != nil {
		return fail(err)
	}

	if err := choosePeers(cfg, peers, *noPeers); err != nil {
		return fail(err)
	}

	if err := chooseTaints(cfg, taints, *noTaint); err != nil {
		return fail(err)
	}

	return bring(ctx, d, cfg, "proxy")
}

// unknownProxyFlag returns the first dash-prefixed argument that is not one of
// conflux proxy's own, or "".
func unknownProxyFlag(args []string) string {
	ours := map[string]bool{
		"-taint": true, "--taint": true,
		"-no-taint": true, "--no-taint": true,
		"-api": true, "--api": true,
		"-uplink": true, "--uplink": true,
		"-no-uplink": true, "--no-uplink": true,
		"-peers": true, "--peers": true,
		"-no-peers": true, "--no-peers": true,
		"-port": true, "--port": true,
		"-no-port": true, "--no-port": true,
		"-low-latency": true, "--low-latency": true,
		"-no-low-latency": true, "--no-low-latency": true,
		"-lan-discovery": true, "--lan-discovery": true,
		"-h": true, "--help": true, "-help": true,
	}

	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			continue
		}

		name := a
		if i := strings.IndexByte(a, '='); i >= 0 {
			name = a[:i]
		}

		if !ours[name] {
			return a
		}
	}

	return ""
}

// splitPositional separates the specs from the flags, so that they may be written in
// any order -- `conflux proxy --taint x 8080=…` and the reverse both work, which
// Go's flag package on its own does not allow.
func splitPositional(args []string) (positional, flags []string) {
	expectValue := false

	for _, a := range args {
		switch {
		case expectValue:
			flags = append(flags, a)
			expectValue = false
		case strings.HasPrefix(a, "-"):
			flags = append(flags, a)
			// A flag written as -taint value, rather than -taint=value, takes the
			// next argument with it.
			if !strings.Contains(a, "=") && takesValue(a) {
				expectValue = true
			}
		default:
			positional = append(positional, a)
		}
	}

	return positional, flags
}

// takesValue reports whether a flag written as `-flag value` swallows the argument
// after it. Only conflux proxy's own value-taking flags are here; --no-taint,
// --no-uplink and --low-latency are booleans and take nothing.
//
// --lan-discovery is here rather than with the booleans because it is a tristate
// written as a value: missing it would read `conflux proxy --lan-discovery no
// 8080=127.0.0.1:3000` as a proxy spec called "no".
func takesValue(arg string) bool {
	switch strings.TrimLeft(arg, "-") {
	case "taint", "api", "uplink", "peers", "port", "lan-discovery":
		return true
	default:
		return false
	}
}
