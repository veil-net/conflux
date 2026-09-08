package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/taint"
	"github.com/veil-net/conflux/internal/ui"
)

// repeated collects a flag given more than once.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

func runUp(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(ui.Errw)

	var (
		taints   repeated
		subnets  repeated
		ipv4     = fs.String("ipv4", "", "overlay IPv4 as a prefix, e.g. 10.128.0.7/24")
		noIPv4   = fs.Bool("no-ipv4", false, "do not assign an overlay IPv4; the v6 address is derived anyway")
		noTaint  = fs.Bool("no-taint", false, "join the realm's shared compartment instead of a private one")
		tunName  = fs.String("interface", "", "name for the network interface (default anchor0)")
		uplink   = fs.String("uplink", "", "carry the mesh over a link rather than the host network, e.g. /dev/ttyUSB0:115200")
		noUplink = fs.Bool("no-uplink", false, "go back to the host's network on a machine configured for a link")
		noPeers  = fs.Bool("no-peers", false, "forget the bootstrap list and go back to the one enrolment supplies")
		apiBase  = fs.String("api", "", "enrolment API base URL")
		port     = fs.Uint("port", 0, "UDP port to bind on every interface; omit to let the kernel pick one")
		peers    repeated
	)

	// Registered for the flag package and read through typedFlags, not through these
	// values: what matters is whether they were written, not what they default to.
	fs.Bool("no-port", false, "go back to letting the kernel pick the port")
	fs.Bool("low-latency", false, "carry frames on datagrams: no head-of-line blocking, and a lost frame stays lost")
	fs.Bool("no-low-latency", false, "go back to carrying frames on streams")
	fs.Bool("serve-exit", false, "offer this machine as a way out to the public internet")
	fs.Bool("no-serve-exit", false, "stop offering a way out")
	fs.Bool("use-exit", false, "send this machine's own internet traffic over the overlay")
	fs.Bool("no-use-exit", false, "send this machine's internet traffic the ordinary way")

	fs.Var(&taints, "taint", "compartment label; repeat to carry more than one")
	fs.Var(&subnets, "subnet", "a network this machine forwards for the realm; repeat for more")
	fs.Var(&peers, "peers", "bootstrap entry as host:port; repeat for more. Enrolment supplies these, so this is an override")

	fs.Usage = func() {
		ui.Printf("conflux up — join the overlay with a network interface\n\n" +
			"  conflux up [--taint T] [--ipv4 PREFIX | --no-ipv4] [--subnet CIDR]...\n" +
			"             [--uplink DEV | --no-uplink] [--peers HOST:PORT | --no-peers]\n\n" +
			"Enrols this machine if it has never been, starts an anchor in TUN mode, writes\n" +
			"the configuration, and registers the boot service so a reboot needs nothing.\n\n" +
			"With --uplink the realm is reached over a link rather than the host's network:\n" +
			"no socket is bound and no address is advertised. Enrolment still goes over the\n" +
			"internet, so enrol this machine while it has one.\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	if err := privcheck.Require("bringing up a network interface", "conflux up"); err != nil {
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

	// Before the warning below, because a flag that is going to be refused should be
	// refused before this machine is told its proxies are being replaced. The
	// announcement is not a lie -- nothing is saved until bring -- but reading
	// "replaces that" and then an error is a worse way to learn you typo'd a port.
	if err := chooseTuning(cfg, typedFlags(fs), *port, true); err != nil {
		return fail(err)
	}

	// Switching a proxy machine to TUN is a real change of shape, not an edit.
	if cfg.Mode == config.ModeProxy && len(cfg.Proxies) > 0 {
		ui.Warnf("this machine was serving %d proxied service(s) in userspace mode.\n"+
			"  Bringing up a network interface replaces that: one daemon holds one anchor,\n"+
			"  and an anchor with an interface cannot also serve a reverse proxy.",
			len(cfg.Proxies))

		cfg.Proxies = nil
	}

	cfg.Mode = config.ModeTUN

	if *tunName != "" {
		cfg.TUNName = *tunName
	}

	if err := chooseUplink(cfg, *uplink, *noUplink); err != nil {
		return fail(err)
	}

	if err := choosePeers(cfg, peers, *noPeers); err != nil {
		return fail(err)
	}

	if *apiBase != "" {
		cfg.APIBaseURL = *apiBase
	}

	if len(subnets) > 0 {
		cfg.Subnets = subnets
	}

	address, err := chooseIPv4(cfg, *ipv4, *noIPv4)
	if err != nil {
		return fail(err)
	}

	cfg.IPv4 = address

	if err := chooseTaints(cfg, taints, *noTaint); err != nil {
		return fail(err)
	}

	return bring(ctx, d, cfg, "up")
}

// typedFlags records which flags were actually written, rather than which have a
// non-zero value.
//
// The distinction is the whole of how a persisted setting is kept: `--port 0` and no
// --port at all are the same value and opposite instructions, and a boolean that
// defaults false cannot say "leave it alone" by its value either. anchorctl draws the
// same line with fs.Visit, for the same reason.
func typedFlags(fs *flag.FlagSet) map[string]bool {
	typed := map[string]bool{}

	fs.Visit(func(f *flag.Flag) { typed[f.Name] = true })

	return typed
}

// chooseToggle resolves a --x / --no-x pair against what is already configured.
//
// Every persisted answer needs a way back, which is what the negation is for: a
// machine configured once with --low-latency cannot be talked out of it by omitting
// the flag, because omitting it is how every other re-run keeps its settings.
func chooseToggle(name string, typed map[string]bool, current bool) (bool, error) {
	on, off := typed[name], typed["no-"+name]

	switch {
	case on && off:
		return false, fmt.Errorf("--%s and --no-%s contradict each other", name, name)
	case on:
		return true, nil
	case off:
		return false, nil
	default:
		return current, nil
	}
}

// choosePort decides the UDP port, keeping a persisted one when no flag names one.
func choosePort(cfg *config.Config, typed map[string]bool, value uint) error {
	on, off := typed["port"], typed["no-port"]

	switch {
	case on && off:
		return fmt.Errorf("--port and --no-port contradict each other")
	case off:
		cfg.Port = 0
	case on:
		// Zero is the kernel's choice rather than a port, so it cannot be asked for
		// by number without the request being ambiguous with not asking at all.
		if value == 0 || value > 65535 {
			return fmt.Errorf(
				"--port %d is not a port: it must be 1-65535, and --no-port is how to go back to letting the kernel pick one",
				value)
		}

		cfg.Port = uint16(value)
	}

	return nil
}

// chooseTuning applies the settings that are neither the mode nor the medium.
//
// exits is false on proxy, where the two exit flags are not registered at all: both
// need a host interface, so offering them on the verb that has none would be offering
// a setting whose only outcome is a refusal.
func chooseTuning(cfg *config.Config, typed map[string]bool, port uint, exits bool) error {
	if err := choosePort(cfg, typed, port); err != nil {
		return err
	}

	lowLatency, err := chooseToggle("low-latency", typed, cfg.LowLatency)
	if err != nil {
		return err
	}

	cfg.LowLatency = lowLatency

	if !exits {
		return nil
	}

	if cfg.ServeExit, err = chooseToggle("serve-exit", typed, cfg.ServeExit); err != nil {
		return err
	}

	if cfg.UseExit, err = chooseToggle("use-exit", typed, cfg.UseExit); err != nil {
		return err
	}

	return nil
}

// loadOrNew reads the existing configuration, or starts a fresh one.
func loadOrNew(d paths.Dirs) (*config.Config, error) {
	cfg, err := config.Load(d)
	if err == nil {
		return cfg, nil
	}

	if errors.Is(err, os.ErrNotExist) {
		return &config.Config{}, nil
	}

	return nil, err
}

// chooseIPv4 decides the overlay address, prompting only when it has to.
//
// The prompt appears at most once in a machine's life. Re-running `conflux up` with
// an existing configuration and no flag keeps what is there and asks nothing:
// changing a machine's overlay address because somebody re-ran a command is not an
// acceptable thing to do to them.
func chooseIPv4(cfg *config.Config, flagValue string, none bool) (string, error) {
	switch {
	case none:
		return "", nil

	case flagValue != "":
		if _, err := config.ParseOverlayIPv4(flagValue); err != nil {
			return "", err
		}

		return flagValue, nil

	case cfg.IPv4 != "":
		return cfg.IPv4, nil
	}

	if !ui.IsTerminal() {
		return "", errors.New(
			"conflux up needs --ipv4 PREFIX or --no-ipv4 when there is no terminal to ask at")
	}

	return promptIPv4()
}

func promptIPv4() (string, error) {
	ui.Println("An overlay IPv4 lets other machines reach this one by a v4 address.")
	ui.Println("Everyone on your network picks the same prefix and a different host part.")
	ui.Println("The IPv6 address is derived from this machine's identity and needs no answer.")
	ui.Println()

	for {
		answer, err := ui.Ask("  Overlay IPv4 [e.g. 10.128.0.7/24, blank for IPv6-only]: ")
		if err != nil {
			if errors.Is(err, io.EOF) {
				ui.Println()

				return "", nil
			}

			return "", err
		}

		if answer == "" {
			ui.Println("  IPv6-only. Peers reach this machine by its overlay IPv6 address.")
			ui.Println()

			return "", nil
		}

		if _, err := config.ParseOverlayIPv4(answer); err != nil {
			ui.Printf("  %v\n\n", err)

			continue
		}

		ui.Println()

		return answer, nil
	}
}

// chooseUplink decides what layer 1 runs over.
//
// The same rule the overlay address follows: a flag decides, and no flag keeps
// whatever the configuration already says. A machine on a cable that is re-brought
// up without --uplink stays on the cable, because the alternative is a command that
// silently moves a machine onto a network it may not have.
func chooseUplink(cfg *config.Config, flagValue string, none bool) error {
	switch {
	case none && flagValue != "":
		return errors.New("--uplink and --no-uplink contradict each other")

	case none:
		cfg.Uplink = ""

		return nil

	case flagValue == "":
		return nil
	}

	spec, err := config.ParseUplinkSpec(flagValue)
	if err != nil {
		return err
	}

	// A descriptor is adopted from whatever started the daemon, and what starts
	// anchord here is conflux's own supervisor, which passes it none. Rather than
	// let that arrive as "bad file descriptor" from a child process, say where the
	// form does work.
	if spec.FD >= 0 {
		return fmt.Errorf(
			"%s adopts a descriptor from whatever started the daemon, and conflux's supervisor starts anchord\n"+
				"  with none to adopt. Name the device instead, which conflux's anchor opens itself:\n\n"+
				"    conflux up --uplink /dev/ttyUSB0:115200\n\n"+
				"  To drive an anchor you hand a descriptor to yourself, that is anchorctl's own start:\n\n"+
				"    conflux anchorctl start -uplink %s",
			flagValue, flagValue)
	}

	// anchor opens a link on unix only (internal/uplink/open_other.go), so refuse
	// here rather than at the first start, where it would be a daemon exiting with
	// a message about a field nobody typed.
	if runtimeOS() == "windows" {
		return fmt.Errorf(
			"anchor has no way to open a link on Windows, so --uplink cannot be used here.\n" +
				"  The overlay over the host's network needs no flag:  conflux up")
	}

	if spec.Baud > 0 && spec.Baud < config.SlowUplinkBaud {
		ui.Warnf("%d baud carries a realm handshake in about %ds, against a 60s idle timeout.\n"+
			"  It is a full TLS 1.3 exchange with ML-DSA certificates both ways, so the floor is\n"+
			"  the identity model's rather than the link's: slower lines run out of time rather\n"+
			"  than merely take longer.",
			spec.Baud, 25*9600/spec.Baud)
	}

	cfg.Uplink = spec.String()

	return nil
}

// choosePeers decides where this machine starts looking for the realm.
//
// The default is to name nothing, and that is a decision rather than an omission.
// anchorctl fills bootstrap from the manifest only for fields no flag named, so the
// way to keep the issuer's own list -- and to let the API move a bootstrap node
// without every machine needing an edit -- is to pass no -peers at all.
//
// So --peers is an override for a realm the manifest does not describe, which in
// practice means a test node. It persists, like every other setting here, because a
// machine brought up against one has to come back to it after a reboot.
func choosePeers(cfg *config.Config, values []string, none bool) error {
	switch {
	case none && len(values) > 0:
		return errors.New("--peers and --no-peers contradict each other")

	case none:
		cfg.Peers = nil

		return nil

	case len(values) == 0:
		return nil
	}

	if err := config.ValidatePeers(values); err != nil {
		return err
	}

	if len(cfg.Peers) > 0 && !slices.Equal(cfg.Peers, values) {
		ui.Warnf("this machine was bootstrapping from %s and will now use %s.",
			strings.Join(cfg.Peers, ", "), strings.Join(values, ", "))
	}

	cfg.Peers = values

	return nil
}

// chooseTaints decides which compartment this machine is in.
//
// Omitting --taint mints one, because the alternative is not "no restriction": an
// anchor with no taints carries the realm's default compartment, which every other
// unconfigured anchor in the realm also carries. Leaving a machine there silently is
// the one thing conflux will not do.
func chooseTaints(cfg *config.Config, given []string, none bool) error {
	if none {
		if len(given) > 0 {
			return errors.New("--taint and --no-taint contradict each other")
		}

		ui.Warnf("--no-taint puts this machine in the realm's shared compartment,\n" +
			"  where it can exchange data with every other anchor that has no taint either.")

		// anchor treats an empty list as the default compartment, and conflux's
		// config validation insists on a non-empty one -- so name it explicitly.
		cfg.Taints = []string{defaultCompartment}

		return nil
	}

	if len(given) > 0 {
		if err := taint.ValidateSet(given); err != nil {
			return err
		}

		if len(cfg.Taints) > 0 && !sameSet(cfg.Taints, given) {
			ui.Warnf("this changes the taint from %s to %s, which changes which machines can reach this one.",
				strings.Join(cfg.Taints, ","), strings.Join(given, ","))
		}

		cfg.Taints = given

		if len(given) > 1 {
			ui.Warnf("a set of %d taints is reachable only from a machine carrying all of them.\n"+
				"  anchor's rule is containment, not overlap: two machines exchange data only if\n"+
				"  one carries every taint the other does.", len(given))
		}

		return nil
	}

	// Already has one. Never mint a second.
	if len(cfg.Taints) > 0 {
		return nil
	}

	minted := taint.New()
	cfg.Taints = []string{minted}

	ui.Println()
	ui.Println("Minted a taint for this network:")
	ui.Println()
	ui.Printf("    %s\n", minted)
	ui.Println()
	ui.Println("Share it. Any machine that runs")
	ui.Println()
	ui.Printf("    conflux up --taint %s\n", minted)
	ui.Println()
	ui.Println("joins this network and nothing else. Without a taint a machine sits in the")
	ui.Println("realm's shared compartment with every other unconfigured anchor, which is why")
	ui.Println("conflux makes one.")
	ui.Println()

	return nil
}

// defaultCompartment is the name conflux gives the shared compartment when somebody
// asks for it explicitly. Any single agreed string works: what matters is that every
// machine choosing --no-taint chooses the same one.
const defaultCompartment = "conflux-commons"

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	seen := make(map[string]bool, len(a))
	for _, v := range a {
		seen[v] = true
	}

	for _, v := range b {
		if !seen[v] {
			return false
		}
	}

	return true
}
