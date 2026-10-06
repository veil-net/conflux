package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/paths"
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
		ipv4     = fs.String("ipv4", "", ipv4Usage)
		noIPv4   = fs.Bool("no-ipv4", false, noIPv4Usage)
		tunName  = fs.String("interface", "", "name for the network interface (default anchor0); macOS and the BSDs number their own")
		uplink   = fs.String("uplink", "", "carry the mesh over a link rather than the host network, e.g. /dev/ttyUSB0:115200")
		noUplink = fs.Bool("no-uplink", false, "go back to the host's network on a machine configured for a link")
		noPeers  = fs.Bool("no-peers", false, "forget the bootstrap list and go back to the one enrolment supplies")
		noSubnet = fs.Bool("no-subnet", false, subnetOffUsage)
		apiBase  = fs.String("api", "", "enrolment API base URL")
		port     = fs.Uint("port", 0, "UDP port to bind on every interface; omit to let the kernel pick one")
		lanDisco = fs.String("lan-discovery", "auto",
			"find peers on the networks this host is attached to: yes, no, or auto to let enrolment decide")
		peers repeated
	)

	// Registered for the flag package and read through typedFlags, not through these
	// values: what matters is whether they were written, not what they default to.
	fs.Bool("no-port", false, "go back to letting the kernel pick the port")
	fs.Bool("low-latency", false, "carry frames on datagrams: no head-of-line blocking, and a lost frame stays lost")
	fs.Bool("no-low-latency", false, "go back to carrying frames on streams")
	registerExits(fs)

	fs.Var(&taints, "taint", taintUsage)
	fs.Var(&subnets, "subnet", subnetUsage)
	fs.Var(&peers, "peers", "bootstrap entry as host:port; repeat for more. Enrolment supplies these, so this is an override")

	fs.Usage = func() {
		ui.Printf("conflux up — join the overlay with a network interface\n\n" +
			"  conflux up [--taint T] [--ipv4 ADDRESS | --no-ipv4] [--subnet CIDR... | --no-subnet]\n" +
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

	if err := needsRoot("bringing up a network interface", "up", args); err != nil {
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

	// Before the warning below, because a flag that is going to be refused should be
	// refused before this machine is told its proxies are being replaced. The
	// announcement is not a lie -- nothing is saved until bring -- but reading
	// "replaces that" and then an error is a worse way to learn you typo'd a port.
	if err := chooseTuning(cfg, typedFlags(fs), *port, *lanDisco); err != nil {
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

	if err := chooseSubnets(cfg, subnets, *noSubnet); err != nil {
		return fail(err)
	}

	if err := chooseIPv4(cfg, *ipv4, *noIPv4); err != nil {
		return fail(err)
	}

	held, err := heldCredential(d)
	if err != nil {
		return fail(err)
	}

	if err := chooseTaints(cfg, taints, held); err != nil {
		return fail(err)
	}

	return bring(ctx, d, cfg, "up", len(subnets) > 0 || *noSubnet)
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

// chooseTristate resolves a yes/no/auto flag against what is already configured.
//
// Three answers rather than two, so this is a value flag and not a --x/--no-x pair:
// auto is the one that passes nothing to anchorctl and so leaves the manifest's own
// answer in play, and a boolean has nowhere to put it. Typing --lan-discovery auto
// is the way back from a persisted yes or no, which is the job the negations do for
// the toggles above.
//
// An absent flag keeps what is configured, because that is how every other re-run of
// up keeps its settings.
func chooseTristate(name string, typed map[string]bool, value string, current *bool) (*bool, error) {
	if !typed[name] {
		return current, nil
	}

	switch strings.ToLower(strings.TrimSpace(value)) {
	case "auto":
		return nil, nil
	case "yes":
		yes := true

		return &yes, nil
	case "no":
		no := false

		return &no, nil
	default:
		return nil, fmt.Errorf("--%s %s: want yes, no or auto", name, value)
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

// Flag help shared by up and proxy, which take the same routing settings: with an
// interface the host forwards, and in userspace the anchor does from its own process.
const (
	subnetUsage = "a network this machine forwards for the realm: a prefix, an interface, or '*' for every private one, " +
		"optionally bound to some of its taints as SPEC@a+b; repeat for more. Replaces a list a Subnets order set"
	subnetOffUsage = "forward no networks for the realm; the way back from --subnet, and from a Subnets order"
	taintUsage     = "the taint to enrol in: the one the first machine of a network printed, to join it; " +
		"omit it there and one is minted. Repeat for more than one. Fixed by the credential once enrolled"
)

// registerExits adds the two exit settings and their negations, read through
// typedFlags rather than by value.
func registerExits(fs *flag.FlagSet) {
	fs.Bool("serve-exit", false, "offer this machine as a way out to the public internet")
	fs.Bool("no-serve-exit", false, "stop offering a way out")
	fs.Bool("use-exit", false, "send this machine's own internet traffic over the overlay")
	fs.Bool("no-use-exit", false, "send this machine's internet traffic the ordinary way")
}

// chooseTuning applies the settings that are neither the mode nor the medium.
func chooseTuning(cfg *config.Config, typed map[string]bool, port uint, lanDisco string) error {
	if err := choosePort(cfg, typed, port); err != nil {
		return err
	}

	lowLatency, err := chooseToggle("low-latency", typed, cfg.LowLatency)
	if err != nil {
		return err
	}

	cfg.LowLatency = lowLatency

	lan, err := chooseTristate("lan-discovery", typed, lanDisco, cfg.LANDiscovery)
	if err != nil {
		return err
	}

	cfg.LANDiscovery = lan

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

// ipv4Usage and noIPv4Usage are the IPv4 flags' help, shared by up and proxy.
const (
	ipv4Usage   = "this machine's IPv4: an address, or address/length to route the rest of that range to peers, e.g. 10.128.0.7/24"
	noIPv4Usage = "give this machine no IPv4 of its own; it still reaches IPv4 peers, and is reached by IPv6"
)

// chooseIPv4 decides this machine's IPv4, prompting only when it has to.
//
// The question is asked at most once in a machine's life. A flag decides; otherwise a
// configuration that has been asked keeps its answer -- an address, or none -- and
// nothing is asked: changing a machine's address because somebody re-ran a command is
// not an acceptable thing to do to them.
func chooseIPv4(cfg *config.Config, flagValue string, none bool) error {
	var answer string

	switch {
	case none && flagValue != "":
		return errors.New("--ipv4 and --no-ipv4 contradict each other")

	case none:

	case flagValue != "":
		if _, err := config.ParseOverlayIPv4(flagValue); err != nil {
			return err
		}

		answer = flagValue

	case cfg.IPv4 != nil:
		return nil

	case !ui.IsTerminal():
		return errors.New(
			"this machine has not been given an IPv4 yet and there is no terminal to ask at: pass --ipv4 ADDRESS or --no-ipv4")

	default:
		a, err := promptIPv4()
		if err != nil {
			return err
		}

		answer = a
	}

	cfg.IPv4 = &answer

	return nil
}

func promptIPv4() (string, error) {
	ui.Println("An IPv4 lets the other machines on this network reach this one by a v4 address.")
	ui.Println("A private address is advertised to them; give each machine that should be")
	ui.Println("reachable on its own a different one. The IPv6 address is derived from this")
	ui.Println("machine's identity and needs no answer.")
	ui.Println()

	for {
		answer, err := ui.Ask("  IPv4 [e.g. 10.128.0.7/24, blank for none]: ")
		if err != nil {
			if errors.Is(err, io.EOF) {
				ui.Println()

				return "", nil
			}

			return "", err
		}

		if answer == "" {
			ui.Println("  No IPv4. Peers reach this machine by its IPv6 address.")
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
	if runtime.GOOS == "windows" {
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

	values = unique(values)

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

// chooseSubnets decides what this machine forwards for the realm: the --subnet flags
// when there are any, nothing with --no-subnet, and otherwise what is configured, like
// every other setting a re-run keeps. Validate checks each entry, and the bindings
// against the taints.
//
// Either flag is a new set of the list, which replaces one a member's Subnets order set
// since; see dropSubnetsOrder. A re-run with neither keeps whatever is served.
func chooseSubnets(cfg *config.Config, values []string, none bool) error {
	switch {
	case none && len(values) > 0:
		return errors.New("--subnet and --no-subnet contradict each other")
	case none:
		cfg.Subnets = nil
	case len(values) > 0:
		cfg.Subnets = unique(values)
	}

	return nil
}

// chooseTaints decides which compartments this machine asks to be enrolled in, or
// checks the ones its credential already grants.
//
// The credential commits to its taints for the life of the identity -- anchor starts it
// under no others, and a renewal restates them -- so with a credential held, --taint can
// only say the same thing again, and anything else is refused with the way out: a new
// identity. Without one, --taint is the request: the taint the first machine of a
// network printed, which a machine joining it asks for. Omitted there, conflux mints one,
// because the alternative is not "no restriction": an anchor with no taints is in the
// realm's shared compartment with every other untainted device, and conflux never asks
// the alpha realm for that.
func chooseTaints(cfg *config.Config, given []string, held *enrol.Manifest) error {
	given = unique(given)

	if err := config.ValidateTaints(given); err != nil {
		return err
	}

	if held != nil {
		want := given
		if len(want) == 0 {
			want = cfg.Taints
		}

		if err := held.CheckTaints(want); err != nil {
			return err
		}

		// The grant, whatever conflux.json said: it is the one place the names are, and a
		// configuration that lost them gets them back.
		cfg.Taints = unique(held.Taints())

		return nil
	}

	switch {
	case len(given) > 0:
		cfg.Taints = given
	case len(cfg.Taints) > 0:
		return nil // asked for by an earlier run that has not enrolled yet
	default:
		minted := taint.New()
		cfg.Taints = []string{minted}

		ui.Println()
		ui.Println("Minted a taint for this network:")
		ui.Println()
		ui.Printf("    %s\n", minted)
		ui.Println()
		ui.Println("This machine's credential is issued in it, for the life of its identity. Share it:")
		ui.Println("any machine that runs")
		ui.Println()
		ui.Printf("    conflux up --taint %s\n", minted)
		ui.Println()
		ui.Println("is issued a credential in it too, and joins this network and nothing else. Anybody")
		ui.Println("may ask for any name, so a taint is as private as it is hard to guess: keep it to")
		ui.Println("the machines meant to join.")
		ui.Println()

		return nil
	}

	if len(given) > 1 {
		ui.Warnf("a set of %d taints is compared by containment, not overlap: this machine exchanges\n"+
			"  data only with one whose taints include all of these, or are all among them.\n"+
			"  Sharing one of them is not enough.", len(given))
	}

	return nil
}

// heldCredential is this machine's credential, or nil before it has one.
func heldCredential(d paths.Dirs) (*enrol.Manifest, error) {
	env, err := config.LoadManifest(d)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return enrol.Decode(env)
}

// subnetsOrder is the list a member's Subnets order set on this machine, which anchor
// keeps in its directory and serves in place of the configured one from every start.
type subnetsOrder struct {
	Subnets []string  `json:"subnets"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
}

// readSubnetsOrder is the order in force, or nil when none is.
func readSubnetsOrder(d paths.Dirs) (*subnetsOrder, error) {
	b, err := os.ReadFile(d.SubnetsOrderFile())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	var o subnetsOrder
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, fmt.Errorf("%s: %w", d.SubnetsOrderFile(), err)
	}

	return &o, nil
}

// dropSubnetsOrder lets the list conflux starts with be served again: the operator just
// set it, and the last set is the one served. The order's file is anchor's documented way
// back, removed before the restart that reads it.
func dropSubnetsOrder(d paths.Dirs) error {
	o, err := readSubnetsOrder(d)
	if o == nil {
		return err
	}

	if err := os.Remove(d.SubnetsOrderFile()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("could not replace the subnet list an order set: %w", err)
	}

	ui.Printf("Replacing the subnet list an order from %s set at %s.\n", o.By, o.At.Format(time.RFC3339))

	return nil
}

// unique drops repeated values and keeps the first of each, in order. Every list a
// flag can repeat means a set, and anchor collapses a repeat anyway.
func unique(values []string) []string {
	out := make([]string, 0, len(values))

	for _, v := range values {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}

	return out
}
