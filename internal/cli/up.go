package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
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
		taints  repeated
		subnets repeated
		ipv4    = fs.String("ipv4", "", "overlay IPv4 as a prefix, e.g. 10.128.0.7/24")
		noIPv4  = fs.Bool("no-ipv4", false, "do not assign an overlay IPv4; the v6 address is derived anyway")
		noTaint = fs.Bool("no-taint", false, "join the realm's shared compartment instead of a private one")
		tunName = fs.String("interface", "", "name for the network interface (default anchor0)")
		apiBase = fs.String("api", "", "enrolment API base URL")
	)

	fs.Var(&taints, "taint", "compartment label; repeat to carry more than one")
	fs.Var(&subnets, "subnet", "a network this machine forwards for the realm; repeat for more")

	fs.Usage = func() {
		ui.Printf("conflux up — join the overlay with a network interface\n\n" +
			"  conflux up [--taint T] [--ipv4 PREFIX | --no-ipv4] [--subnet CIDR]...\n\n" +
			"Enrols this machine if it has never been, starts an anchor in TUN mode, writes\n" +
			"the configuration, and registers the boot service so a reboot needs nothing.\n\n")
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
