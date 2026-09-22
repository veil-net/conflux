package cli

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/service"
	"github.com/veil-net/conflux/internal/ui"
	"github.com/veil-net/conflux/internal/version"
)

// runStatus resolves the collision with anchorctl's status by arity, and is
// additive rather than replacing.
//
// Bare `conflux status` is conflux's, and it prints anchorctl's underneath, so
// nothing is lost by conflux owning that spelling. Given any argument it forwards
// verbatim, so `conflux status -watch 5s` and `conflux status -h` do what an anchor
// user expects. A shadow that loses information is the problem; one that adds is not.
func runStatus(ctx context.Context, args []string) int {
	if len(args) > 0 {
		return passthrough(ctx, append([]string{"status"}, args...))
	}

	d := paths.Default()

	ui.Println(version.String())
	ui.Println()

	if mgr, err := service.New(); err == nil {
		ui.Field("service", mgr.Describe())
	}

	cfg, err := config.Load(d)
	if err != nil {
		if os.IsNotExist(err) {
			ui.Field("config", "none — this machine has never been configured")
			ui.Println()
			ui.Printf("  conflux up                          join with a network interface\n" +
				"  conflux proxy 8080=127.0.0.1:3000   publish a port, no interface needed\n")

			return ExitNoConfig
		}

		return fail(err)
	}

	reportConfig(cfg)
	reportCredential(d)
	reportBinaries(d)

	ui.Field("api", cfg.APIBase())
	reportExport(ctx, d, cfg)
	ui.Println()

	appendAnchorStatus(ctx, d)

	return ExitOK
}

func reportConfig(cfg *config.Config) {
	// Before the mode, because it is the medium the mode runs over.
	if cfg.Uplink != "" {
		ui.Field("uplink", cfg.Uplink+" — no host network under it")
	}

	switch cfg.Mode {
	case config.ModeTUN:
		ui.Field("mode", "tun — interface "+cfg.TUNInterface())
	case config.ModeProxy:
		ui.Field("mode", "proxy — userspace, no host interface")
	}

	if note := exitNote(cfg); note != "" {
		ui.Field("exit", note)
	}

	ui.Field("taint", joinTaints(cfg.Taints))

	// Only when overridden. Silence here means the manifest's own list, which is
	// the normal case and not a missing setting.
	if len(cfg.Peers) > 0 {
		ui.Field("peers", strings.Join(cfg.Peers, ", ")+" — overriding the enrolled list")
	}

	if cfg.IPv4 != "" {
		ui.Field("ipv4", cfg.IPv4)
	}

	for _, s := range cfg.Subnets {
		ui.Field("forwarding", s)
	}

	for _, p := range cfg.Proxies {
		ui.Field("serving", p)
	}
}

func reportCredential(d paths.Dirs) {
	if !config.HasManifest(d) {
		ui.Field("credential", "none — nothing enrolled yet")

		return
	}

	st, err := config.LoadState(d)
	if err != nil || st.NotAfter.IsZero() {
		ui.Field("credential", "held, expiry unknown")

		return
	}

	if st.AnchorID != "" {
		ui.Field("anchor", st.AnchorID)
	}

	left := time.Until(st.NotAfter)

	switch {
	case left <= 0:
		ui.Field("credential", "EXPIRED "+st.NotAfter.Format(time.RFC3339))
	default:
		ui.Field("credential", "valid until "+st.NotAfter.Format(time.RFC3339)+" ("+until(st.NotAfter)+")")
	}

	// A renewal that is failing is reported rather than hidden. An anchor can be
	// running perfectly while every handshake it attempts is refused, and status
	// that says "running" and nothing else would be describing the wrong thing.
	// Zero until something has called the API in this process, so silence here
	// means "not measured", not "measured and fine".
	if enrol.Skew > time.Second {
		note := ""
		if enrol.Skew > daemon.MaxSkew {
			note = " — past the hour the handshake tolerates; fix the clock (timedatectl set-ntp true)"
		}

		ui.Field("clock", "off by "+enrol.Skew.Round(time.Second).String()+note)
	}

	if st.LastRenewalError != "" {
		ui.Field("renewal", "failing since "+st.LastRenewalTry.Format(time.RFC3339)+": "+st.LastRenewalError)
	}

	// A link that keeps ending is a failing cable, and the anchor's own uptime
	// cannot say so: it resets on every reopen, so a machine losing its link hourly
	// looks like one that has been up for fifty minutes.
	if st.LinkReopens > 0 {
		ui.Field("uplink", plural(st.LinkReopens, "reopen")+", last "+st.LastLinkReopen.Format(time.RFC3339))
	}
}

// plural renders a count with its noun, so "1 reopen" does not read as a typo.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}

	return strconv.Itoa(n) + " " + noun + "s"
}

func reportBinaries(d paths.Dirs) {
	st, err := config.LoadState(d)
	if err != nil || st.BinSetID == "" || !anchor.Supported {
		return
	}

	if st.BinSetID != anchor.SetID() {
		ui.Field("binaries", "stale — conflux was upgraded; run \"conflux start\" to restart onto the new anchor")
	}
}

// reportExport says where telemetry goes, and -- when the two disagree -- which
// surface the running daemon is actually obeying.
//
// The disagreement is real and is the reason this reads the daemon at all rather
// than printing the config file. Three surfaces can set export: conflux.json,
// rendered to anchord's -config on every spawn; a SetExport call, which
// `conflux anchorctl export -endpoint ...` makes; and a SIGHUP, which re-reads the
// file and discards the call. So a machine can be exporting somewhere its own
// configuration does not name, until the next restart puts it back.
//
// That is a supportable arrangement and an unsupportable surprise, so the fix is to
// show it. anchor made it showable on purpose -- ExportSource exists, in its own
// words, because "an operator looking at a daemon that is not exporting what they
// asked for has no way to find out who asked otherwise".
func reportExport(ctx context.Context, d paths.Dirs, cfg *config.Config) {
	want := "none — nothing is exported until an endpoint is set"
	if cfg.Export != nil && cfg.Export.Enabled {
		want = cfg.Export.Endpoint + " — " + strings.Join(exportSignals(cfg.Export), ", ")
	}

	ui.Field("telemetry", want)

	// What the daemon believes, and only when it can be asked. A machine that is
	// not running has nothing to disagree with.
	ctl, err := runCtl(d)
	if err != nil || ctl.Token == "" {
		return
	}

	out, err := runQuiet(ctx, ctl.Bin, ctl.Env(), []string{"export"})
	if err != nil {
		return
	}

	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "set by")
		if ok && key == "" {
			source := strings.TrimSpace(value)

			// Named rather than merely printed. "the config file" is conflux.json
			// having been applied and needs no explanation; anything else is a
			// live override with an end date.
			if source != "the config file" {
				source += " — an override, discarded at the next restart"
			}

			ui.Field("", "set by "+source)
		}
	}
}

// exportSignals names what is being sent, for a status line.
func exportSignals(e *config.Export) []string {
	var out []string

	for _, s := range []struct {
		on   bool
		name string
	}{{e.Metrics, "metrics"}, {e.Traces, "traces"}, {e.Logs, "logs"}} {
		if s.on {
			out = append(out, s.name)
		}
	}

	return out
}

// appendAnchorStatus prints anchorctl's own answer beneath conflux's, indented.
func appendAnchorStatus(ctx context.Context, d paths.Dirs) {
	ctl, err := runCtl(d)
	if err != nil || ctl.Token == "" {
		ui.Println("anchor:")
		ui.Println("  not running")

		return
	}

	out, err := runQuiet(ctx, ctl.Bin, ctl.Env(), []string{"status"})

	ui.Println("anchor:")

	text := strings.TrimSpace(out)
	if text == "" {
		if err != nil {
			text = err.Error()
		} else {
			text = "not running"
		}
	}

	for line := range strings.SplitSeq(text, "\n") {
		ui.Printf("  %s\n", line)
	}
}
