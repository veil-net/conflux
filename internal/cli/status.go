package cli

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
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

	cfg, err := config.Load(d)
	if err != nil {
		if !os.IsNotExist(err) {
			return fail(err)
		}

		reportService()
		ui.Field("config", "none — this machine has never been configured")
		ui.Println()
		ui.Printf("  conflux up                          join with a network interface\n" +
			"  conflux proxy 8080=127.0.0.1:3000   publish a port, no interface needed\n")

		return ExitNoConfig
	}

	// The daemon's two answers are forks, so they are asked for first and read last,
	// and the wait for them overlaps everything conflux prints of its own.
	daemon := askDaemon(ctx, d)

	st, _ := config.LoadState(d)

	reportService()
	reportConfig(cfg)
	reportCredential(d, st)
	reportBinaries(st)

	ui.Field("api", cfg.APIBase())

	daemon.wg.Wait()

	reportExport(cfg, daemon)
	ui.Println()
	reportAnchor(daemon)

	return ExitOK
}

// daemonAnswers is what the running daemon said, asked for in parallel.
type daemonAnswers struct {
	wg      sync.WaitGroup
	asked   bool
	status  string
	statErr error
	export  string
	expErr  error
}

// askDaemon starts `anchorctl status` and `anchorctl export`, or asks nothing when
// there is no daemon to ask.
func askDaemon(ctx context.Context, d paths.Dirs) *daemonAnswers {
	a := &daemonAnswers{}

	ctl, err := runCtl(d)
	if err != nil || ctl.Token == "" {
		return a
	}

	a.asked = true
	env := ctl.Env()

	a.wg.Go(func() { a.status, a.statErr = runQuiet(ctx, ctl.Bin, env, []string{"status"}) })
	a.wg.Go(func() { a.export, a.expErr = runQuiet(ctx, ctl.Bin, env, []string{"export"}) })

	return a
}

func reportService() {
	if mgr, err := service.New(); err == nil {
		ui.Field("service", mgr.Describe())
	}
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

	if ip := cfg.OverlayIPv4(); ip != "" {
		ui.Field("ipv4", ip)
	}

	for _, s := range cfg.Subnets {
		ui.Field("forwarding", s)
	}

	for _, p := range cfg.Proxies {
		ui.Field("serving", p)
	}
}

func reportCredential(d paths.Dirs, st *config.State) {
	if !config.HasManifest(d) {
		ui.Field("credential", "none — nothing enrolled yet")

		return
	}

	if st == nil || st.NotAfter.IsZero() {
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
		ui.Field("credential", "valid until "+st.NotAfter.Format(time.RFC3339)+" ("+ui.Until(st.NotAfter)+")")
	}

	// A bad clock and a failing renewal are reported rather than hidden. An anchor can
	// be running perfectly while every handshake it attempts is refused, and status
	// that says "running" and nothing else would be describing the wrong thing. The
	// skew is as of the last call to the API, which every renewal makes.
	if st.ClockSkew > time.Second {
		note := ""
		if st.ClockSkew > daemon.MaxSkew {
			note = " — past the " + strings.TrimSuffix(daemon.MaxSkew.String(), "0s") + " anchor allows; fix the clock (timedatectl set-ntp true)"
		}

		ui.Field("clock", "off by "+st.ClockSkew.Round(time.Second).String()+note)
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

func reportBinaries(st *config.State) {
	if st == nil || st.BinSetID == "" || !anchor.Supported {
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
// configuration does not name, until the next restart puts it back. anchor reports
// which surface set it -- ExportSource -- for exactly this.
func reportExport(cfg *config.Config, a *daemonAnswers) {
	want := "none — nothing is exported until an endpoint is set"
	if cfg.Export != nil && cfg.Export.Enabled {
		want = cfg.Export.Endpoint + " — " + strings.Join(exportSignals(cfg.Export), ", ")
	}

	ui.Field("telemetry", want)

	// What the daemon believes, and only when it could be asked. A machine that is
	// not running has nothing to disagree with.
	if !a.asked || a.expErr != nil {
		return
	}

	for line := range strings.SplitSeq(strings.TrimSpace(a.export), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "set by")
		if ok && key == "" {
			source := strings.TrimSpace(value)

			// Named rather than merely printed. The config file, read at start or
			// re-read on a SIGHUP, is conflux.json having been applied and needs no
			// explanation; a call to anchorctl export is a live override with an end
			// date.
			if source == "anchorctl export" {
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

// reportAnchor prints anchorctl's own answer beneath conflux's, indented.
func reportAnchor(a *daemonAnswers) {
	ui.Println("anchor:")

	text := strings.TrimSpace(a.status)

	switch {
	case !a.asked:
		text = "not running"
	case text == "" && a.statErr != nil:
		text = a.statErr.Error()
	case text == "":
		text = "not running"
	}

	for line := range strings.SplitSeq(text, "\n") {
		ui.Printf("  %s\n", line)
	}
}
