package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/ui"
	"github.com/veil-net/conflux/internal/version"
)

// statusConfig is how status reads the configuration: a variable, so a test run as root can
// meet the refusal an account that cannot read it meets.
var statusConfig = config.Load

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
	// conflux's own mode: anchord's is the fips140 row of the anchor's status below.
	ui.Field("fips140", version.FIPS())
	ui.Println()

	ephemeral := reportEphemeralRun(ctx)

	cfg, err := statusConfig(d)

	// The root lets no account but root's in, and status reads it: asked for again with
	// privilege, as pass-through asks for the token.
	if errors.Is(err, fs.ErrPermission) {
		ui.Errf("%s is not readable, and conflux status reads it.\n  try:  %s",
			d.ConfigFile(), privcheck.Retry(typed("conflux", "status")))

		return ExitDenied
	}

	if err != nil {
		if !os.IsNotExist(err) {
			return fail(err)
		}

		reportService()
		ui.Field("config", "none — this machine has never been configured")
		ui.Println()
		ui.Printf("%s\n", configureHint)

		// What runs is the ephemeral anchor, which needs no configuration to be running.
		if ephemeral {
			return ExitOK
		}

		return ExitNoConfig
	}

	// The daemon's two answers are forks, so they are asked for first and read last,
	// and the wait for them overlaps everything conflux prints of its own.
	daemon := askDaemon(ctx, d, true)

	st, _ := config.LoadState(d)

	reportService()
	reportConfig(d, cfg)
	reportCredential(d, cfg, st)

	reportBinaries(st)

	ui.Field("api", cfg.APIBase())

	daemon.wg.Wait()

	reportExport(cfg, daemon)

	if cfg.Observer != nil {
		o := anchorctl.ParseStatus(daemon.status).Observer
		if !daemon.asked || daemon.statErr != nil {
			o.Note = "not running"
		}

		reportObserver(cfg, o)
	}

	reportPrivilege(d, daemon.asked && daemon.statErr == nil)
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

// askDaemon starts `anchorctl status`, and `anchorctl export` for a caller that reads it, or
// asks nothing when there is no daemon to ask.
func askDaemon(ctx context.Context, d paths.Dirs, export bool) *daemonAnswers {
	a := &daemonAnswers{}

	// No socket, no daemon. The token outlives one, since nothing clears the run directory
	// on stop but the next supervisor, and asking would cost two forks for anchorctl's
	// "is anchord running on that socket", which reads as a fault rather than a stop.
	if _, err := os.Stat(d.Socket()); err != nil {
		return a
	}

	ctl, err := runCtl(d)
	if err != nil || ctl.Token == "" {
		return a
	}

	a.asked = true
	env := ctl.Env()

	a.wg.Go(func() { a.status, a.statErr = runQuiet(ctx, ctl.Bin, env, []string{"status"}) })

	if export {
		a.wg.Go(func() { a.export, a.expErr = runQuiet(ctx, ctl.Bin, env, []string{"export"}) })
	}

	return a
}

func reportService() { ui.Field("service", services().Describe()) }

// reportEphemeralRun says what an ephemeral run is doing, before the machine's own anchor,
// and whether one is running: or what a killed one left behind.
func reportEphemeralRun(ctx context.Context) bool {
	d, run := ephemeralAt(paths.EphemeralRoot())

	switch run {
	case noRun:
		return false
	case staleRun:
		ui.Field("ephemeral", "none running; "+d.Root+" was left by one that was killed, and the next "+
			"ephemeral run clears it and stops any anchord it left")
		ui.Println()

		return false
	}

	ui.Println("ephemeral:")

	if !daemon.IsLiveReady(d) {
		ui.Field("running", "starting, from "+d.Root+" — in memory alone; nothing of it outlives the run")
		ui.Println()

		return true
	}

	daemon := askDaemon(ctx, d, false)
	daemon.wg.Wait()

	ui.Field("running", "from "+d.Root+" — in memory alone; nothing of it outlives the run")
	reportPrivilege(d, daemon.asked && daemon.statErr == nil)
	reportAnchor(daemon)
	ui.Println()

	return true
}

// reportPrivilege says who the running anchord runs as, with what, and why it keeps what
// it keeps: nothing for a daemon that is not running, whose record describes the last one.
func reportPrivilege(d paths.Dirs, running bool) {
	if !running {
		return
	}

	if p, ok := daemon.RecordedPrivilege(d); ok {
		ui.Field("anchord", p.String())
	}
}

func reportConfig(d paths.Dirs, cfg *config.Config) {
	// Before the mode, because it is the medium the mode runs over.
	if cfg.Uplink != "" {
		ui.Field("uplink", cfg.Uplink+" — no host network under it")
	}

	switch cfg.Mode {
	case config.ModeTUN:
		// What was asked for: the anchor's own answer, the name it holds, is its status's
		// `interface` row below.
		ui.Field("mode", "tun — interface "+interfaceLine(runtime.GOOS, cfg.TUNInterface(), ""))
	case config.ModeProxy:
		ui.Field("mode", "proxy — userspace, no host interface")
	case config.ModeObserve:
		ui.Field("mode", "observe — this host's traffic inventoried; no anchor, no realm")

		// The anchor's settings are kept for the next up or proxy, and describe nothing that
		// runs now.
		return
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

	reportSubnets(d, cfg)

	for _, p := range cfg.Proxies {
		ui.Field("serving", p)
	}
}

func reportCredential(d paths.Dirs, cfg *config.Config, st *config.State) {
	// Observing alone as beside an anchor: the observer runs under the same credential.
	held, err := heldCredential(d)

	switch {
	case err != nil:
		ui.Field("credential", "unreadable: "+err.Error())

		return
	case held == nil:
		ui.Field("credential", "none — nothing enrolled yet")

		return
	}

	// What stops a machine starting before anything else about the credential: one
	// configured for taints it does not grant, such as one enrolled before alpha granted
	// any. The supervisor refuses it for good, and this says why, and what to do.
	if err := held.CheckTaints(cfg.Taints); err != nil {
		ui.Field("refused", err.Error())
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
			note = " — past the " + strings.TrimSuffix(daemon.MaxSkew.String(), "0s") + " anchor allows; fix the clock" + clockHint()
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
// which surface set it -- ExportSource -- for exactly this, and where it exports, or that it
// exports nothing (anchorctl export's "exporting to" and "not exporting"), which is said where
// it is not what conflux.json names.
func reportExport(cfg *config.Config, a *daemonAnswers) {
	configured := cfg.Export != nil && cfg.Export.Enabled

	want := "none — nothing is exported until an endpoint is set"
	if configured {
		want = cfg.Export.Endpoint + " — " + strings.Join(cfg.Export.Signals(), ", ")
	}

	ui.Field("telemetry", want)

	// What the daemon believes, and only when it could be asked. A machine that is
	// not running has nothing to disagree with.
	if !a.asked || a.expErr != nil {
		return
	}

	for line := range strings.SplitSeq(strings.TrimSpace(a.export), "\n") {
		line = strings.TrimSpace(line)

		if line == "not exporting" {
			if configured {
				ui.Field("", "not exporting, the daemon says")
			}

			continue
		}

		if endpoint, ok := strings.CutPrefix(line, "exporting to"); ok {
			if endpoint = strings.TrimSpace(endpoint); !configured || endpoint != cfg.Export.Endpoint {
				ui.Field("", "the daemon exports to "+endpoint)
			}

			continue
		}

		key, value, ok := strings.Cut(line, "set by")
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

// clockHint is how to put this machine's clock right, where there is one command for it.
func clockHint() string {
	if runtime.GOOS == "linux" {
		return " (timedatectl set-ntp true)"
	}

	return ""
}
