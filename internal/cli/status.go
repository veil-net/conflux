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
	// conflux's own mode: anchord's is the fips140 row of the anchor's status below.
	ui.Field("fips140", version.FIPS())
	ui.Println()

	eph := ephemeral != nil && ephemeral.report(ctx)

	// Nothing of the machine's is read by its name until its root passes paths' check; one not
	// there is a machine never configured, with nothing read.
	err := d.Check()

	var cfg *config.Config
	if err == nil {
		cfg, err = config.Load(d)
	}

	if err != nil {
		// An installed machine's configuration is root's alone, so another account is refused
		// as every verb needing privilege refuses it: exit 13, and the command to run again.
		if errors.Is(err, fs.ErrPermission) {
			if denial := needsRoot("reading this machine's configuration", "status", nil); denial != nil {
				return fail(denial)
			}
		}

		if !errors.Is(err, fs.ErrNotExist) {
			return fail(err)
		}

		reportService()
		ui.Field("config", "none — this machine has never been configured")
		ui.Println()
		ui.Printf("%s\n", configureHint)

		// What runs is the ephemeral anchor, which needs no configuration to be running.
		if eph {
			return ExitOK
		}

		return ExitNoConfig
	}

	// The daemon's two answers are forks, so they are asked for first and read last,
	// and the wait for them overlaps everything conflux prints of its own.
	answers := askDaemon(ctx, d, true)

	st, stErr := config.LoadState(d)

	// The last anchord's record, read once for the two things said of it: the anchor
	// directory, where a subnets order is kept, and who anchord runs as.
	priv, recorded := daemon.RecordedPrivilege(d)

	reportService()
	reportConfig(d, priv, cfg)

	// Said rather than skipped: a corrupt one is what the next start refuses.
	if stErr != nil {
		ui.Field("state", "unreadable: "+stErr.Error())
	}

	reportCredential(d, cfg, st)

	reportBinaries(st)

	ui.Field("api", cfg.APIBase())

	answers.wg.Wait()

	answered := answers.asked && answers.statErr == nil
	said := anchorctl.ParseStatus(answers.status)

	reportGivenUp(cfg, st, answered && said.Running)
	reportExport(cfg, answers)

	if cfg.Observer != nil {
		o := said.Observer
		if !answered {
			o.Note = "not running"
		}

		reportObserver(cfg, o)
	}

	reportPrivilege(priv, recorded, answered)
	ui.Println()
	reportAnchor(answers)

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

// askDaemon starts `anchorctl status`, and `anchorctl export` where the caller reads it, or
// asks nothing when there is no daemon to ask.
func askDaemon(ctx context.Context, d paths.Dirs, export bool) *daemonAnswers {
	a := &daemonAnswers{}

	// No socket, no daemon. The token outlives one where nothing clears the run directory
	// on stop -- launchd, rc, Windows -- and asking would cost a fork for each answer, to
	// hear anchorctl's "is anchord running on that socket", which reads as a fault rather
	// than a stop.
	if _, err := os.Stat(d.Socket()); err != nil {
		return a
	}

	ctl, done, err := runCtl(ctx, d)
	if err != nil {
		return a
	}

	if ctl.Token == "" {
		done()

		return a
	}

	a.asked = true
	env := ctl.Env()

	// Both at once, and the anchorctl they run removed once both have, where it is a temporary copy,
	// before wg lets the caller go on.
	a.wg.Go(func() {
		defer done()

		var exported sync.WaitGroup
		if export {
			exported.Go(func() { a.export, a.expErr = runQuiet(ctx, ctl.Bin, env, anchorctl.ExportStatusArgs()) })
		}

		a.status, a.statErr = runQuiet(ctx, ctl.Bin, env, anchorctl.StatusArgs())
		exported.Wait()
	})

	return a
}

func reportService() { ui.Field("service", newService().Describe()) }

// reportPrivilege says who the running anchord runs as, with what, and why it keeps what
// it keeps, from p, its record where one is: nothing for a daemon that is not running, whose
// record describes the last one.
func reportPrivilege(p daemon.Privilege, recorded, running bool) {
	if running && recorded {
		ui.Field("anchord", p.String())
	}
}

// reportConfig says what the configuration runs; priv is the last anchord's record, which
// names the anchor directory a member's Subnets order is kept in.
func reportConfig(d paths.Dirs, priv daemon.Privilege, cfg *config.Config) {
	// Before the mode, because it is the medium the mode runs over.
	if cfg.Uplink != "" {
		ui.Field("uplink", cfg.Uplink+" — no host network under it")
	}

	switch cfg.Mode {
	case config.ModeTUN:
		// What was asked for: the anchor's own answer, the name it holds, is its status's
		// `interface` row below.
		ui.Field("mode", "tun — interface "+interfaceLine(runtime.GOOS, cfg.TUNName, ""))
	case config.ModeProxy:
		ui.Field("mode", "proxy — userspace, no host interface")
	case config.ModeObserve:
		ui.Field("mode", "observe — this host's traffic inventoried, under this machine's credential; no anchor")
		ui.Field("taint", joinTaints(cfg.Taints))

		// The anchor's other settings are kept for the next up or proxy, and describe nothing
		// that runs now.
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

	reportSubnets(daemon.ActiveAnchorDir(d, priv), cfg)

	for _, p := range cfg.Proxies {
		ui.Field("serving", p)
	}
}

// reportCredential says what the credential the anchor and the observer run under is, and how
// its renewal goes.
func reportCredential(d paths.Dirs, cfg *config.Config, st *config.State) {
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

	// The identity's AnchorID, which is the anchor's name, and what an observer alone runs as.
	if st.AnchorID != "" {
		if cfg.Anchor() {
			ui.Field("anchor", st.AnchorID)
		} else {
			ui.Field("identity", st.AnchorID)
		}
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

// reportGivenUp says when the supervisor gave up on the anchor, refused for good, and why, where
// no anchor runs -- the daemon answering with none, or not answering, the service having ended
// on it -- since anchorctl's status beneath says only that none runs. Whether the observer runs
// is its own row's to say. Observing alone, there is no anchor to have given up on.
func reportGivenUp(cfg *config.Config, st *config.State, running bool) {
	if st == nil || st.AnchorRefused == "" || running || !cfg.Anchor() {
		return
	}

	ui.Field("given up", "the anchor, at "+st.AnchorRefusedAt.Format(time.RFC3339)+": "+st.AnchorRefused)
	ui.Field("", "conflux start tries the anchor again")
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
		want = cfg.Export.Endpoint + " — " + strings.Join(cfg.Export.Signals(), ", ")
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
