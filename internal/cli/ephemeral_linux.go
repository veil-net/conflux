package cli

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
)

// Ephemeral runs are Linux's alone: here they are run, and found (ephemeral).
func init() { ephemeral = onLinux{} }

// onLinux runs and finds ephemeral runs.
type onLinux struct{}

// memoryRun is an ephemeral run being put together: the credential it was handed, if any,
// read before anything else is decided.
type memoryRun struct {
	env config.Envelope
	m   *enrol.Manifest
}

// start reads the credential at manifest, where one is named: first, and through the one reader every
// credential comes in by -- stdin may be a pipe from a slow fetch, and nothing else is worth deciding
// before it has arrived.
func (onLinux) start(manifest string) (ephemeralRun, int) {
	run := &memoryRun{}

	if manifest == "" {
		return run, ExitOK
	}

	env, err := readEnvelope(manifest)
	if err != nil {
		return nil, fail(err)
	}

	m, err := enrol.Decode(env)
	if err != nil {
		return nil, fail(err)
	}

	if _, err := m.Auth(); err != nil {
		return nil, fail(err)
	}

	run.env, run.m = env, m

	return run, ExitOK
}

func (r *memoryRun) credential() *enrol.Manifest { return r.m }

// fresh is the configuration an ephemeral run starts from: nothing of the machine's, and the
// handed credential's API and taints where there is one, as enrol would take them.
func (r *memoryRun) fresh(apiFlag string) (*config.Config, error) {
	cfg := &config.Config{APIBaseURL: apiFlag}

	if r.m == nil {
		return cfg, nil
	}

	base, err := chooseAPIBase(r.m, apiFlag)
	if err != nil {
		return nil, err
	}

	if base != "" {
		cfg.APIBaseURL = base
	}

	taints, err := importedTaints(r.m)
	if err != nil {
		return nil, err
	}

	cfg.Taints = taints

	return cfg, nil
}

// ipv4 is the run's IPv4, decided without a question: an ephemeral run is often started by
// something other than a person, and asks nothing. --ipv4, else --no-ipv4, else the handed
// credential's own, else none.
func (r *memoryRun) ipv4(cfg *config.Config, flagValue string, none bool) error {
	switch {
	case none && flagValue != "":
		return errors.New("--ipv4 and --no-ipv4 contradict each other")
	case none:
		cfg.IPv4 = new(string)

		return nil
	}

	value := flagValue
	if value == "" && r.m != nil {
		value = r.m.IPv4()
	}

	if value != "" {
		if _, err := config.ParseOverlayIPv4(value); err != nil {
			return err
		}
	}

	cfg.IPv4 = &value

	return nil
}

// root refuses what an ephemeral proxy cannot do as whoever runs it. Observing needs the
// host's capture, which only root gives here. Everything else runs as an ordinary user:
// userspace needs no privilege, and an ephemeral run registers nothing that would. An ephemeral
// up's TUN needs root too, which up asks for itself, as it does for every run.
func (r *memoryRun) root(cfg *config.Config, args []string) error {
	if cfg.Observer != nil {
		return needsRoot("observing this host's traffic", "proxy", args)
	}

	return nil
}

// secondSignalEnds lets the first signal stop a run cleanly, by ending ctx, and waits for no
// second: once ctx ends the handlers of the forwarded signals go, so the next interrupt, SIGTERM
// or hangup ends conflux at once, and anchord with it. One conflux was started ignoring
// (catches) is ignored still: Reset puts back the ignore it found.
func secondSignalEnds(ctx context.Context) {
	go func() {
		<-ctx.Done()
		signal.Reset(forwarded...)
	}()
}

// run runs cfg in the foreground until it is stopped or anchord ends, and says so.
func (r *memoryRun) run(ctx context.Context, cfg *config.Config) int {
	if err := cfg.Validate(); err != nil {
		return fail(err)
	}

	d, err := paths.Ephemeral()
	if err != nil {
		return fail(err)
	}

	ctx, stop := hangupContext(ctx)
	defer stop()

	secondSignalEnds(ctx)

	ui.Printf("Starting an ephemeral anchor: nothing is saved, and when it stops nothing of it remains.\n")

	e := &daemon.Ephemeral{
		Dirs:     d,
		Config:   cfg,
		Manifest: r.m,
		Envelope: r.env,
		Reporter: reporter{},
		Drop:     true,
		Up:       func(u daemon.EphemeralUp) { reportEphemeral(d, cfg, u) },
	}

	err = e.Run(ctx)

	switch {
	// Ctrl-C while the run is still starting ends whatever it was waiting on with the
	// context's error, and is as much a stop asked for as one once it is up.
	case err == nil || ctx.Err() != nil:
		ui.Printf("\nStopped. Nothing of the run remains: no credential, no configuration, no state.\n")

		return ExitOK
	case daemon.Permanent(err):
		ui.Errf("%v", err)

		return ExitChildFailed
	default:
		return fail(err)
	}
}

// reportEphemeral is what a person sees once the anchor is up.
func reportEphemeral(d paths.Dirs, cfg *config.Config, u daemon.EphemeralUp) {
	st := u.Status
	if st.ID == "" {
		st.ID = u.Started.ID
	}

	ui.Println()
	reportAnchorRows(daemon.ActiveAnchorDir(d, u.Privilege), cfg, st)
	reportObserver(cfg, st.Observer)
	ui.Field("anchord", u.Privilege.String())
	ui.Field("ephemeral", "in memory alone; "+d.Root+" holds the socket and the binaries, and goes with the run")
	ui.Println()

	if len(cfg.Taints) > 0 && (u.Manifest == nil || u.Manifest.Alpha()) {
		ui.Printf("Reachable from any machine that runs:  conflux up --taint %s\n", strings.Join(cfg.Taints, " --taint "))
	}

	// How anchorctl's commands reach this anchor beside an installed one, which they
	// otherwise reach first.
	ui.Printf("Running in the foreground. Ctrl-C stops it and removes what it made; "+
		"conflux status, from another terminal, reports it.\n"+
		"With an installed conflux running too, conflux's pass-through reaches it with %s=1.\n", ephemeralEnv)
}

// hangupContext adds SIGHUP to what ends ctx: an ephemeral run in a terminal that is closed
// stops cleanly, as it does on Ctrl-C, rather than being left for the kernel to kill. Not where
// conflux was started ignoring it (catches), as nohup starts it, to run on once the terminal
// has gone.
func hangupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if !catches(syscall.SIGHUP) {
		return context.WithCancel(ctx)
	}

	return signal.NotifyContext(ctx, syscall.SIGHUP)
}

// checkEphemeral is the readers' check of an ephemeral run's root (paths.Dirs.Check), which a test
// stands in for: nil only for a root that is there as conflux makes one, an error that is
// fs.ErrNotExist for one not there, and a refusal for any other.
var checkEphemeral = paths.Dirs.Check

// statLock is os.Stat, for a root's lock, which a test counts.
var statLock = os.Stat

// runs is what this account's ephemeral root holds (paths.EphemeralDirs), read in one pass: the root
// of the run that is running, whose lock is held, or the root a run that was killed left behind, its
// lock there with nobody holding it -- or nil for each, as where this account has no ephemeral root at
// all.
//
// A root not as conflux makes one -- another account's, or a link -- is neither, whatever it holds: a
// run is never kept in one (paths.Ephemeral), and a reader taking the lock, the marker and the anchorctl
// in it for a run's would run that anchorctl.
func (onLinux) runs() (live, stale *paths.Dirs) {
	d, err := paths.EphemeralDirs()
	if err != nil {
		return nil, nil
	}

	// The root itself, and nothing beneath it before that: a root as conflux makes one holds nothing
	// another account put there. And a root not there (fs.ErrNotExist) holds no run, and is looked up by
	// its name no more: what is at a name that was not there a moment ago is whoever made it first's.
	if err := checkEphemeral(d); err != nil {
		return nil, nil
	}

	if _, err := statLock(d.ServeLockFile()); err != nil {
		return nil, nil
	}

	switch held, err := flock.Held(d.ServeLockFile()); {
	case err != nil:
		return nil, nil
	case held:
		return &d, nil
	}

	return nil, &d
}

// errEphemeralStarting is an ephemeral run asked for before it is up.
var errEphemeralStarting = errors.New("the ephemeral run is still starting; ask again once it is up")

// tools is the anchorctl to reach the ephemeral run d's daemon with (toolsFor): the pair the run
// extracted, taken as it is found and nothing written, and nothing read until the run has marked itself
// up, since before that it may still be clearing what a killed one left.
func (onLinux) tools(d paths.Dirs) (string, func(), error) {
	if !daemon.IsLiveReady(d) {
		return "", nil, errEphemeralStarting
	}

	t, err := libexec.Extracted(d)
	if err != nil {
		return "", nil, err
	}

	return t.Anchorctl, nil, nil
}

// report says what an ephemeral run is doing, for status, before the machine's own anchor, and
// whether one is running: or what a killed one left behind.
func (o onLinux) report(ctx context.Context) bool {
	live, stale := o.runs()

	if stale != nil {
		ui.Field("ephemeral", "none running; "+stale.Root+" was left by one that was killed, and the next "+
			"ephemeral run clears it and stops any anchord it left")
		ui.Println()
	}

	if live == nil {
		return false
	}

	d := *live

	ui.Println("ephemeral:")

	if !daemon.IsLiveReady(d) {
		ui.Field("running", "starting, from "+d.Root+" — in memory alone; nothing of it outlives the run")
		ui.Println()

		return true
	}

	answers := askDaemon(ctx, d, false)
	answers.wg.Wait()

	ui.Field("running", "from "+d.Root+" — in memory alone; nothing of it outlives the run")

	priv, recorded := daemon.RecordedPrivilege(d)
	reportPrivilege(priv, recorded, answers.asked && answers.statErr == nil)
	reportAnchor(answers)
	ui.Println()

	return true
}
