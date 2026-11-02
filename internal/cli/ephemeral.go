package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
)

// An ephemeral run of up or proxy: one anchor, in the foreground, from a credential held in
// memory and nowhere else. See daemon.Ephemeral, and docs/ephemeral.md.

const (
	ephemeralUsage = "run in the foreground and keep nothing: the credential lives in memory, " +
		"nothing is saved or registered, and when anchord stops everything is gone"
	manifestUsage = "with --ephemeral, run on this issued credential rather than enrolling; - reads it from stdin. " +
		"It is never written"
)

// ephemeralFlags are the two flags up and proxy take for an ephemeral run.
type ephemeralFlags struct {
	on       *bool
	manifest *string
}

func registerEphemeral(fs *flag.FlagSet) ephemeralFlags {
	return ephemeralFlags{
		on:       fs.Bool("ephemeral", false, ephemeralUsage),
		manifest: fs.String("manifest", "", manifestUsage),
	}
}

// ephemeralRun is an ephemeral run being put together: the credential it was handed, if any,
// read before anything else is decided.
type ephemeralRun struct {
	env config.Envelope
	m   *enrol.Manifest
}

// prepare reads what the flags asked for: nil for a run that is not ephemeral. --manifest
// without --ephemeral is refused: a credential to keep is conflux enrol's.
func (f ephemeralFlags) prepare() (*ephemeralRun, error) {
	if !*f.on {
		if *f.manifest != "" {
			return nil, errors.New("--manifest is for an --ephemeral run, which keeps it in memory.\n" +
				"  To install a credential this machine keeps: conflux enrol --manifest FILE")
		}

		return nil, nil
	}

	run := &ephemeralRun{}

	if *f.manifest == "" {
		return run, nil
	}

	// First, and through the one reader every credential comes in by: stdin may be a pipe
	// from a slow fetch, and nothing else is worth deciding before it has arrived.
	env, err := readEnvelope(*f.manifest)
	if err != nil {
		return nil, err
	}

	m, err := enrol.Decode(env)
	if err != nil {
		return nil, err
	}

	if _, err := m.Auth(); err != nil {
		return nil, err
	}

	run.env, run.m = env, m

	return run, nil
}

// runCredential is the credential up or proxy decides the taints against: the one an
// ephemeral run was handed, or the one this machine holds.
func runCredential(run *ephemeralRun, d paths.Dirs) (*enrol.Manifest, error) {
	if run != nil {
		return run.m, nil
	}

	return heldCredential(d)
}

// fresh is the configuration an ephemeral run starts from: nothing of the machine's, and the
// handed credential's API and taints where there is one, as enrol would take them.
func (r *ephemeralRun) fresh(apiFlag string) (*config.Config, error) {
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
func (r *ephemeralRun) ipv4(cfg *config.Config, flagValue string, none bool) error {
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

// root refuses what an ephemeral run of verb cannot do as whoever runs it. A TUN needs root
// (Administrator on Windows), and observing needs the host's capture, which only root gives
// here. Everything else runs as an ordinary user: userspace needs no privilege, and an
// ephemeral run registers nothing that would. On Windows every root conflux keeps is
// Administrators', so there an ephemeral run needs Administrator whatever its mode.
func (r *ephemeralRun) root(verb string, cfg *config.Config, args []string) error {
	switch {
	case verb == "up":
		return needsRoot("bringing up a network interface", verb, args)
	case cfg.Observer != nil:
		return needsRoot("observing this host's traffic", verb, args)
	case runtime.GOOS == "windows":
		return needsRoot("keeping an ephemeral run's socket and binaries", verb, args)
	}

	return nil
}

// runEphemeral runs cfg in the foreground until it is stopped or anchord ends, and says so.
func runEphemeral(ctx context.Context, cfg *config.Config, run *ephemeralRun) int {
	if err := cfg.Validate(); err != nil {
		return fail(err)
	}

	d, err := paths.Ephemeral()
	if err != nil {
		return fail(err)
	}

	ctx, stop := hangupContext(ctx)
	defer stop()

	// The first signal stops the run cleanly; a second is not waited for. The handlers go,
	// so it ends conflux at once, and anchord with it.
	go func() {
		<-ctx.Done()
		signal.Reset(os.Interrupt, syscall.SIGTERM)
	}()

	ui.Printf("Starting an ephemeral anchor: nothing is saved, and when it stops nothing of it remains.\n")

	e := &daemon.Ephemeral{
		Dirs:     d,
		Config:   cfg,
		Manifest: run.env,
		Reporter: reporter{},
		Drop:     runtime.GOOS != "windows",
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
	reportAnchorRows(d, cfg, st)
	reportObserver(cfg, st.Observer)
	ui.Field("anchord", u.Privilege.String())
	ui.Field("ephemeral", "in memory alone; "+d.State+" holds the socket and the binaries, and goes with the run")
	ui.Println()

	if len(cfg.Taints) > 0 && (u.Manifest == nil || u.Manifest.Alpha()) {
		ui.Printf("Reachable from any machine that runs:  conflux up --taint %s\n", strings.Join(cfg.Taints, " --taint "))
	}

	ui.Printf("Running in the foreground. Ctrl-C stops it and removes what it made; "+
		"conflux status, from another terminal, reports it.\n%s\n", ephemeralReachedBy(d))
}

// ephemeralReachedBy says how anchorctl's commands reach an ephemeral anchor beside an
// installed one, which they otherwise reach first.
func ephemeralReachedBy(paths.Dirs) string {
	return fmt.Sprintf("With an installed conflux running too, conflux's pass-through reaches it with %s=1.", ephemeralEnv)
}
