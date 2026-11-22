package cli

import (
	"context"
	"errors"
	"flag"
	"runtime"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
)

// An ephemeral run of up or proxy: one anchor, in the foreground, from a credential held in
// memory and nowhere else, on Linux alone (ephemeral_linux.go). See docs/ephemeral.md.

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

// ephemeral runs and finds ephemeral runs: Linux's alone, which ephemeral_linux.go sets it to, the one
// platform whose runtime folder, a filesystem in memory the system empties at boot, keeps nothing of a
// run past it. Nil everywhere else, where --ephemeral is refused and no run is ever found.
var ephemeral interface {
	// start puts an ephemeral run together from the credential at manifest, "" to enrol in memory, or
	// is the exit code that refuses it, said.
	start(manifest string) (ephemeralRun, int)

	// runs is what this account's ephemeral root holds (ephemeralRuns).
	runs() (live, stale *paths.Dirs)

	// report says what an ephemeral run is doing, for status, and whether one is running.
	report(ctx context.Context) bool

	// tools is the anchorctl to reach the ephemeral run d's daemon with (toolsFor).
	tools(d paths.Dirs) (string, func(), error)
}

// ephemeralRun is an ephemeral run being put together (ephemeral).
type ephemeralRun interface {
	// fresh is the configuration it starts from.
	fresh(apiFlag string) (*config.Config, error)

	// ipv4 decides its IPv4 without a question.
	ipv4(cfg *config.Config, flagValue string, none bool) error

	// root refuses what an ephemeral proxy cannot do as whoever runs it.
	root(cfg *config.Config, args []string) error

	// credential is the credential it was handed, nil to enrol in memory.
	credential() *enrol.Manifest

	// run runs cfg in the foreground until it is stopped or anchord ends, and is the exit code.
	run(ctx context.Context, cfg *config.Config) int
}

// prepare reads what the flags asked for: no run, and ExitOK, for a run that is not ephemeral, or the
// run, or the exit code that refuses it, said. --manifest without --ephemeral is refused: a credential
// to keep is conflux enrol's. --ephemeral is refused, exit 2, where there are no ephemeral runs, before
// anything is read, the credential --manifest names among it.
func (f ephemeralFlags) prepare() (ephemeralRun, int) {
	if !*f.on {
		if *f.manifest != "" {
			return nil, fail(errors.New("--manifest is for an --ephemeral run, which keeps it in memory.\n" +
				"  To install a credential this machine keeps: conflux enrol --manifest FILE"))
		}

		return nil, ExitOK
	}

	if ephemeral == nil {
		ui.Errf("--ephemeral runs on Linux alone, which keeps the run in a filesystem in memory that goes at boot; "+
			"this is %s", runtime.GOOS)

		return nil, ExitUsage
	}

	return ephemeral.start(*f.manifest)
}

// runCredential is the credential up or proxy decides the taints against: the one an
// ephemeral run was handed, or the one this machine holds.
func runCredential(run ephemeralRun, d paths.Dirs) (*enrol.Manifest, error) {
	if run != nil {
		return run.credential(), nil
	}

	return heldCredential(d)
}
