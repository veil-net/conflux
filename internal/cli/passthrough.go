package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/ui"
)

// passthrough hands an argument vector to anchorctl exactly as it arrived.
//
// Not one token is parsed. conflux supplies the connection details through the
// environment instead of injecting flags, so there is never an argv to rewrite; a socket
// the user named, by -socket or ANCHOR_SOCKET, is answered before anything of conflux's is
// supplied, and a token the user exported is kept.
//
// On Unix a command for conflux's daemon replaces the process outright, where its anchorctl is
// the installation's extraction. That gives perfect stdio, the child's exit code without
// translation, signals delivered to the right process, and nothing left in `ps` pretending to be
// a wrapper. A temporary copy, which is removed once it has run, runs as a child instead
// (runAnchorctl), as does what needs nothing of conflux's daemon; see runDetached.
func passthrough(ctx context.Context, args []string) int {
	// Neither a socket the user named nor usage needs conflux's daemon, so each is answered
	// before anything is asked of it, with the user's environment alone, and with the readers'
	// anchorctl (readersAnchorctl), which the installation never stands in the way of: where it is
	// not there, or its roots are refused, that is a temporary copy, so an account that cannot read
	// them still reaches its own daemon. A user who named a socket is talking to a daemon conflux does
	// not manage; ANCHOR_SOCKET exported empty names no socket, as anchorctl reads it. Usage needs
	// nothing running: anchorctl groups keygen, issue and inspect under "no anchor needed", but that
	// means no *anchor* -- they are still RPCs to the daemon, which mints the identity and derives the
	// id -- and asking for help is the only thing that genuinely reaches no socket, because Go's flag
	// package answers before anything dials.
	if namesSocket(args) || os.Getenv(anchorctl.SocketEnv) != "" || wantsUsage(args) {
		bin, done, err := readersAnchorctl()

		return runDetached(args, bin, done, err)
	}

	d, checked := activeDirs()

	token, code := connectionDetails(d, checked, args)
	if code != ExitOK {
		return code
	}

	// Only once there is something to talk to. Extracting first made the directories
	// uninstall had removed, and tens of megabytes in them, on a machine with nothing
	// running, and failed for an account that cannot write them before saying what was
	// wrong.
	bin, done, err := toolsFor(d)
	if err != nil {
		return fail(err)
	}

	env := (&anchorctl.Ctl{Socket: d.Socket(), Token: token}).PassthroughEnv()

	// A temporary copy is removed once the run ends, which a process replaced by it cannot do.
	if done != nil {
		return runAnchorctl(bin, args, env, done)
	}

	return execAnchorctl(ctx, bin, args, env)
}

// connectionDetails reads the token, once d has passed paths' check (checked: an error that is
// fs.ErrNotExist where nothing of conflux's is there, and a refusal where d is not conflux's to
// read), and intercepts the one failure anchorctl cannot advise on.
//
// Its own answer to a socket with no daemon behind it asks whether anchord is running
// there, which is right for anchor and no help to somebody holding conflux, who never
// started anchord and is not meant to. Everything else, including anchorctl's
// genuinely good explanations of every other refusal, passes through untouched.
func connectionDetails(d paths.Dirs, checked error, args []string) (string, int) {
	retry := privcheck.Retry(privcheck.Command(append([]string{"conflux"}, args...)...))

	if checked == nil {
		if _, err := os.Stat(d.Socket()); errors.Is(err, fs.ErrNotExist) {
			checked = err
		}
	}

	switch {
	case errors.Is(checked, fs.ErrNotExist):
		ui.Errf("nothing is running here.\n\n"+
			"  conflux start                       start from a configuration that already exists\n"+
			configureHint+"\n\n"+
			"  (the control socket would be %s)", d.Socket())

		return "", ExitUnavailable
	case errors.Is(checked, fs.ErrPermission):
		ui.Errf("%v\n  try:  %s", checked, retry)

		return "", ExitDenied
	case checked != nil:
		return "", fail(checked)
	}

	token, err := readToken(d)
	if errors.Is(err, fs.ErrPermission) {
		ui.Errf("%s is not readable, and anchorctl needs it to authenticate.\n  try:  %s", d.TokenFile(), retry)

		return "", ExitDenied
	}

	// Any other failure is a daemon that is up with its token gone. Let anchorctl
	// produce the error; it may still work from the user's own environment.
	return token, ExitOK
}

// readersAnchorctl is the anchorctl what needs nothing of conflux's daemon runs -- help's, and a
// pass-through for usage or to a socket the user named -- and done, which removes it where it is a
// temporary copy: the readers' (libexec.ForUsage), the installation's roots held to the readers' check
// first. A variable so that a test can point it at a stand-in.
var readersAnchorctl = func() (string, func(), error) {
	d := paths.Default()

	return libexec.ForUsage(d, d.Check())
}

// runDetached runs bin, the anchorctl for what needs nothing of conflux's daemon -- usage, which reaches
// no daemon, or a daemon the user named -- or says err, why there is none, as a child that is waited
// for; done, where it is given, removes bin, a temporary copy, once the run ends, however it ends.
func runDetached(args []string, bin string, done func(), err error) int {
	if err != nil {
		return fail(err)
	}

	return runAnchorctl(bin, args, os.Environ(), done)
}

// wantsUsage reports whether this invocation is only asking what a command takes: help
// as the command, or a help flag anywhere. Not help anywhere at all, which is as likely a
// flag's value -- `block -target X -reason help` -- as a request.
func wantsUsage(args []string) bool {
	return len(args) > 0 && args[0] == "help" || slices.ContainsFunc(args, isHelpFlag)
}

// namesSocket reports whether the user supplied their own -socket, in any of the
// spellings Go's flag package accepts.
func namesSocket(args []string) bool {
	for _, a := range args {
		switch {
		case a == "-socket", a == "--socket":
			return true
		case strings.HasPrefix(a, "-socket="), strings.HasPrefix(a, "--socket="):
			return true
		}
	}

	return false
}

// runEscapeHatch is `conflux anchorctl ...`: the always-unambiguous way to reach a
// command conflux shadows, or one it refuses to pass through.
func runEscapeHatch(ctx context.Context, args []string) int {
	// "conflux anchorctl -- proxy -add ..." is a spelling people will try, and the
	// separator is noise once it has done its job at the shell.
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}

	if len(args) == 0 {
		args = []string{"help"}
	}

	return passthrough(ctx, args)
}

// runCtl builds a Ctl for conflux's own use, against conflux's own daemon, and done, which removes
// the temporary copy of anchorctl it runs, where it runs one, once the caller is done with it. Its
// token is empty when there is none to read, which is a daemon that is not running.
func runCtl(d paths.Dirs) (*anchorctl.Ctl, func(), error) {
	bin, done, err := toolsFor(d)
	if err != nil {
		return nil, nil, err
	}

	if done == nil {
		done = func() {}
	}

	token, _ := readToken(d)

	return &anchorctl.Ctl{
		Bin:    bin,
		Socket: d.Socket(),
		Token:  token,
		SetID:  anchor.SetID(),
	}, done, nil
}

// readToken is the daemon's bearer token; "" with the error when it cannot be read.
func readToken(d paths.Dirs) (string, error) {
	b, err := os.ReadFile(d.TokenFile())

	return strings.TrimSpace(string(b)), err
}

// runQuiet runs anchorctl and returns its output, for the places conflux embeds it
// in its own (conflux status, mainly).
func runQuiet(ctx context.Context, bin string, env, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env

	out, err := cmd.CombinedOutput()

	return string(out), err
}

// ephemeralEnv set to 1 sends pass-through to the ephemeral anchor while the installed one
// runs too; see activeDirs.
const ephemeralEnv = "CONFLUX_EPHEMERAL"

// activeDirs is the root whose anchor the pass-through reaches: the machine's own, or an
// ephemeral run's. The ephemeral one only when it is the one running, or when asked for by
// CONFLUX_EPHEMERAL=1: a command never switches anchors because one was started beside it.
// The machine's own is held to paths' check before anything in it is looked at by name, and
// what the check said comes back with it (Dirs.Check): fs.ErrNotExist where it is not there, which
// the ephemeral run's answers for where one is running, and a refusal, which nothing answers for.
// An ephemeral run's was judged as its readers judge one (ephemeralRuns).
func activeDirs() (paths.Dirs, error) {
	installed := paths.Default()

	eph, live := liveEphemeral()
	if live && os.Getenv(ephemeralEnv) == "1" {
		return eph, nil
	}

	switch err := installed.Check(); {
	case live && errors.Is(err, fs.ErrNotExist):
		return eph, nil
	case err != nil, !live:
		return installed, err
	}

	if _, err := os.Stat(installed.Socket()); err == nil {
		return installed, nil
	}

	return eph, nil
}

// liveEphemeral is the root of the ephemeral run that is running, if one is: the one whose
// lock is held.
func liveEphemeral() (paths.Dirs, bool) {
	if live, _ := ephemeralRuns(); live != nil {
		return *live, true
	}

	return paths.Dirs{}, false
}

// checkEphemeral is the readers' check of the ephemeral root at root (paths.Dirs.Check), which a test
// points at a root it made: nil only for a root that is there as conflux makes one, an error that is
// fs.ErrNotExist for one not there, and a refusal for any other.
var checkEphemeral = func(root string) error { return paths.EphemeralDirs(root).Check() }

// statLock is os.Stat, for a root's lock, which a test counts.
var statLock = os.Stat

// ephemeralRuns is what the ephemeral roots hold, read in one pass: the root of the run that is
// running, whose lock is held, and the root a run that was killed left behind, its lock there
// with nobody holding it -- the first of each, or nil.
//
// A root not as conflux makes one -- another account's, or a link -- is neither, whatever it holds: a
// run is never kept in one (paths.Ephemeral), and /tmp and %ProgramData% let anybody make the name
// first and put a held lock, a marker and an anchorctl of their own in it, which a reader taking it
// for a run would run.
func ephemeralRuns() (live, stale *paths.Dirs) {
	for _, root := range paths.EphemeralCandidates() {
		// The root itself, and nothing beneath it before that: a root as conflux makes one holds nothing
		// another account put there. And a root not there (fs.ErrNotExist) holds no run, and is looked up
		// by its name no more: what is at a name that was not there a moment ago is whoever made it
		// first's.
		if err := checkEphemeral(root); err != nil {
			continue
		}

		d := paths.EphemeralDirs(root)
		if _, err := statLock(d.ServeLockFile()); err != nil {
			continue
		}

		switch held, err := flock.Held(d.ServeLockFile()); {
		case err != nil:
		case held && live == nil:
			live = &d
		case !held && stale == nil:
			stale = &d
		}
	}

	return live, stale
}

// errEphemeralStarting is an ephemeral run asked for before it is up.
var errEphemeralStarting = errors.New("the ephemeral run is still starting; ask again once it is up")

// toolsFor is the anchorctl to reach d's daemon with, and done, which removes it once it has run,
// where it is a temporary copy, and is nil where it is not. For the installation's daemon it is the
// readers' anchorctl (libexec.ForUsage), its roots held to the readers' check first -- by every caller,
// which comes here only where the check passed, reading nothing between but files in them, and where the
// owner of what it makes was set (ownerRefusal): this build's
// pair extracted there taken as it is found, or extracted into a bin directory as conflux makes one where
// it is not there yet, and otherwise a private temporary copy; neither a root nor the bin directory is
// made. An ephemeral run's root is the run's own: a reader takes the pair it finds there and writes
// nothing, and reads nothing until the run has marked itself up, since before that the run may still be
// clearing what a killed one left -- and a reader that refilled what it was clearing, or held one of its
// binaries open, would stop it.
func toolsFor(d paths.Dirs) (string, func(), error) {
	if !slices.Contains(paths.EphemeralCandidates(), d.State) {
		return libexec.ForUsage(d, nil)
	}

	if !daemon.IsLiveReady(d) {
		return "", nil, errEphemeralStarting
	}

	t, err := libexec.Extracted(d)
	if err != nil {
		return "", nil, err
	}

	return t.Anchorctl, nil, nil
}
