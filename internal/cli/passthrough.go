package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"strings"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/ui"
)

// passthrough hands an argument vector to anchorctl exactly as it arrived.
//
// Not one token is parsed. conflux supplies the connection details through the
// environment instead of injecting flags, because anchorctl resolves the socket as
// firstNonEmpty(-socket, global -socket, ANCHOR_SOCKET) -- so a flag the user typed
// still beats conflux's environment, and there is never an argv to rewrite.
//
// On Unix the process is replaced outright. That gives perfect stdio, the child's
// exit code without translation, signals delivered to the right process, and
// nothing left in `ps` pretending to be a wrapper.
func passthrough(ctx context.Context, args []string) int {
	d := paths.Default()

	token, code := connectionDetails(d, args)
	if code != ExitOK {
		return code
	}

	// Only once there is something to talk to. Extracting first made the directories
	// uninstall had removed, and 45 MB in them, on a machine with nothing running, and
	// failed for an account that cannot write them before saying what was wrong.
	tools, err := libexec.Ensure(d)
	if err != nil {
		return fail(err)
	}

	env := (&anchorctl.Ctl{Socket: d.Socket(), Token: token}).Env()

	return execAnchorctl(ctx, tools.Anchorctl, args, env)
}

// connectionDetails reads the token, and intercepts the one failure anchorctl
// cannot advise on.
//
// Its own answer to a socket with no daemon behind it asks whether anchord is running
// there, which is right for anchor and no help to somebody holding conflux, who never
// started anchord and is not meant to. Everything else, including anchorctl's
// genuinely good explanations of every other refusal, passes through untouched.
func connectionDetails(d paths.Dirs, args []string) (string, int) {
	// A user who named a socket themselves is talking to a daemon conflux does not
	// manage, so none of the checks below apply to them.
	if namesSocket(args) || os.Getenv(anchorctl.SocketEnv) != "" {
		return "", ExitOK
	}

	// Usage needs nothing running. anchorctl groups keygen, issue and inspect
	// under "no anchor needed", but that means no *anchor*: they are still RPCs to
	// the daemon, which mints the identity and derives the id. Asking for help is
	// the only thing that genuinely reaches no socket, because Go's flag package
	// answers before anything dials.
	if wantsUsage(args) {
		return "", ExitOK
	}

	if _, err := os.Stat(d.Socket()); errors.Is(err, fs.ErrNotExist) {
		ui.Errf("nothing is running here.\n\n"+
			"  conflux start                       start from a configuration that already exists\n"+
			"  conflux up                          join with a network interface\n"+
			"  conflux proxy 8080=127.0.0.1:3000   publish a port, no interface needed\n\n"+
			"  (the control socket would be %s)", d.Socket())

		return "", ExitUnavailable
	}

	token, err := readToken(d)
	if errors.Is(err, fs.ErrPermission) {
		ui.Errf("%s is not readable, and anchorctl needs it to authenticate.\n  try:  %s",
			d.TokenFile(), privcheck.Retry(typed("conflux", args...)))

		return "", ExitDenied
	}

	// Any other failure is a daemon that is up with its token gone. Let anchorctl
	// produce the error; it may still work from the user's own environment.
	return token, ExitOK
}

// wantsUsage reports whether this invocation is only asking what a command takes: help
// as the command, or a help flag anywhere. Not help anywhere at all, which is as likely a
// flag's value -- `block -target X -reason help` -- as a request.
func wantsUsage(args []string) bool {
	if len(args) > 0 && args[0] == "help" {
		return true
	}

	for _, a := range args {
		switch a {
		case "-h", "--help", "-help":
			return true
		}
	}

	return false
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

// runCtl builds a Ctl for conflux's own use, against conflux's own daemon. Its token
// is empty when there is none to read, which is a daemon that is not running.
func runCtl(d paths.Dirs) (*anchorctl.Ctl, error) {
	tools, err := libexec.Ensure(d)
	if err != nil {
		return nil, err
	}

	token, _ := readToken(d)

	return &anchorctl.Ctl{
		Bin:    tools.Anchorctl,
		Socket: d.Socket(),
		Token:  token,
		SetID:  tools.SetID,
	}, nil
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
