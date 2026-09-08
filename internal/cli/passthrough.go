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

	tools, err := libexec.Ensure(d)
	if err != nil {
		return fail(err)
	}

	token, ok := connectionDetails(d, args)
	if !ok {
		return ExitUnavailable
	}

	env := (&anchorctl.Ctl{Socket: d.Socket(), Token: token}).Env()

	return execAnchorctl(ctx, tools.Anchorctl, args, env)
}

// connectionDetails reads the token, and intercepts the one failure anchorctl
// cannot advise on.
//
// Its own hint for an unreachable daemon reads "anchorctl start -identity FILE
// -root FILE -cred FILE", which is right for anchor and useless to somebody holding
// conflux -- they have no such files and are not meant to. Everything else,
// including anchorctl's genuinely good explanations of every other refusal, passes
// through untouched.
func connectionDetails(d paths.Dirs, args []string) (string, bool) {
	// A user who named a socket themselves is talking to a daemon conflux does not
	// manage, so none of the checks below apply to them.
	if namesSocket(args) || os.Getenv(anchorctl.SocketEnv) != "" {
		return "", true
	}

	// Usage needs nothing running. anchorctl groups keygen, issue and inspect
	// under "no anchor needed", but that means no *anchor*: they are still RPCs to
	// the daemon, which mints the identity and derives the id. Asking for help is
	// the only thing that genuinely reaches no socket, because Go's flag package
	// answers before anything dials.
	if wantsUsage(args) {
		return "", true
	}

	if _, err := os.Stat(d.Socket()); errors.Is(err, fs.ErrNotExist) {
		ui.Errf("nothing is running here.\n\n"+
			"  conflux start                       start from a configuration that already exists\n"+
			"  conflux up                          join with a network interface\n"+
			"  conflux proxy 8080=127.0.0.1:3000   publish a port, no interface needed\n\n"+
			"  (the control socket would be %s)", d.Socket())

		return "", false
	}

	b, err := os.ReadFile(d.TokenFile())
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			ui.Errf("%s is not readable, and anchorctl needs it to authenticate.\n"+
				"  try:  sudo conflux %s", d.TokenFile(), strings.Join(args, " "))

			return "", false
		}

		// The daemon is up but the token is gone. Let anchorctl produce the error;
		// it may still work from the user's own environment.
		return "", true
	}

	return strings.TrimSpace(string(b)), true
}

// wantsUsage reports whether this invocation is only asking what a command takes.
func wantsUsage(args []string) bool {
	for _, a := range args {
		switch a {
		case "help", "-h", "--help", "-help":
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
	if len(args) == 0 {
		args = []string{"help"}
	}

	// "conflux anchorctl -- proxy -add ..." is a spelling people will try, and the
	// separator is noise once it has done its job at the shell.
	if args[0] == "--" {
		args = args[1:]
	}

	if len(args) == 0 {
		args = []string{"help"}
	}

	return passthrough(ctx, args)
}

// runCtl builds a Ctl for conflux's own use, against conflux's own daemon.
func runCtl(d paths.Dirs) (*anchorctl.Ctl, error) {
	tools, err := libexec.Ensure(d)
	if err != nil {
		return nil, err
	}

	token, err := os.ReadFile(d.TokenFile())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	return &anchorctl.Ctl{
		Bin:    tools.Anchorctl,
		Socket: d.Socket(),
		Token:  strings.TrimSpace(string(token)),
		SetID:  tools.SetID,
	}, nil
}

// runQuiet runs anchorctl and returns its output, for the places conflux embeds it
// in its own (conflux status, mainly).
func runQuiet(ctx context.Context, bin string, env, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env

	out, err := cmd.CombinedOutput()

	return string(out), err
}
