package anchorctl

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/veil-net/conflux/internal/config"
)

// Environment variables anchorctl reads for its connection details.
//
// Setting these rather than injecting -socket and -token-file is what keeps
// pass-through honest. anchorctl resolves the socket as
// firstNonEmpty(subcommand -socket, global -socket, ANCHOR_SOCKET), so a flag the
// user typed still wins over conflux's environment, and conflux never has to
// rewrite an argv it did not construct.
const (
	SocketEnv = "ANCHOR_SOCKET"
	TokenEnv  = "ANCHORD_TOKEN"
)

// Ctl runs the extracted anchorctl against one daemon.
type Ctl struct {
	Bin    string // the extracted anchorctl
	Socket string
	Token  string
	SetID  string
}

// Env is the child environment: the caller's, with conflux's connection details
// added only where the caller has not set them.
func (c *Ctl) Env() []string {
	env := os.Environ()

	for _, kv := range [...][2]string{{SocketEnv, c.Socket}, {TokenEnv, c.Token}} {
		if kv[1] != "" && os.Getenv(kv[0]) == "" {
			env = append(env, kv[0]+"="+kv[1])
		}
	}

	return env
}

// Error is a failed run, carrying what the child said.
type Error struct {
	Args   []string
	Stderr string

	// Err is how the run failed: an exit status, a signal, or a binary that never
	// started -- which says nothing on stderr and would otherwise read as a bare code.
	Err error
}

func (e *Error) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" && e.Err != nil {
		msg = e.Err.Error()
	}

	return fmt.Sprintf("anchorctl %s: %s", strings.Join(e.Args, " "), msg)
}

func (e *Error) Unwrap() error { return e.Err }

// run invokes anchorctl and returns its stdout.
func (c *Ctl) run(ctx context.Context, stdin []byte, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, c.Bin, args...)
	cmd.Env = c.Env()

	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	var out, errBuf bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		return out.String(), &Error{Args: args, Stderr: errBuf.String(), Err: err}
	}

	return out.String(), nil
}

// Start builds the anchor and starts it.
//
// The manifest goes in on stdin and never onto a second file. anchorctl's
// -manifest takes "-" for stdin and turns everything the document carries into an
// inline secret on the wire, so the identity seed travels from conflux's 0600 file
// through memory and an anonymous pipe to the daemon's socket, and is never written
// anywhere a crash could leave it. It also means no credential is named by path in
// the Start request: what does name a path is -dir, and an uplink's device, which
// anchord's -credentials-dir would confine as well -- a fence conflux does not set,
// since the socket it would guard is conflux's alone.
func (c *Ctl) Start(ctx context.Context, env config.Envelope, mode StartMode) (Started, error) {
	out, err := c.run(ctx, env, mode.Args()...)
	if err != nil {
		return Started{}, err
	}

	s := ParseStarted(out)
	if s.ID == "" {
		return s, fmt.Errorf("anchorctl start said nothing this build recognises:\n%s", strings.TrimSpace(out))
	}

	return s, nil
}

// Metric reads one of the daemon's counters or gauges. One that has not been
// published yet is not an error; it is reported absent.
func (c *Ctl) Metric(ctx context.Context, name string) (float64, bool, error) {
	out, err := c.run(ctx, nil, MetricsArgs()...)
	if err != nil {
		return 0, false, err
	}

	v, ok := ParseMetric(out, name)

	return v, ok, nil
}

// Status asks what is running. A daemon that is up with no anchor in it is not an
// error: it is a daemon between starts, or one whose anchor an admin's kill order or
// its own end took away, which the supervisor's watcher asks this to find out.
func (c *Ctl) Status(ctx context.Context) (Status, error) {
	out, err := c.run(ctx, nil, StatusArgs()...)
	if err != nil {
		return Status{}, err
	}

	return ParseStatus(out), nil
}

// Stop closes the anchor. The daemon stays up, and nothing running is not an error.
//
// Worth doing even when the process is about to be killed anyway: a closed anchor
// says goodbye, and a departure that is announced saves every peer from working it
// out by timeout.
func (c *Ctl) Stop(ctx context.Context) error {
	_, err := c.run(ctx, nil, StopArgs()...)

	return err
}

// Renew installs a fresh credential on the running anchor, hot: SetRealmCred rather
// than a restart, so not one session is lost.
func (c *Ctl) Renew(ctx context.Context, credPath string) error {
	_, err := c.run(ctx, nil, RenewArgs(credPath)...)

	return err
}
