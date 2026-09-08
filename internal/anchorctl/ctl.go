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

	for k, v := range map[string]string{SocketEnv: c.Socket, TokenEnv: c.Token} {
		if v == "" || os.Getenv(k) != "" {
			continue
		}

		env = append(env, k+"="+v)
	}

	return env
}

// Error is a non-zero exit, carrying what the child said.
type Error struct {
	Args   []string
	Code   int
	Stderr string
}

func (e *Error) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		msg = fmt.Sprintf("exit status %d", e.Code)
	}

	return fmt.Sprintf("anchorctl %s: %s", strings.Join(e.Args, " "), msg)
}

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
		code := -1
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}

		return out.String(), &Error{Args: args, Code: code, Stderr: errBuf.String()}
	}

	return out.String(), nil
}

// Start builds the anchor and starts it.
//
// The manifest goes in on stdin and never onto a second file. anchorctl's
// -manifest takes "-" for stdin and turns everything the document carries into an
// inline secret on the wire, so the identity seed travels from conflux's 0600 file
// through memory and an anonymous pipe to the daemon's socket, and is never written
// anywhere a crash could leave it. It also means no path is named in the Start
// request at all, which is why anchord's -credentials-dir confinement is a question
// conflux never has to answer.
func (c *Ctl) Start(ctx context.Context, env config.Envelope, mode StartMode) (Started, error) {
	if err := mode.Validate(); err != nil {
		return Started{}, err
	}

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

// Metrics reads the daemon's counters and gauges. An anchor that has not published
// any yet is not an error; the map is simply empty.
func (c *Ctl) Metrics(ctx context.Context) (map[string]float64, error) {
	out, err := c.run(ctx, nil, MetricsArgs()...)
	if err != nil {
		return nil, err
	}

	return ParseMetrics(out), nil
}

// Status asks what is running. A daemon that is up with no anchor in it is not an
// error -- it is the state conflux down leaves behind.
func (c *Ctl) Status(ctx context.Context) (Status, error) {
	out, err := c.run(ctx, nil, StatusArgs()...)
	if err != nil {
		return Status{}, err
	}

	return ParseStatus(out), nil
}

// Ping reports whether the daemon is up and the token is accepted. It is the
// readiness probe: a socket file proves nothing, because a crashed daemon leaves
// one behind.
func (c *Ctl) Ping(ctx context.Context) error {
	_, err := c.run(ctx, nil, StatusArgs()...)

	return err
}

// Stop closes the anchor. The daemon stays up.
//
// Worth doing even when the process is about to be killed anyway: a closed anchor
// says goodbye, and a departure that is announced saves every peer from working it
// out by timeout.
func (c *Ctl) Stop(ctx context.Context) error {
	_, err := c.run(ctx, nil, StopArgs()...)
	if err == nil {
		return nil
	}

	// Nothing running is what we wanted.
	var e *Error
	if ok := asError(err, &e); ok && strings.Contains(strings.ToLower(e.Stderr), "no anchor") {
		return nil
	}

	return err
}

// Renew installs a fresh credential on the running anchor, hot: SetRealmCred rather
// than a restart, so not one session is lost.
func (c *Ctl) Renew(ctx context.Context, credPath string) error {
	_, err := c.run(ctx, nil, RenewArgs(credPath)...)

	return err
}

func asError(err error, target **Error) bool {
	e, ok := err.(*Error) //nolint:errorlint // run only ever returns this type unwrapped
	if ok {
		*target = e
	}

	return ok
}
