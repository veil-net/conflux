package daemon

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
)

// The supervisor is what the service manager actually runs.
//
//	systemd / launchd / SCM
//	  └── conflux serve
//	        ├── anchord -socket … -token-file …
//	        ├── the renewal timer
//	        └── the restart loop
//
// Registering anchord itself as the service was the obvious alternative and does not
// work: anchord is configured with nothing and holds no anchor until something calls
// start over its socket, so a supervisor has to exist, and it may as well be the
// thing the service manager watches.

const (
	// readyTimeout bounds how long a daemon has to come up before conflux gives up
	// on it. Generous, because a loaded Raspberry Pi is slower than it looks.
	readyTimeout = 30 * time.Second

	// stopTimeout bounds the polite half of shutdown.
	stopTimeout = 20 * time.Second

	// killTimeout is how long after SIGTERM before SIGKILL.
	killTimeout = 10 * time.Second

	// tailLines is how much of the daemon's own output to keep, so a failure can be
	// reported in its words rather than as an exit code.
	tailLines = 64
)

// Supervisor runs anchord and keeps the configured anchor inside it.
type Supervisor struct {
	Dirs     paths.Dirs
	Reporter Reporter

	// Ready is closed once the anchor is up. The service integrations use it to
	// tell the service manager the unit has actually started.
	Ready chan struct{}

	tools *libexec.Tools
	ctl   *anchorctl.Ctl
	tail  *ring
	once  sync.Once

	// links counts how many times a dead uplink has been reopened, so that a
	// machine quietly restarting its anchor every few minutes says so in
	// conflux status rather than looking like it has simply been up all along.
	links atomic.Int64
}

// LinkReopens is how many times the uplink has been found dead and the anchor
// rebuilt on it.
func (s *Supervisor) LinkReopens() int64 { return s.links.Load() }

func (s *Supervisor) report() Reporter {
	if s.Reporter == nil {
		return nopReporter{}
	}

	return s.Reporter
}

func (s *Supervisor) signalReady() {
	s.once.Do(func() {
		if s.Ready != nil {
			close(s.Ready)
		}
	})
}

// Run starts anchord, brings the anchor up, and keeps both going until the context
// is cancelled.
func (s *Supervisor) Run(ctx context.Context) error {
	if err := s.Dirs.EnsureAll(); err != nil {
		return err
	}

	if err := s.Dirs.CheckSocketLen(); err != nil {
		return err
	}

	// Nothing to supervise. Distinguished from a failure so the unit can stop
	// instead of restarting into the same emptiness every five seconds.
	if _, err := config.Load(s.Dirs); err != nil {
		if os.IsNotExist(err) {
			return ErrNotConfigured
		}

		return err
	}

	tools, err := libexec.Ensure(s.Dirs)
	if err != nil {
		return err
	}

	s.tools = tools
	s.tail = newRing(tailLines)

	token, err := s.freshToken()
	if err != nil {
		return err
	}

	s.ctl = &anchorctl.Ctl{
		Bin:    tools.Anchorctl,
		Socket: s.Dirs.Socket(),
		Token:  token,
		SetID:  tools.SetID,
	}

	return s.loop(ctx)
}

// loop is spawn, bring up, watch, back off, repeat.
func (s *Supervisor) loop(ctx context.Context) error {
	backoff := time.Second

	const maxBackoff = 30 * time.Second

	var permanentFailures int

	for {
		startedAt := time.Now()

		err := s.cycle(ctx)

		if ctx.Err() != nil {
			return nil
		}

		// A configuration anchor itself refuses will be refused again in five
		// seconds and in five hours. Give up after a few so the service manager
		// shows a failed unit rather than a hot loop nobody is watching.
		if isPermanent(err) {
			permanentFailures++
			if permanentFailures >= 3 {
				return fmt.Errorf("anchord will not start with this configuration: %w", err)
			}
		} else {
			permanentFailures = 0
		}

		if err != nil {
			s.report().Warn("%v", err)
		}

		// A daemon that ran healthily for a while and then died is not in a crash
		// loop; start its backoff over.
		if time.Since(startedAt) > 5*time.Minute {
			backoff = time.Second
		}

		s.report().Step("restarting in %s", backoff)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}

		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// cycle is one daemon lifetime.
func (s *Supervisor) cycle(ctx context.Context) error {
	cmd, done, err := s.spawn(ctx)
	if err != nil {
		return err
	}

	defer s.shutdown(cmd, done)

	if err := s.waitReady(ctx, done); err != nil {
		return err
	}

	started, err := BringUp(ctx, s.Dirs, s.ctl, s.report())
	if err != nil {
		return err
	}

	s.report().Step("anchor %s is up", started.ID)
	s.signalReady()

	renewCtx, stopRenewals := context.WithCancel(ctx)
	defer stopRenewals()

	go s.renewLoop(renewCtx)

	// Only for an anchor on a link. On the host's network a change is anchor's own
	// business, and it recovers in-process without conflux knowing.
	if cfg, err := config.Load(s.Dirs); err == nil && cfg.Uplink != "" {
		go s.linkLoop(renewCtx, cfg.Uplink)
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-done:
		if err != nil {
			return fmt.Errorf("anchord exited: %w\n%s", err, s.tail.String())
		}

		return errors.New("anchord exited unexpectedly\n" + s.tail.String())
	}
}

// spawn starts anchord.
//
// Its output goes to pipes and never to os.Stdout. The previous conflux wired them
// straight through, and the Windows service then had to grow a whole fallback path
// because a LocalSystem service has no valid stdout handle to inherit. Pipes also
// give us the last few lines to attach to a startup failure, which an exit code
// alone cannot explain.
func (s *Supervisor) spawn(ctx context.Context) (*exec.Cmd, <-chan error, error) {
	args := []string{"-socket", s.Dirs.Socket(), "-token-file", s.Dirs.TokenFile()}
	if os.Getenv("CONFLUX_DEBUG") == "1" {
		args = append(args, "-v")
	}

	// A socket left by a crashed daemon would otherwise make readiness think a
	// dead process is alive.
	_ = os.Remove(s.Dirs.Socket())

	cmd := exec.Command(s.tools.Anchord, args...) //nolint:gosec // our own extracted binary
	cmd.SysProcAttr = procAttr()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start anchord: %w", err)
	}

	go s.drain(stdout)
	go s.drain(stderr)

	done := make(chan error, 1)

	go func() { done <- cmd.Wait() }()

	return cmd, done, nil
}

func (s *Supervisor) drain(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := sc.Text()
		s.tail.add(line)
		s.report().Step("anchord: %s", line)
	}
}

// waitReady replaces the fixed one-second sleep the previous conflux used in three
// places, which was too long on a fast machine, too short on a slow one, and never
// noticed that the daemon had died.
func (s *Supervisor) waitReady(ctx context.Context, done <-chan error) error {
	deadline := time.Now().Add(readyTimeout)
	wait := 50 * time.Millisecond

	for {
		// The case a sleep can never catch: the child is already gone.
		select {
		case err := <-done:
			return fmt.Errorf("anchord exited before it was ready: %w\n%s", err, s.tail.String())
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := s.probe(ctx); err == nil {
			return nil
		} else if permanent := probeIsFatal(err); permanent != nil {
			return permanent
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("anchord did not answer on %s within %s\n%s",
				s.Dirs.Socket(), readyTimeout, s.tail.String())
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}

		if wait < 250*time.Millisecond {
			wait *= 2
		}
	}
}

// probe is a real readiness check and not a file test.
//
// A socket on disk proves nothing: a crashed daemon leaves one behind. Dialling
// proves something is listening. Only an authenticated status call proves that the
// socket is bound, that gRPC is serving, and that the token both sides hold agree.
func (s *Supervisor) probe(ctx context.Context) error {
	if _, err := os.Stat(s.Dirs.Socket()); err != nil {
		return err
	}

	conn, err := net.DialTimeout("unix", s.Dirs.Socket(), 500*time.Millisecond)
	if err != nil {
		return err
	}

	conn.Close()

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	return s.ctl.Ping(ctx)
}

// probeIsFatal picks out the failures that retrying cannot fix.
func probeIsFatal(err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("cannot reach anchord's socket: %w\n  this usually means conflux is not running as root", err)
	}

	var e *anchorctl.Error
	if errors.As(err, &e) && strings.Contains(strings.ToLower(e.Stderr), "token") {
		return fmt.Errorf("anchord refused conflux's bearer token: %s", strings.TrimSpace(e.Stderr))
	}

	return nil
}

// shutdown closes the anchor and then the daemon, in that order.
//
// The order is the point. `anchorctl stop` closes the anchor so it says goodbye, and
// an announced departure saves every peer from working it out by timeout. Killing
// the process is only safe because that has already happened.
func (s *Supervisor) shutdown(cmd *exec.Cmd, done <-chan error) {
	stopCtx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()

	if err := s.ctl.Stop(stopCtx); err != nil {
		s.report().Warn("could not close the anchor cleanly: %v", err)
	}

	if cmd.Process == nil {
		return
	}

	terminate(cmd)

	select {
	case <-done:
	case <-time.After(killTimeout):
		s.report().Warn("anchord did not exit in %s; killing it", killTimeout)
		_ = cmd.Process.Kill()
		<-done
	}

	_ = os.Remove(s.Dirs.Socket())
}

// renewLoop keeps the credential current while the anchor runs.
func (s *Supervisor) renewLoop(ctx context.Context) {
	for {
		st, err := config.LoadState(s.Dirs)
		if err != nil {
			return
		}

		wait := SleepUntilRenewal(st.IssuedAt, st.NotAfter, time.Now())

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		if !DueAt(st.IssuedAt, st.NotAfter, time.Now()) {
			continue
		}

		if err := s.renewOnce(ctx); err != nil {
			s.report().Warn("renewal failed: %v", err)
		}
	}
}

// freshToken writes a new bearer token for this daemon's lifetime.
//
// Fresh on every start rather than persisted: it authenticates a socket that is
// recreated anyway, rotating it costs nothing, and it means a token left behind by
// a crashed run can never authenticate against a new daemon.
func (s *Supervisor) freshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	token := hex.EncodeToString(b)

	// No trailing newline: the file is read by conflux as well as by anchord.
	if err := config.WriteFileAtomic(s.Dirs.TokenFile(), []byte(token), 0o600); err != nil {
		return "", fmt.Errorf("write the control token: %w", err)
	}

	return token, nil
}

// isPermanent reports whether an error will still be an error after a wait.
func isPermanent(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, ErrNotConfigured) {
		return true
	}

	var e *anchorctl.Error
	if errors.As(err, &e) {
		s := strings.ToLower(e.Stderr)
		for _, phrase := range []string{
			"needs userspace mode",
			"needs enabletun",
			"is not an overlay port",
			"invalid argument",
			"taints",
			"matches nothing",

			// An interface name another interface already holds. Not permanent in
			// the strictest sense -- the holder could go away -- but it will not
			// free itself inside thirty seconds of backoff, and two conflux
			// installations on one machine hit this every time, because both
			// default to anchor0. Retrying to the 90-second unit timeout buries the
			// reason in the journal; failing in three seconds puts it in front of
			// somebody who can pass --interface.
			"device or resource busy",
		} {
			if strings.Contains(s, phrase) {
				return true
			}
		}
	}

	return false
}

// ring keeps the last n lines of the daemon's output.
type ring struct {
	mu    sync.Mutex
	lines []string
	n     int
}

func newRing(n int) *ring { return &ring{n: n} }

func (r *ring) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.lines = append(r.lines, line)
	if len(r.lines) > r.n {
		r.lines = r.lines[len(r.lines)-r.n:]
	}
}

func (r *ring) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.lines) == 0 {
		return "  (anchord said nothing)"
	}

	var b strings.Builder
	for _, l := range r.lines {
		b.WriteString("  anchord: ")
		b.WriteString(l)
		b.WriteByte('\n')
	}

	return strings.TrimRight(b.String(), "\n")
}
