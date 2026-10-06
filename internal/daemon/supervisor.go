package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/wintun"
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

	// stopTimeout bounds closing the anchor over the socket, where that is how it is
	// closed: a daemon no signal reaches, and an uplink being reopened.
	stopTimeout = 20 * time.Second

	// killTimeout is how long after SIGTERM before SIGKILL. The same budget as the
	// socket's close, because on a signal anchord does that close itself -- the anchor,
	// then its control plane's 5s grace, then 5s to flush telemetry -- and it stays
	// inside the unit's 30s TimeoutStopSec.
	killTimeout = 20 * time.Second

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
}

func (s *Supervisor) report() Reporter {
	if s.Reporter == nil {
		return nopReporter{}
	}

	return s.Reporter
}

// signalReady records that an anchor is up, for the two things that need to know.
//
// The channel is closed once, because that is what the service integrations want: launchd
// and the Windows SCM are told the unit started, and telling them twice means nothing. The
// marker file is written on every cycle, because a crash-and-restart clears it on the way
// down and the next `conflux status` or `conflux up` would otherwise wait out its fallback
// for an anchor that is already running.
func (s *Supervisor) signalReady(id string) {
	if err := MarkReady(s.Dirs, id); err != nil {
		// Never fatal. The marker is an optimisation over a status call that still
		// works, so losing it costs a second of polling and not a start.
		s.report().Warn("could not record readiness: %v", err)
	}

	s.once.Do(func() {
		if s.Ready != nil {
			close(s.Ready)
		}
	})
}

// clearReady withdraws the marker. Best effort: a stale marker costs one status call,
// which is what the fallback is for.
func (s *Supervisor) clearReady() { _ = ClearReady(s.Dirs) }

// Run starts anchord, brings the anchor up, and keeps both going until the context
// is cancelled.
func (s *Supervisor) Run(ctx context.Context) error {
	if err := s.Dirs.EnsureAll(); err != nil {
		return err
	}

	if err := s.Dirs.CheckSocketLen(); err != nil {
		return err
	}

	// Before anything else can be asked about, because nothing is up yet and a marker
	// saying otherwise is a lie the whole mechanism rests on not telling. Two of the
	// three platforms clear the run directory for us -- systemd's RuntimeDirectory= on
	// stop, and /var/run at boot on macOS -- and Windows does not: %ProgramData%\conflux
	// \run survives a reboot, so a marker written before a power cut would still be
	// there when this starts.
	s.clearReady()

	// Nothing to supervise. Distinguished from a failure so the unit can stop
	// instead of restarting into the same emptiness every five seconds.
	if _, err := config.Load(s.Dirs); err != nil {
		if os.IsNotExist(err) {
			return ErrNotConfigured
		}

		return &permanentError{err: err} // names the file already
	}

	tools, err := libexec.Ensure(s.Dirs)
	if err != nil {
		return err
	}

	// This supervisor is the one running the service now, so no other set is in use by it.
	go libexec.Sweep(tools)

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
	cfg, c, err := s.spawn(ctx)
	if err != nil {
		return err
	}

	defer s.shutdown(c)

	if err := s.waitReady(ctx, c); err != nil {
		return err
	}

	// Windows needs the driver beside anchord before an interface can exist, and it
	// lives in the content-addressed set directory: an upgraded conflux extracts a new
	// set with no wintun.dll in it, and a boot must not need somebody to run `up`.
	if cfg.Mode == config.ModeTUN {
		if err := wintun.Ensure(ctx, s.Dirs); err != nil {
			return err
		}
	}

	started, err := BringUp(ctx, s.Dirs, s.ctl, s.report())
	if err != nil {
		return err
	}

	s.report().Step("anchor %s is up", started.ID)
	s.signalReady(started.ID)

	// The timer, and the watcher that keeps an anchor in the daemon -- and on a link,
	// keeps the link carrying something. Both are finished before the daemon is shut
	// down, so neither writes state or talks to a daemon that the next cycle has already
	// replaced. A watcher that gives up on an anchor this configuration will not build
	// ends both: there is nothing left to keep, or to renew a credential for, until the
	// service is started again.
	loops, stopLoops := context.WithCancel(ctx)

	var wg sync.WaitGroup

	defer func() {
		stopLoops()
		wg.Wait()
	}()

	wg.Go(func() { s.renewLoop(loops) })
	wg.Go(func() {
		if s.watch(loops, cfg.Uplink, checkInterval(cfg.Uplink)) {
			stopLoops()
		}
	})

	select {
	case <-ctx.Done():
		return nil
	case <-c.exited:
		return c.gone("unexpectedly", s.tail)
	}
}

// anchordArgs is everything anchord is started with.
//
// A function rather than three lines inside spawn, so the argument vector can be
// asserted without starting a process. -config is what carries conflux.json's export
// block into the daemon on every start; see writeDaemonConfig.
func anchordArgs(d paths.Dirs) []string {
	args := []string{
		"-socket", d.Socket(),
		"-token-file", d.TokenFile(),
		"-config", d.DaemonConfigFile(),
	}

	if os.Getenv("CONFLUX_DEBUG") == "1" {
		args = append(args, "-v")
	}

	return args
}

// child is one anchord process, and whether it has gone.
//
// exited is closed rather than sent on, so every wait on the process -- for
// readiness, for the rest of the cycle, in shutdown -- sees the exit, however many
// of them look and in whatever order. A value sent once is taken by the first; the
// shutdown that came after it then waited forever for an exit already consumed, and
// a daemon that died was never restarted.
type child struct {
	cmd    *exec.Cmd
	exited chan struct{}
	err    error // Wait's answer, read only once exited is closed
}

// gone reports an exit nobody asked for, in anchord's own last words.
func (c *child) gone(when string, tail *ring) error {
	if c.err != nil {
		return fmt.Errorf("anchord exited %s: %w\n%s", when, c.err, tail)
	}

	return fmt.Errorf("anchord exited %s\n%s", when, tail)
}

// spawn starts anchord, and returns the configuration it was started for.
//
// Its output goes to the supervisor's reporter and to the tail kept for failure
// messages, never straight to os.Stdout: a Windows service has no valid stdout handle
// to inherit, and the last few lines are what explains a startup failure an exit
// code alone cannot.
//
// Both streams go to one writer, which os/exec gives one descriptor and one copying
// goroutine rather than a pipe and a goroutine each -- and which keeps anchord's lines
// in the order it wrote them, so the tail reads as one account rather than two.
func (s *Supervisor) spawn(ctx context.Context) (*config.Config, *child, error) {
	// The daemon's own configuration, rendered from conflux.json on every spawn.
	//
	// Passed on every start rather than only when something is configured, so that
	// the file is what the daemon believes in both directions; see writeDaemonConfig.
	cfg, err := config.Load(s.Dirs)
	if err != nil {
		return nil, nil, err
	}

	// Before anchord reads any of it. A block anchord refuses is fatal to it at startup,
	// which would otherwise read as a daemon dying before it answered and be retried for
	// ever, where this is a file no retry changes.
	if err := cfg.Validate(); err != nil {
		return nil, nil, &permanentError{path: s.Dirs.ConfigFile(), err: err}
	}

	if err := writeDaemonConfig(s.Dirs, cfg); err != nil {
		return nil, nil, err
	}

	out := s.lines()

	cmd := exec.Command(s.tools.Anchord, anchordArgs(s.Dirs)...) //nolint:gosec // our own extracted binary
	cmd.SysProcAttr = procAttr()
	cmd.Stdout, cmd.Stderr = out, out

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start anchord: %w", err)
	}

	c := &child{cmd: cmd, exited: make(chan struct{})}

	// Wait returns once the output is drained, so the tail holds anchord's last words
	// by the time anybody reads it.
	go func() {
		c.err = cmd.Wait()
		out.flush()
		close(c.exited)
	}()

	return cfg, c, nil
}

// lines is a writer for anchord's output, delivering it a line at a time to the tail
// and the reporter.
func (s *Supervisor) lines() *lineWriter {
	return &lineWriter{emit: func(line string) {
		s.tail.add(line)
		s.report().Step("anchord: %s", line)
	}}
}

// lineWriter splits what is written to it into lines. os/exec copies a writer named for
// both streams from one goroutine, so it is only ever written from one at a time.
type lineWriter struct {
	emit func(string)
	buf  []byte
}

// maxLine bounds a line that never ends, so a stream without newlines is still read
// out rather than held.
const maxLine = 64 << 10

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)

	start := 0

	for {
		i := bytes.IndexByte(w.buf[start:], '\n')
		if i < 0 {
			break
		}

		w.emit(string(bytes.TrimRight(w.buf[start:start+i], "\r")))
		start += i + 1
	}

	// What is left of an unfinished line goes back to the front, so the buffer is
	// reused rather than walked off the end of and reallocated.
	w.buf = w.buf[:copy(w.buf, w.buf[start:])]

	if len(w.buf) >= maxLine {
		w.flush()
	}

	return len(p), nil
}

// flush emits whatever is left of a line that ended without a newline.
func (w *lineWriter) flush() {
	if len(w.buf) > 0 {
		w.emit(string(w.buf))
	}

	w.buf = w.buf[:0]
}

// waitReady waits for the daemon to answer, and notices when it dies instead.
func (s *Supervisor) waitReady(ctx context.Context, c *child) error {
	deadline := time.Now().Add(readyTimeout)
	wait := 50 * time.Millisecond

	for {
		// The case a sleep can never catch: the child is already gone.
		select {
		case <-c.exited:
			return c.gone("before it was ready", s.tail)
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

	_, err = s.ctl.Status(ctx)

	return err
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

// shutdown takes the daemon down with its anchor, and returns once it has gone.
//
// The anchor is closed first either way, so it says goodbye: an announced departure
// saves every peer from working it out by timeout. Where a signal can be delivered it
// is all that is sent, because anchord closes its anchor on SIGTERM, flushes its
// telemetry and exits -- the same close `anchorctl stop` asks for, without a process
// forked to ask it. Where none can (a Windows service has no console to deliver a
// control event to), the anchor is closed over the socket instead, and the daemon,
// holding nothing by then, is killed.
//
// Nothing is asked of a daemon that has already gone. There is no anchor left to close,
// and its pid has been reaped and may belong to something else by now.
func (s *Supervisor) shutdown(c *child) {
	s.clearReady()

	select {
	case <-c.exited:
	default:
		s.stop(c)
	}

	// A daemon that exits closes its socket and the file goes with it; one that was
	// killed leaves the file, and `conflux status` and pass-through read a socket file
	// as a daemon that is running.
	_ = os.Remove(s.Dirs.Socket())
}

// stop is shutdown for a daemon that is still running.
func (s *Supervisor) stop(c *child) {
	if terminate(c.cmd) {
		select {
		case <-c.exited:
			return
		case <-time.After(killTimeout):
			s.report().Warn("anchord did not exit in %s; killing it", killTimeout)
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
		if err := s.ctl.Stop(ctx); err != nil {
			s.report().Warn("could not close the anchor cleanly: %v", err)
		}

		cancel()
	}

	_ = c.cmd.Process.Kill()
	<-c.exited
}

// renewLoop keeps the credential current while the anchor runs.
//
// It re-reads the state every round rather than trusting what it read before
// sleeping, so a renewal somebody ran by hand in between moves the next one along.
// A failed renewal is retried after MinSleep. A credential that does not renew ends
// the loop: the manifest cannot change while this process holds it, so asking again
// would only say the same thing every minute.
func (s *Supervisor) renewLoop(ctx context.Context) {
	for {
		wait := MinSleep

		switch st, err := config.LoadState(s.Dirs); {
		case err != nil:
			s.report().Warn("could not read %s: %v", s.Dirs.StateFile(), err)
		case DueAt(st.IssuedAt, st.NotAfter, time.Now()):
			if err := RenewNow(ctx, s.Dirs, s.ctl, s.report()); errors.Is(err, enrol.ErrDoesNotRenew) {
				s.report().Warn("%v", err)

				return
			} else if err != nil {
				s.report().Warn("renewal failed: %v", err)
			} else {
				continue
			}
		default:
			wait = SleepUntilRenewal(st.IssuedAt, st.NotAfter, time.Now())
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
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
//
// A file conflux itself refuses, an argument vector anchorctl refuses as a usage error,
// and what anchor refuses that conflux cannot check beforehand: a credential under a
// root other than the one these binaries are pinned to; a TUN the host will not give --
// no capability, no device or no IPv6, or the name held by another interface, which two
// conflux installations both defaulting to anchor0 hit every time; and a host that will
// not be set up to forward for the realm. None frees itself inside thirty seconds of
// backoff, and failing in three puts the reason in front of somebody rather than
// burying it in the journal under a unit timeout.
//
// A served subnet the host is not attached to is deliberately absent. At boot that is
// usually an interface that has not come up yet, which a retry does fix.
// Permanent reports whether err is a refusal no restart changes -- a configuration conflux
// or anchor will not start on -- as distinct from a failure the next start may not meet.
// `conflux serve` exits on it with the status the service manager does not restart.
func Permanent(err error) bool { return isPermanent(err) }

func isPermanent(err error) bool {
	if err == nil {
		return false
	}

	var refused *permanentError
	if errors.Is(err, ErrNotConfigured) || errors.As(err, &refused) {
		return true
	}

	var e *anchorctl.Error
	if !errors.As(err, &e) {
		return false
	}

	if exit := (*exec.ExitError)(nil); errors.As(e.Err, &exit) && exit.ExitCode() == 2 {
		return true
	}

	s := strings.ToLower(e.Stderr)

	for _, phrase := range []string{
		"is not the pinned genesis",
		"will not give this process a tun device",
		"could not be set up to forward for the realm",
		// A manifest whose taints are not the ones its chain grants: conflux starts on
		// the issuer's names and checks them first, so this is the issuer's mistake, and
		// a credential's taints never change.
		"does not grant this anchor's taints",
	} {
		if strings.Contains(s, phrase) {
			return true
		}
	}

	// The kernel's answer to a TUN name another interface holds. Only a TUN's: a serial
	// line held by another process is as often a prober that lets go.
	return strings.Contains(s, "tundev: creating") && strings.Contains(s, "device or resource busy")
}

// ring keeps the last n lines of the daemon's output, in n slots allocated once:
// every line anchord writes passes through here, and almost none is ever read.
type ring struct {
	mu    sync.Mutex
	lines []string
	next  int  // the slot the next line goes in, which holds the oldest once full
	full  bool // whether every slot has been written
}

func newRing(n int) *ring { return &ring{lines: make([]string, n)} }

func (r *ring) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.lines[r.next] = line

	if r.next++; r.next == len(r.lines) {
		r.next, r.full = 0, true
	}
}

func (r *ring) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	held := r.lines[:r.next]
	if r.full {
		held = append(r.lines[r.next:len(r.lines):len(r.lines)], r.lines[:r.next]...)
	}

	if len(held) == 0 {
		return "  (anchord said nothing)"
	}

	var b strings.Builder
	for i, l := range held {
		if i > 0 {
			b.WriteByte('\n')
		}

		b.WriteString("  anchord: ")
		b.WriteString(l)
	}

	return b.String()
}
