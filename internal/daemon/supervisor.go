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
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/wintun"
)

// The supervisor is what the service manager actually runs.
//
//	systemd / launchd / rc / SCM
//	  └── conflux serve                  root, or SYSTEM
//	        ├── anchord -socket … -config …   as its own account wherever that costs nothing; see privilege.go
//	        ├── the renewal timer, beside an anchor
//	        ├── the watcher: a lost anchor, on an uplink an ended link, and an observer whose capture ended
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

	// Drop lets the supervisor start anchord as its own unprivileged account where its
	// mode and the host allow. The service sets it; a test leaves it off, so a test run
	// as root makes no account.
	Drop bool

	tools *libexec.Tools
	ctl   *anchorctl.Ctl
	tail  *ring
	once  sync.Once

	// priv is what the running anchord was started with, and lastDir the anchor
	// directory the last one was given, which the next starts from when it is given
	// the other.
	priv    Privilege
	lastDir string

	// respawn ends the cycle so the next starts anchord with what it now needs.
	respawn chan struct{}

	// observing is whether the running anchord was started to observe: what shutdown stops
	// before it kills a daemon it cannot signal.
	observing bool

	drop dropState
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

	// One supervisor per root, held for as long as this one runs: what it does next is stop
	// the anchord the last one left, and two would each take the other's for that. First,
	// so a second is told that whatever else about the root it would refuse.
	unlock, ok, err := flock.TryAcquire(s.Dirs.ServeLockFile())
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("another conflux supervisor is already serving %s; "+
			"stop it first (conflux down)", s.Dirs.State)
	}
	defer unlock()

	if err := s.Dirs.CheckSocketLen(); err != nil {
		return &permanentError{err: err}
	}

	switch pid, err := ReapOrphan(s.Dirs); {
	case err != nil:
		s.report().Warn("%v", err)
	case pid != 0:
		s.report().Warn("stopped anchord (pid %d), left running by a supervisor that ended without stopping it", pid)
	}

	// conflux 1.0.0 kept the socket in the run directory itself. The daemon that held it
	// is gone by now, and so the two names are nothing's.
	if held, err := flock.Held(s.Dirs.LegacySocket() + ".lock"); err == nil && !held {
		_ = os.Remove(s.Dirs.LegacySocket())
		_ = os.Remove(s.Dirs.LegacySocket() + ".lock")
	}

	if p, ok := RecordedPrivilege(s.Dirs); ok {
		s.lastDir = p.Dir
	}

	// Before anything else can be asked about, because nothing is up yet and a marker
	// saying otherwise is a lie the whole mechanism rests on not telling. Two of the
	// three platforms clear the run directory for us -- systemd's RuntimeDirectory= on
	// stop, and /var/run at boot on macOS -- and Windows does not: %ProgramData%\conflux
	// \run survives a reboot, so a marker written before a power cut would still be
	// there when this starts.
	s.clearReady()

	// Nothing to supervise, or nothing it will start on, before anything is extracted.
	// Distinguished from a failure so the unit can stop instead of restarting into the
	// same answer every five seconds.
	if _, err := loadConfig(s.Dirs); err != nil {
		return err
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
		if Permanent(err) {
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
	s.respawn = make(chan struct{}, 1)

	cfg, c, err := s.spawn(ctx)
	if err != nil {
		return err
	}

	defer s.shutdown(c)

	if err := s.waitReady(ctx, c); err != nil {
		return err
	}

	// The observer before the anchor, because it needs nothing the anchor does -- no
	// credential, no enrolment, no realm -- and an anchor that cannot come up must not keep
	// it from observing. Observing alone, a refusal is the cycle's: there is nothing else
	// to run. Beside an anchor it is said, and the anchor starts without it.
	if cfg.Observer != nil {
		if err := s.startObserver(ctx, cfg); err != nil {
			if !cfg.Anchor() {
				return err
			}

			s.report().Warn("the observer did not start, and the anchor starts without it: %v", err)
		}
	}

	if cfg.Anchor() {
		ready, err := s.anchorUp(ctx, cfg)
		if err != nil {
			return err
		}

		if ready != "" {
			s.signalReady(ready)
		}
	} else {
		s.signalReady("observer")
	}

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

	if cfg.Anchor() {
		wg.Go(func() { s.renewLoop(loops) })
	}

	wg.Go(func() {
		if s.watch(loops, cfg, checkInterval(cfg)) {
			stopLoops()
		}
	})

	select {
	case <-ctx.Done():
		return nil
	case <-c.exited:
		return c.gone("unexpectedly", s.tail)
	case <-s.respawn:
		return errRespawn
	}
}

// anchorUp brings the configured anchor up in the daemon, and says what readiness to
// record: the anchor's ID, or nothing yet.
//
// An anchor that cannot come up for now -- an enrolment the API does not answer, say -- ends
// the cycle, unless the observer runs beside it: then the daemon is kept, and with it the
// observer and the inventory it holds, and the watcher brings the anchor up when it can, as it
// rebuilds one that is lost. A refusal for good ends the cycle either way.
func (s *Supervisor) anchorUp(ctx context.Context, cfg *config.Config) (string, error) {
	// Windows needs the driver beside anchord before an interface can exist, and it
	// lives in the content-addressed set directory: an upgraded conflux extracts a new
	// set with no wintun.dll in it, and a boot must not need somebody to run `up`.
	if cfg.Mode == config.ModeTUN {
		if err := wintun.Ensure(ctx, s.Dirs); err != nil {
			return "", err
		}
	}

	started, err := bringUp(ctx, s.Dirs, s.ctl, s.report(), s.priv.Dir, false)

	switch {
	case err == nil:
		s.report().Step("anchor %s is up", started.ID)

		return started.ID, nil
	case s.redecided():
		// A start the decision no longer fits -- the first enrolment named a port only
		// root may bind -- is one the next cycle makes with what it needs. Not wrapped, so a
		// refusal for good does not count against the configuration.
		return "", fmt.Errorf("%w: %v", errRespawn, err)
	case cfg.Observer != nil && !Permanent(err):
		s.report().Warn("the anchor did not come up, and the observer goes on without it until it does: %v", err)

		return "", nil
	default:
		return "", err
	}
}

// startObserver starts the daemon's observer with what conflux.json asks of it. anchord
// keeps no observer across a restart, so every daemon is asked afresh.
func (s *Supervisor) startObserver(ctx context.Context, cfg *config.Config) error {
	start, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()

	if err := s.ctl.ObserveStart(start, *cfg.Observer); err != nil {
		return fmt.Errorf("starting the observer: %w", err)
	}

	where := "kept in the daemon's inventory"
	if cfg.Exports() {
		where = "each sent to " + cfg.Export.Endpoint + " as it is made"
	}

	s.report().Step("observing; the records are %s", where)

	return nil
}

// anchordArgs is everything anchord is started with.
//
// A function rather than three lines inside spawn, so the argument vector can be
// asserted without starting a process. -config is what carries conflux.json's export
// block into the daemon on every start; see writeDaemonConfig. -allow-observer only where
// the configuration observes: the Observer service has the host copy the start of every
// flow it carries to the daemon, and a daemon not asked to observe should not be able to.
//
// No -token-file: the token arrives as ANCHORD_TOKEN (anchor's contract.Token), so the
// file the CLI reads it from stays root's whoever anchord runs as.
func anchordArgs(d paths.Dirs, cfg *config.Config) []string {
	args := []string{
		"-socket", d.Socket(),
		"-config", d.DaemonConfigFile(),
	}

	if cfg.Observer != nil {
		args = append(args, "-allow-observer")
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
	cmd     *exec.Cmd
	exited  chan struct{}
	err     error  // Wait's answer, read only once exited is closed
	release func() // ends whatever anchord left behind it, once it has gone
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
	//
	// Validated before anchord reads any of it. A block anchord refuses is fatal to it at
	// startup, which would otherwise read as a daemon dying before it answered and be
	// retried for ever, where this is a file no retry changes.
	cfg, err := loadConfig(s.Dirs)
	if err != nil {
		return nil, nil, err
	}

	p := s.privilege(cfg)

	// The BPF devices the account was given for an earlier observer, given back where this
	// anchord does not read them through its own group: one that does not observe, or runs
	// as root. Nothing off macOS.
	if p.BPF != BPFOwn {
		if err := RevokeBPF(); err != nil {
			s.report().Warn("could not give /dev/bpf* back to root alone: %v", err)
		}
	}

	// Whatever the account's directories need that the host will not let the supervisor
	// do, anchord runs as the supervisor instead, which loses nothing it had before.
	if err := s.prepare(&p); err != nil {
		if !p.Account {
			return nil, nil, err
		}

		s.report().Warn("could not prepare anchord's directories for %s: %v", p.As, err)

		p = asSupervisor("could not prepare its directories for its own account: " + firstLine(err))
		p.As = supervisorName()

		if err := s.prepare(&p); err != nil {
			return nil, nil, err
		}
	}

	if err := writeDaemonConfig(s.Dirs, cfg, p); err != nil {
		return nil, nil, err
	}

	s.report().Step("starting anchord as %s", p)

	out := s.lines()

	cmd := exec.Command(s.tools.Anchord, anchordArgs(s.Dirs, cfg)...) //nolint:gosec // our own extracted binary
	cmd.SysProcAttr = s.procAttrFor(p)
	cmd.Env = anchordEnv(p, s.ctl.Token)
	cmd.Dir = workDir
	cmd.Stdout, cmd.Stderr = out, out

	// What anchord started can hold its output open after it has gone; Wait gives up on
	// the pipe this long after the exit rather than waiting with it.
	cmd.WaitDelay = 5 * time.Second

	err = startProcess(cmd, p)
	s.releaseDrop()

	if err != nil {
		return nil, nil, fmt.Errorf("start anchord as %s: %w", p.As, err)
	}

	release, err := bind(cmd.Process)
	if err != nil {
		s.report().Warn("anchord will not end with this process if it is killed: %v", err)
	}

	if err := recordDaemon(s.Dirs, cmd.Process.Pid, s.tools.Anchord); err != nil {
		s.report().Warn("could not record anchord's pid: %v", err)
	}

	if err := recordPrivilege(s.Dirs, p); err != nil {
		s.report().Warn("could not record what anchord runs as: %v", err)
	}

	s.priv, s.lastDir, s.observing = p, p.Dir, cfg.Observer != nil

	c := &child{cmd: cmd, exited: make(chan struct{}), release: release}

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

	// Whatever anchord started that outlived it: its job, on Windows, and on Unix what
	// still runs as its account.
	if c.release != nil {
		c.release()
	}

	if s.priv.Account {
		s.killLeftovers()
	}

	// Waited for, so the record no longer names a process of ours.
	forgetDaemon(s.Dirs)

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

		// The observer first: on Windows its capture is a kernel trace session, which
		// outlives a process that is killed and goes on copying every packet the host
		// carries until something stops it.
		if s.observing {
			if err := s.ctl.ObserveStop(ctx); err != nil {
				s.report().Warn("could not stop the observer cleanly: %v", err)
			}
		}

		if err := s.ctl.Stop(ctx); err != nil {
			s.report().Warn("could not close the anchor cleanly: %v", err)
		}

		cancel()
	}

	kill(c.cmd)
	<-c.exited
}

// renewLoop keeps the credential current while the anchor runs.
//
// It re-reads the state every round rather than trusting what it read before
// sleeping, so a renewal somebody ran by hand in between moves the next one along.
// A failed renewal is retried after minSleep. A credential that does not renew ends
// the loop: the manifest cannot change while this process holds it, so asking again
// would only say the same thing every minute.
func (s *Supervisor) renewLoop(ctx context.Context) {
	for {
		wait := minSleep

		switch st, err := config.LoadState(s.Dirs); {
		case err != nil:
			s.report().Warn("could not read %s: %v", s.Dirs.StateFile(), err)
		case dueAt(st.IssuedAt, st.NotAfter, time.Now()):
			if err := RenewNow(ctx, s.Dirs, s.ctl, s.report()); errors.Is(err, enrol.ErrDoesNotRenew) {
				s.report().Warn("%v", err)

				return
			} else if err != nil {
				s.report().Warn("renewal failed: %v", err)
			} else {
				continue
			}
		default:
			wait = sleepUntilRenewal(st.IssuedAt, st.NotAfter, time.Now())
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

// Permanent reports whether err is a refusal no restart changes -- a configuration
// conflux or anchor will not start on -- as distinct from a failure the next start may
// not meet. `conflux serve` exits on it with the status the service manager does not
// restart.
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
func Permanent(err error) bool {
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
		// A host that will not let the daemon capture, or a platform with no capture:
		// anchorctl's hint for REASON_CAPTURE_UNAVAILABLE, which no retry changes. The
		// privilege is the supervisor's to give at a spawn, and it gave what it could.
		"capturing needs cap_net_raw",
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
