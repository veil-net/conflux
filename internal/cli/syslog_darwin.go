package cli

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/veil-net/conflux/internal/service"
)

// toSystemLog sends what this process writes -- its own lines, and the runtime's trace should
// it crash -- to the unified log, tagged conflux, through a logger(1) of its own, where launchd
// started it: launchd keeps no output, and conflux keeps no log file. Run by hand, its output
// stays where it was.
//
// The logger is a process group of its own, so the signal launchd sends the job's group to
// stop it leaves the logger reading to the end of what conflux wrote. SIGPIPE is ignored, so
// a logger that went away costs the log and not the supervisor.
func toSystemLog() {
	if os.Getenv("XPC_SERVICE_NAME") != service.Label {
		return
	}

	r, w, err := os.Pipe()
	if err != nil {
		return
	}

	logger := exec.Command("/usr/bin/logger", "-t", "conflux")
	logger.Stdin = r
	logger.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err = logger.Start()
	r.Close()

	if err != nil {
		w.Close()

		return
	}

	signal.Ignore(syscall.SIGPIPE)

	_ = unix.Dup2(int(w.Fd()), int(os.Stdout.Fd()))
	_ = unix.Dup2(int(w.Fd()), int(os.Stderr.Fd()))
	w.Close()
}
