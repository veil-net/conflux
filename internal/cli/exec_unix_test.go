//go:build !windows

package cli

import (
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestAChildAnchorctlIsSentWhatConfluxIs: an anchorctl conflux runs as its child, a temporary
// copy, is sent the SIGTERM conflux is, and ends on it, where Main's context would otherwise
// take the signal and leave conflux waiting for a child nothing told to end.
func TestAChildAnchorctlIsSentWhatConfluxIs(t *testing.T) {
	// As Main does, so the SIGTERM below is conflux's to take, and does not end the test.
	_, stop := signal.NotifyContext(t.Context(), os.Interrupt, unix.SIGTERM)
	defer stop()

	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	bin := filepath.Join(dir, "anchorctl")

	script := "#!/bin/sh\ntrap 'exit 7' TERM\necho $$ > \"$READY.tmp\" && mv \"$READY.tmp\" \"$READY\"\n" +
		"while :; do sleep 0.05; done\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	code := make(chan int, 1)

	go func() { code <- runAnchorctl(bin, nil, append(os.Environ(), "READY="+ready)) }()

	var pid int

	for deadline := time.Now().Add(10 * time.Second); pid == 0; time.Sleep(10 * time.Millisecond) {
		if b, err := os.ReadFile(ready); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		} else if time.Now().After(deadline) {
			t.Fatal("the stand-in anchorctl never started")
		}
	}

	if err := unix.Kill(os.Getpid(), unix.SIGTERM); err != nil {
		t.Fatal(err)
	}

	select {
	case c := <-code:
		if c != 7 {
			t.Errorf("the child anchorctl exited %d, want 7, its answer to SIGTERM", c)
		}
	case <-time.After(5 * time.Second):
		_ = unix.Kill(pid, unix.SIGKILL)

		t.Error("the SIGTERM conflux was sent never reached its child anchorctl")
		<-code
	}
}
