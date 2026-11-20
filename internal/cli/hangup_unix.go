//go:build !windows

package cli

import (
	"context"
	"os/signal"
	"syscall"
)

// hangupContext adds SIGHUP to what ends ctx: an ephemeral run in a terminal that is closed
// stops cleanly, as it does on Ctrl-C, rather than being left for the kernel to kill. Not where
// conflux was started ignoring it (catches), as nohup starts it, to run on once the terminal
// has gone.
func hangupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if !catches(syscall.SIGHUP) {
		return context.WithCancel(ctx)
	}

	return signal.NotifyContext(ctx, syscall.SIGHUP)
}
