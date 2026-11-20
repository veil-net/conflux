package cli

import "context"

// hangupContext is ctx on Windows, where closing the console window arrives as SIGTERM
// (CTRL_CLOSE_EVENT), which Main already stops on.
func hangupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(ctx)
}
