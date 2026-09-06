package cli

import "github.com/veil-net/conflux/internal/ui"

// reporter prints what the shared bring-up path is doing, for the commands a person
// is watching.
type reporter struct{ quiet bool }

func (r reporter) Step(format string, a ...any) {
	if r.quiet {
		return
	}

	ui.Printf("  "+format+"\n", a...)
}

func (r reporter) Warn(format string, a ...any) { ui.Warnf(format, a...) }

// runtimeOS is indirected so journalHint stays testable.
var runtimeOS = func() string { return goos }
