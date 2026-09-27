package cli

import "github.com/veil-net/conflux/internal/ui"

// reporter prints what the shared bring-up path is doing, for the commands a person
// is watching.
type reporter struct{}

func (reporter) Step(format string, a ...any) { ui.Printf("  "+format+"\n", a...) }

func (reporter) Warn(format string, a ...any) { ui.Warnf(format, a...) }
