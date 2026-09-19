//go:build !unix && !windows

package ui

// isTerminal is false where conflux has no way to ask. It ships for no such
// platform; this is here so the package still builds on one, and "no terminal"
// is the safe answer to a question that cannot be put.
func isTerminal(uintptr) bool { return false }
