//go:build darwin || freebsd

package service

import "github.com/veil-net/conflux/internal/paths"

// logFile is the service's log: what launchd or daemon(8) is given for what conflux cannot
// write itself, and what `serve --log` writes, stamped and moved aside to .1 when full.
// logfile.Remove takes both.
func logFile() string { return paths.Default().LogFile() }

// withLog is the service's serve argv, told where its log is.
func withLog(args []string) []string {
	return append(append([]string(nil), args...), "--log", logFile())
}
