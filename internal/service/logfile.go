//go:build darwin || freebsd

package service

import (
	"github.com/veil-net/conflux/internal/logfile"
	"github.com/veil-net/conflux/internal/paths"
)

// logFile is the service's log: what launchd or daemon(8) is given for what conflux cannot
// write itself, and what `serve --log` writes, stamped and moved aside to .1 when full.
func logFile() string { return paths.Default().LogFile() }

// removeLog deletes it, and the one moved aside from it.
func removeLog(path string) error { return logfile.Remove(path) }

// withLog is the service's serve argv, told where its log is.
func withLog(args []string) []string {
	return append(append([]string(nil), args...), "--log", logFile())
}
