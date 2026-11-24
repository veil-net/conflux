//go:build !darwin

package cli

// toSystemLog is nothing here: systemd's journal, FreeBSD's daemon(8) and OpenBSD's rc.d send
// the service's output to the system log themselves, and the Windows service writes to the
// event log (serveAsService).
func toSystemLog() {}
