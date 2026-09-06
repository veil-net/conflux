//go:build !linux

package cli

// notifyReadyWhen has no counterpart outside systemd. launchd infers readiness from
// the process staying alive, and the Windows SCM is told directly by the service
// handler.
func notifyReadyWhen(<-chan struct{}) {}
