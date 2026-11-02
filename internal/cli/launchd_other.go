//go:build !darwin

package cli

// launchdExit is the supervisor's exit unchanged: only launchd needs it told otherwise.
func launchdExit(code int) int { return code }
