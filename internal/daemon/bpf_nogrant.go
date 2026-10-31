//go:build !darwin && !windows

package daemon

// grantBPF has no device to give off macOS, where decide never asks it to.
func grantBPF(int) error { return nil }
