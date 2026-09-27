//go:build !windows

package config

// restrictToAdmins is a no-op: the mode bits set on the descriptor are real here.
func restrictToAdmins(string) error { return nil }
