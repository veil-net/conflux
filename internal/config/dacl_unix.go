//go:build !windows

package config

import "errors"

// errUnsupportedDirSync is never returned on Unix; it exists so the shared code in
// atomic.go compiles against one name on both sides.
var errUnsupportedDirSync = errors.New("unsupported")

// restrictToAdmins is a no-op: the mode bits set on the descriptor are real here.
func restrictToAdmins(string) error { return nil }
