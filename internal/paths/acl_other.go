//go:build !windows

package paths

// Restrict, Trusted and secure are Windows's. Elsewhere a mode set on the descriptor
// and a 0700 directory created by root are the whole of it.

// Restrict is a no-op here.
func Restrict(string, bool) error { return nil }

// Trusted is always true here.
func Trusted(string) bool { return true }

func secure(string) error { return nil }
