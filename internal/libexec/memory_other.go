//go:build !linux

package libexec

// InMemory is ErrNoMemoryExec here: only Linux runs a program from memory that Go can start.
func InMemory() (*Tools, error) { return nil, ErrNoMemoryExec }

// AnchorctlInMemory is ErrNoMemoryExec here, as InMemory is.
func AnchorctlInMemory() (*Tools, error) { return nil, ErrNoMemoryExec }
