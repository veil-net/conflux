//go:build !linux

package paths

import "errors"

// runtimeFolder is Linux's: an ephemeral run is refused everywhere else, and there is none to find.
func runtimeFolder() (string, error) { return "", errors.New("an ephemeral run is Linux's alone") }
