//go:build !windows

package libexec

import "os"

// makeStaging makes the directory a set is written in before it takes its name, in root under a
// name nobody can foresee: 0700, the extracting account's.
func makeStaging(root string) (string, error) { return os.MkdirTemp(root, ".staging-*") }
