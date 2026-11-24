package cli

import "github.com/veil-net/conflux/internal/paths"

// staleEphemeral is root as an ephemeral run that was killed left it, if one did: there,
// with nobody holding its lock.
func staleEphemeral(root string) (paths.Dirs, bool) {
	d, run := ephemeralAt(root)

	return d, run == staleRun
}
