package pathstest

import (
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privtest"
)

// Every test linking this package makes what it makes the Administrators', as every conflux process
// does as it starts (paths.ElevatedDefaultOwner), and roots it, its CONFLUX_DIRs among it, on a way
// the boot service trusts (privtest.ServiceTemp): EnsureAll holds an installation's way to the rule
// SYSTEM holds it to at every start, which the administrator's own profile, where %TEMP% is, does
// not pass.
func init() {
	if err := paths.ElevatedDefaultOwner(); err != nil {
		panic("pathstest: " + err.Error())
	}

	if err := privtest.ServiceTemp(); err != nil {
		panic("pathstest: " + err.Error())
	}
}
