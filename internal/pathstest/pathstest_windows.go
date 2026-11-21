package pathstest

import "github.com/veil-net/conflux/internal/privtest"

// Every test linking this package roots what it makes, its CONFLUX_DIRs among them, on a way the
// boot service trusts (privtest.ServiceTemp): EnsureAll holds an installation's way to the rule
// SYSTEM holds it to at every start, which the administrator's own profile, where %TEMP% is,
// does not pass.
func init() {
	if err := privtest.ServiceTemp(); err != nil {
		panic("pathstest: " + err.Error())
	}
}
