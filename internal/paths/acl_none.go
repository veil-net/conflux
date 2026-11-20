//go:build !windows && !linux && !darwin && !freebsd

package paths

// rootACLMayRefuse is whether a root's own ACL can refuse it once secure has narrowed it: not
// where there is none, which extendedWriters returns (TestARootsACLIsLeftUnreadOnlyBesideAPOSIXReader).
const rootACLMayRefuse = false

// extendedWriters is who p's ACL lets write it: nobody here, where a directory carries no ACL
// (OpenBSD keeps none) and its mode is the whole of who may.
func extendedWriters(string) ([]writer, bool, error) { return nil, false, nil }
