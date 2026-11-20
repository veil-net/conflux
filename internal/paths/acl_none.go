//go:build !windows && !linux

package paths

// extendedWriters is who p's ACL lets write it: nobody's here, where its mode is the whole of
// who may.
func extendedWriters(string) ([]writer, bool, error) { return nil, false, nil }
