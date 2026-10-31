//go:build !darwin && !linux && !windows

package daemon

// bpfFacts has no device to describe on the BSDs, which share macOS's probe and have no
// capture for the observer at all.
func bpfFacts() (*fileFacts, int) { return nil, -1 }
