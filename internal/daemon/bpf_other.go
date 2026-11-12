//go:build !darwin

package daemon

// There are BPF devices to open up only on macOS: Linux captures with a capability,
// Windows through a trace session its accounts may start, and the BSDs not at all. So there
// is nothing to give back elsewhere.

// RevokeBPF has nothing to give back here.
func RevokeBPF() error { return nil }
