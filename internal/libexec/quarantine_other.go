//go:build !darwin

package libexec

// clearQuarantine is macOS's: nowhere else does a process pass an attribute to what it
// writes that stops it running. Windows's nearest, SmartScreen and Defender, is no
// attribute a process can clear.
func clearQuarantine(string) {}
