package service

import "testing"

// TestNewIsOneManager: the Install a caller makes and the Restart after it ask New each, and
// launchd's Restart starts nothing where that Install has just restarted the job, which it can
// know only where the two are asked of one manager.
func TestNewIsOneManager(t *testing.T) {
	if New() != New() {
		t.Error("New returned two managers, so a Restart cannot know what the Install before it did")
	}
}
