package privcheck

import (
	"runtime"
	"testing"
)

// TestCommandQuotesWhatAShellWouldRead: a word of the characters every shell reads
// literally is left alone, and any other is quoted for the shell the message is pasted
// into, an empty one and a shell's operators included.
func TestCommandQuotesWhatAShellWouldRead(t *testing.T) {
	got := Command("conflux", "up", "--taint", "my net", "--ipv4", "10.128.0.7/24", "", "a;b", "a|b", "a&b", "$HOME", "*", "it's")

	want := `conflux up --taint 'my net' --ipv4 10.128.0.7/24 '' 'a;b' 'a|b' 'a&b' '$HOME' '*' 'it'\''s'`
	if runtime.GOOS == "windows" {
		want = `conflux up --taint 'my net' --ipv4 10.128.0.7/24 '' 'a;b' 'a|b' 'a&b' '$HOME' '*' 'it''s'`
	}

	if got != want {
		t.Errorf("Command = %s\nwant      %s", got, want)
	}
}
