package ui

import (
	"io"
	"strings"
	"testing"
)

// TestAskReadsLineByLine: a prompt that re-asks after a bad answer gets the next line
// of the same input, not an input its first read buffered away.
func TestAskReadsLineByLine(t *testing.T) {
	in, out := In, Out
	In, Out = strings.NewReader("first\nsecond\n"), io.Discard

	t.Cleanup(func() { In, Out = in, out })

	for _, want := range []string{"first", "second"} {
		got, err := Ask("? ")
		if err != nil || got != want {
			t.Fatalf("Ask() = %q, %v; want %q", got, err, want)
		}
	}

	if _, err := Ask("? "); err != io.EOF {
		t.Errorf("Ask() at the end of input returned %v, want io.EOF", err)
	}
}
