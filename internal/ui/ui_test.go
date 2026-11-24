package ui

import (
	"io"
	"strings"
	"testing"
	"time"
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

// TestConfirmTakesOnlyAnExplicitYes: [y/N] defaults to no. Enter alone, end of input and any
// other word are a no; only y or yes, in any case, is a yes -- the question uninstall asks
// before it deletes the only copy of an identity, and update before it crosses trees.
func TestConfirmTakesOnlyAnExplicitYes(t *testing.T) {
	in, out := In, Out
	t.Cleanup(func() { In, Out = in, out })

	for answer, want := range map[string]bool{
		"y\n": true, "Y\n": true, "yes\n": true, "YES\n": true, " y \n": true,
		"n\n": false, "\n": false, "no\n": false, "maybe\n": false, "": false,
	} {
		In, Out = strings.NewReader(answer), io.Discard

		if got := Confirm("Go on?"); got != want {
			t.Errorf("Confirm answered %q = %v, want %v", answer, got, want)
		}
	}
}

// TestUntil: the last hour of a credential reads in minutes rather than as "0h", which
// said nothing was left while something was.
func TestUntil(t *testing.T) {
	for left, want := range map[time.Duration]string{
		30*24*time.Hour - time.Minute: "29d 23h",
		5*time.Hour + 30*time.Second:  "5h",
		40*time.Minute + time.Second:  "40m",
		-time.Second:                  "expired",
	} {
		if got := Until(time.Now().Add(left)); got != want {
			t.Errorf("Until(now + %v) = %q, want %q", left, got, want)
		}
	}
}
