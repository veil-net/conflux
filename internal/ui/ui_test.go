package ui

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// hush points the package at buffers and restores what was there, so a test that
// prompts does not write the question to the test log.
func hush(t *testing.T) *bytes.Buffer {
	t.Helper()

	var out bytes.Buffer

	oldOut, oldErr := Out, Errw
	Out, Errw = &out, &out

	t.Cleanup(func() {
		Out, Errw = oldOut, oldErr
		SetIn(os.Stdin)
	})

	return &out
}

// TestIsTerminalRefusesWhatCannotAnswer is the regression test for a machine that
// was never asked.
//
// stdin is /dev/null for a service, a cron job, a cloud-init run and every `ssh
// host cmd` without a tty. /dev/null is a character device, which is the only thing
// the old check looked at, so conflux printed its question there, read the
// end-of-file that came back, and brought the machine up with no address.
func TestIsTerminalRefusesWhatCannotAnswer(t *testing.T) {
	hush(t)

	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}

	t.Cleanup(func() { null.Close() })

	file, err := os.CreateTemp(t.TempDir(), "answers")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}

	t.Cleanup(func() { file.Close() })

	pipe, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	t.Cleanup(func() { pipe.Close(); w.Close() })

	for name, r := range map[string]io.Reader{
		os.DevNull:         null,
		"a regular file":   file,
		"a pipe":           pipe,
		"a strings.Reader": strings.NewReader("10.128.0.7/24\n"),
	} {
		SetIn(r)

		if IsTerminal() {
			t.Errorf("IsTerminal() with %s for stdin = true, want false", name)
		}
	}
}

// TestAskKeepsWhatItReadAhead: two answers written at once are two answers read.
//
// A reader made per question drops whatever the last one buffered behind the line
// it returned, which is every line but the first -- so a prompt that re-asks after
// a malformed answer read end-of-file instead of the correction already typed.
func TestAskKeepsWhatItReadAhead(t *testing.T) {
	hush(t)
	SetIn(strings.NewReader("10.128.0.7\n10.128.0.7/24\n"))

	first, err := Ask("first: ")
	if err != nil || first != "10.128.0.7" {
		t.Fatalf("Ask() = %q, %v; want %q, nil", first, err, "10.128.0.7")
	}

	second, err := Ask("second: ")
	if err != nil || second != "10.128.0.7/24" {
		t.Fatalf("second Ask() = %q, %v; want %q, nil", second, err, "10.128.0.7/24")
	}
}

// TestAskReportsEndOfInput: the caller has to be able to tell "nothing more is
// coming" from "a blank line", because they mean opposite things at a prompt.
func TestAskReportsEndOfInput(t *testing.T) {
	hush(t)
	SetIn(strings.NewReader(""))

	if answer, err := Ask("q: "); err == nil {
		t.Fatalf("Ask() on exhausted input = %q, nil; want an error", answer)
	}

	SetIn(strings.NewReader("\n"))

	if answer, err := Ask("q: "); err != nil || answer != "" {
		t.Fatalf("Ask() on a blank line = %q, %v; want %q, nil", answer, err, "")
	}
}
