// Package ui is how conflux talks to a person.
package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// Out and Errw are indirected so tests can capture them.
var (
	Out  io.Writer = os.Stdout
	Errw io.Writer = os.Stderr
)

// in is where answers come from, and inBuf is the one buffered reader over it.
//
// One reader for the life of the process rather than one per question. bufio fills
// with whatever is available and not with the line it was asked for, so a reader
// made per Ask drops everything that arrived behind the answer it returned -- which
// is the correction a prompt loop is waiting for when somebody types it before the
// question comes back around.
var (
	in    io.Reader = os.Stdin
	inBuf           = bufio.NewReader(os.Stdin)
)

// SetIn points the questions at another reader. For tests.
//
// Both move together: a reader that disagreed with the buffer over it would answer
// from the input nobody is typing at.
func SetIn(r io.Reader) { in, inBuf = r, bufio.NewReader(r) }

// Printf writes to stdout.
func Printf(format string, a ...any) { fmt.Fprintf(Out, format, a...) }

// Println writes a line to stdout.
func Println(a ...any) { fmt.Fprintln(Out, a...) }

// Errf writes to stderr, prefixed, which is where every failure goes.
func Errf(format string, a ...any) {
	fmt.Fprintf(Errw, "conflux: "+strings.TrimSuffix(format, "\n")+"\n", a...)
}

// Warnf is for something that is worth saying and is not fatal.
func Warnf(format string, a ...any) {
	fmt.Fprintf(Errw, "conflux: "+strings.TrimSuffix(format, "\n")+"\n", a...)
}

// Field prints one aligned "key  value" row, the shape anchorctl's own status uses.
func Field(key, value string) { fmt.Fprintf(Out, "  %-12s %s\n", key, value) }

// IsTerminal reports whether stdin is something a person is typing at. Used to
// decide between prompting and refusing: a prompt with no terminal to answer it is
// a boot service hung forever.
//
// It asks the terminal driver rather than stat(2), because a character device is
// not a terminal. /dev/null is a character device, NUL is one on Windows, and that
// is the stdin a service, a cron job, a cloud-init run and `ssh host cmd` all get
// by default. Reading those as a person printed the question where nobody could see
// it and took the end-of-file that came straight back for the answer, so a machine
// came up addressless with nobody having been asked.
func IsTerminal() bool {
	f, ok := in.(*os.File)
	if !ok {
		return false
	}

	return isTerminal(f.Fd())
}

// Ask prints a prompt and reads one line. Returns io.EOF when input ends, which is
// what a caller uses to stop re-prompting rather than looping forever.
func Ask(prompt string) (string, error) {
	fmt.Fprint(Out, prompt)

	line, err := inBuf.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}

	return strings.TrimSpace(line), nil
}

// Confirm asks a yes-or-no question that defaults to no.
//
// Defaulting to no, and treating anything that is not an explicit yes as no,
// because the only thing conflux asks this about is destroying an identity that has
// no second copy anywhere.
func Confirm(prompt string) bool {
	answer, err := Ask(prompt + " [y/N] ")
	if err != nil {
		return false
	}

	switch strings.ToLower(answer) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
