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
	In   io.Reader = os.Stdin
)

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
func IsTerminal() bool {
	f, ok := In.(*os.File)
	if !ok {
		return false
	}

	fi, err := f.Stat()
	if err != nil {
		return false
	}

	return fi.Mode()&os.ModeCharDevice != 0
}

// Ask prints a prompt and reads one line. Returns io.EOF when input ends, which is
// what a caller uses to stop re-prompting rather than looping forever.
func Ask(prompt string) (string, error) {
	fmt.Fprint(Out, prompt)

	r := bufio.NewReader(In)

	line, err := r.ReadString('\n')
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
