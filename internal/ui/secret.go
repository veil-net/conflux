package ui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
)

// ErrNoTerminal is a secret asked for where nobody can type it.
var ErrNoTerminal = errors.New("there is no terminal to type a passphrase at")

// OpenTerminal opens the terminal a secret is read from; a test replaces it.
var OpenTerminal = openTerminal

// AskSecret prints a prompt to stderr and reads one line from the controlling terminal
// without echoing it.
//
// The terminal itself, not stdin: stdin may be what is being read (a key piped in to be
// encrypted), and a secret is never taken from whatever happens to be there. The prompt goes
// to stderr, so stdout holds nothing but what is written. The line's ending is dropped and
// nothing else of it is: spaces in a passphrase are the passphrase's.
//
// Echo comes back however the read ends, a cancelled ctx included -- a terminal left silent
// after a Ctrl-C is the shell's to recover, and nobody knows to.
func AskSecret(ctx context.Context, prompt string) ([]byte, error) {
	tty, err := OpenTerminal()
	if err != nil {
		return nil, ErrNoTerminal
	}

	defer tty.Close()

	restore, err := noEcho(tty.Fd())
	if err != nil {
		return nil, fmt.Errorf("turning the terminal's echo off: %w", err)
	}

	defer restore()

	fmt.Fprint(Errw, prompt)

	type answer struct {
		line []byte
		err  error
	}

	got := make(chan answer, 1)

	go func() {
		line, err := bufio.NewReader(tty).ReadSlice('\n')
		got <- answer{trimEnding(append([]byte{}, line...)), err}

		clear(line)
	}()

	select {
	case a := <-got:
		// The newline typed is not echoed where the terminal has no ECHONL: say it.
		if !echoesNewline {
			fmt.Fprintln(Errw)
		}

		if a.err != nil && len(a.line) == 0 {
			return nil, a.err
		}

		return a.line, nil
	case <-ctx.Done():
		fmt.Fprintln(Errw)

		return nil, ctx.Err()
	}
}

func trimEnding(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}

	return b
}
