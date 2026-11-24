package config

import (
	"errors"
	"io/fs"
	"os"

	"github.com/veil-net/conflux/internal/paths"
)

// Canonical writes conflux.json and state.json in conflux's own form wherever either is not,
// which is what the supervisor does with both as it starts: a hand edit that is valid takes
// effect, and leaves behind no key conflux does not know and no layout of its own. The
// caller holds d's lock, which every writer of either holds.
//
// A file already in conflux's form is not written, so a start rewrites nothing that was not
// edited. A configuration that does not parse, or that this build cannot read, is left
// exactly as it is: the supervisor refuses it for good as it reads it, naming the file, and
// whoever edited it can see what they wrote. None at all is nothing to do. The manifest is never rewritten: it is the identity,
// and nothing here could put back one that was edited.
func Canonical(d paths.Dirs) error {
	c, err := Load(d)

	var read *fs.PathError

	switch {
	case errors.Is(err, fs.ErrNotExist):
	case errors.As(err, &read):
		return err
	case err != nil:
	default:
		b, err := encodeConfig(c)
		if err != nil {
			return err
		}

		if err := rewrite(d.ConfigFile(), b); err != nil {
			return err
		}
	}

	if _, err := os.Stat(d.StateFile()); errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	st, err := LoadState(d)
	if err != nil {
		return err
	}

	b, err := encodeState(st)
	if err != nil {
		return err
	}

	return rewrite(d.StateFile(), b)
}

// rewrite writes b to path, atomically and 0600, unless path holds b already.
func rewrite(path string, b []byte) error {
	_, err := WriteFileIfChanged(path, b, 0o600)

	return err
}
