package config

import (
	"bytes"
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
// c is the configuration the caller read and took, and raw the bytes it read it from, so the
// file is neither read again nor judged here: one the caller refuses -- that does not parse,
// that this build cannot read, that Validate refuses -- never reaches Canonical, and is left
// exactly as it is, for whoever edited it to see what they wrote. A file already in
// conflux's form is not written, so a start rewrites nothing that was not edited. The
// manifest is never rewritten: it is the identity, and nothing here could put back one that
// was edited.
func Canonical(d paths.Dirs, c *Config, raw []byte) error {
	b, err := encodeConfig(c)
	if err != nil {
		return err
	}

	if !bytes.Equal(b, raw) {
		if err := WriteFileAtomic(d.ConfigFile(), b, 0o600); err != nil {
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

	b, err = encodeState(st)
	if err != nil {
		return err
	}

	_, err = WriteFileIfChanged(d.StateFile(), b, 0o600)

	return err
}
