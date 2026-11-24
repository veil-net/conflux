package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/veil-net/conflux/internal/paths"
)

// Envelope is the base64 anchor manifest exactly as the enrolment API hands it
// over: the identity seed, the realm root, the credential chain, the bootstrap
// list and the renewal endpoint, in one line.
//
// It is a named type rather than a []byte so that the String method below is
// unavoidable. The seed inside regenerates both halves of the anchor's key, and a
// single %v in a log line would put it somewhere it can never be taken back from.
type Envelope []byte

// String is what fmt prints, and it is deliberately useless.
func (Envelope) String() string { return "<anchor manifest, redacted>" }

// GoString covers %#v as well, which String does not.
func (Envelope) GoString() string { return "<anchor manifest, redacted>" }

// ErrEmptyManifest is LoadManifest's refusal of a manifest.b64 holding nothing, or nothing
// but white space.
var ErrEmptyManifest = errors.New("empty, holding no identity")

// LoadManifest reads the identity. A missing file means "never enrolled", which is
// the one condition under which conflux is allowed to enrol. One empty or of nothing but
// white space holds no identity, and is ErrEmptyManifest, naming it: no retry fills it, and
// what it held is a person's to find out.
func LoadManifest(d paths.Dirs) (Envelope, error) {
	b, err := os.ReadFile(d.ManifestFile())
	if err != nil {
		return nil, err
	}

	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("%s: %w", d.ManifestFile(), ErrEmptyManifest)
	}

	return Envelope(b), nil
}

// SaveManifest writes the identity, atomically, 0600, and DACL-restricted on
// Windows.
//
// Called in exactly three places: immediately after enrolment, before anything else
// touches the response; after a renewal splices a fresh chain into it; and by `conflux
// enrol`, installing one a machine was given.
// Enrolment stores nothing on the server -- the response is the only copy -- so an
// enrolment that succeeds and then loses the bytes to a crash costs the machine its
// identity permanently. That is why it is written first and everything else second.
func SaveManifest(d paths.Dirs, env Envelope) error {
	b := bytes.TrimSpace(env)
	if len(b) == 0 {
		return fmt.Errorf("refusing to write an empty manifest")
	}

	// The newline is written after it rather than appended to it: an append to the
	// caller's slice can write into the envelope the caller still holds, and a copy to
	// avoid that is the whole manifest again.
	return writeAtomic(d.ManifestFile(), 0o600, b, []byte{'\n'})
}

// HasManifest reports whether this machine has an identity already, by LoadManifest's rule:
// none only where there is no manifest.b64, or one LoadManifest refuses as empty. One there
// that cannot be read is an identity, which may be the one the machine runs. The answer
// gates enrolment, and getting it wrong in the false direction draws a new identity and
// silently changes the machine's overlay address.
func HasManifest(d paths.Dirs) bool {
	_, err := LoadManifest(d)

	return !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, ErrEmptyManifest)
}
