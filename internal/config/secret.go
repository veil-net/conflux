package config

import (
	"bytes"
	"fmt"
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

// LoadManifest reads the identity. A missing file means "never enrolled", which is
// the one condition under which conflux is allowed to enrol.
func LoadManifest(d paths.Dirs) (Envelope, error) {
	b, err := os.ReadFile(d.ManifestFile())
	if err != nil {
		return nil, err
	}

	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("%s is empty", d.ManifestFile())
	}

	return Envelope(b), nil
}

// SaveManifest writes the identity, atomically, 0600, and DACL-restricted on
// Windows.
//
// Called in exactly two places: immediately after enrolment, before anything else
// touches the response, and after a renewal splices a fresh chain into it.
// Enrolment stores nothing on the server -- the response is the only copy -- so an
// enrolment that succeeds and then loses the bytes to a crash costs the machine its
// identity permanently. That is why it is written first and everything else second.
func SaveManifest(d paths.Dirs, env Envelope) error {
	if len(bytes.TrimSpace(env)) == 0 {
		return fmt.Errorf("refusing to write an empty manifest")
	}

	return WriteFileAtomic(d.ManifestFile(), append(bytes.TrimSpace(env), '\n'), 0o600)
}

// HasManifest reports whether this machine has an identity already. The answer
// gates enrolment, and getting it wrong in the false direction draws a new identity
// and silently changes the machine's overlay address.
func HasManifest(d paths.Dirs) bool {
	fi, err := os.Stat(d.ManifestFile())

	return err == nil && fi.Size() > 0
}

// DeleteManifest destroys the identity. There is no other copy anywhere, so every
// caller of this must have asked the operator first.
func DeleteManifest(d paths.Dirs) error {
	if err := os.Remove(d.ManifestFile()); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
