package pki

import (
	"crypto/fips140"
	"errors"
)

// ErrNotFIPS is a conflux running outside FIPS 140-3 mode: the OpenBSD build, which carries
// no module, or a build without the Makefile's GOFIPS140.
var ErrNotFIPS = errors.New("this conflux does not run in FIPS 140-3 mode, so it makes and checks no keys, " +
	"certificates or revocation lists: they are artifacts other people rely on, and the claim has to hold " +
	"for every one. Use a build against the Go Cryptographic Module (every platform but OpenBSD)")

// CheckFIPS refuses unless the module is in FIPS 140-3 mode.
func CheckFIPS() error {
	if !fips140.Enabled() {
		return ErrNotFIPS
	}

	return nil
}
