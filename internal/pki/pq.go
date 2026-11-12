package pki

import (
	"crypto/x509"
	"strings"
)

// The vocabulary for what resists a quantum computer, as anchor's observer names it: pqc
// for a post-quantum algorithm alone, hybrid for one beside a classical one, classical for
// neither.
const (
	ClassPQC       = "pqc"
	ClassHybrid    = "hybrid"
	ClassClassical = "classical"
)

// SignatureClass is the class of a certificate, request or list's signature.
func SignatureClass(a x509.SignatureAlgorithm) string {
	if strings.HasPrefix(a.String(), "ML-DSA") {
		return ClassPQC
	}

	return ClassClassical
}
