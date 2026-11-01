// Package tlsprobe is conflux cert's TLS client and server: what a server negotiates with a
// FIPS 140-3 mode client, and what clients offer a FIPS 140-3 mode server, each said in the
// observer's words -- pqc, hybrid, classical.
//
// The handshakes are crypto/tls's in FIPS 140-3 mode, which offers and accepts only approved
// parameters: TLS 1.2 and 1.3, AES-GCM (and, in 1.2, AES-CBC with SHA-256), P-256, P-384,
// P-521, the ML-KEM hybrids and ML-KEM-1024, and ML-DSA, ECDSA, RSA and Ed25519 signatures.
package tlsprobe

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/veil-net/conflux/internal/pki"
)

// groups are the key exchange groups FIPS 140-3 mode allows, by the names IANA gives them.
var groups = []struct {
	id    tls.CurveID
	name  string
	class string
}{
	{tls.SecP384r1MLKEM1024, "SecP384r1MLKEM1024", pki.ClassHybrid},
	{tls.SecP256r1MLKEM768, "SecP256r1MLKEM768", pki.ClassHybrid},
	{tls.X25519MLKEM768, "X25519MLKEM768", pki.ClassHybrid},
	{tls.MLKEM1024, "MLKEM1024", pki.ClassPQC},
	{tls.CurveP256, "secp256r1", pki.ClassClassical},
	{tls.CurveP384, "secp384r1", pki.ClassClassical},
	{tls.CurveP521, "secp521r1", pki.ClassClassical},
}

// GroupName is a group by its IANA name; one FIPS 140-3 mode does not allow, by its number.
func GroupName(id tls.CurveID) string {
	for _, g := range groups {
		if g.id == id {
			return g.name
		}
	}

	if id == tls.X25519 {
		return "x25519"
	}

	return fmt.Sprintf("0x%04x", uint16(id))
}

// GroupClass is pqc for ML-KEM alone, hybrid for ML-KEM beside a classical group, and
// classical for the rest.
func GroupClass(id tls.CurveID) string {
	for _, g := range groups {
		if g.id == id {
			return g.class
		}
	}

	return pki.ClassClassical
}

// ParseGroups reads --groups: pq (every group with ML-KEM in it), classical (the three
// curves), or names, comma-separated. Empty is every group FIPS 140-3 mode allows. Which are
// offered first, and which a server picks, crypto/tls decides by its own order, the hybrids
// first, and a client and a server each by theirs: the list says what is allowed.
func ParseGroups(s string) ([]tls.CurveID, error) {
	switch strings.ToLower(s) {
	case "":
		return nil, nil
	case "pq":
		return []tls.CurveID{tls.SecP384r1MLKEM1024, tls.SecP256r1MLKEM768, tls.X25519MLKEM768, tls.MLKEM1024}, nil
	case "classical":
		return []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521}, nil
	}

	var out []tls.CurveID

	for _, n := range strings.Split(s, ",") {
		n = strings.TrimSpace(n)
		found := false

		for _, g := range groups {
			if strings.EqualFold(n, g.name) || strings.EqualFold(n, strings.TrimPrefix(g.id.String(), "Curve")) {
				out, found = append(out, g.id), true
			}
		}

		if !found {
			names := make([]string, len(groups))
			for i, g := range groups {
				names[i] = g.name
			}

			if strings.EqualFold(n, "x25519") {
				return nil, fmt.Errorf("x25519 alone is not a group FIPS 140-3 approves; X25519MLKEM768 carries it beside ML-KEM")
			}

			return nil, fmt.Errorf("%q is not a group: pq, classical, or any of %s", n, strings.Join(names, ", "))
		}
	}

	return out, nil
}

// ParseVersion reads --tls: 1.2 or 1.3.
func ParseVersion(s string) (uint16, error) {
	switch s {
	case "":
		return 0, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}

	return 0, fmt.Errorf("--tls is 1.2 or 1.3, the versions FIPS 140-3 mode speaks, not %q", s)
}

// Signature is the signature scheme a certificate's key authenticates a handshake with, as
// far as it can be known: crypto/tls does not report the scheme, so it is inferred from the
// leaf's key. exact says whether the key leaves only one: ML-DSA and Ed25519 always, ECDSA in
// TLS 1.3, which binds the curve to its hash. RSA's padding and hash, and ECDSA's hash in 1.2,
// are the peers' choice and are not said.
func Signature(version uint16, leaf *x509.Certificate) (name string, exact bool) {
	switch k := leaf.PublicKey.(type) {
	case *mldsa.PublicKey:
		return k.Parameters().String(), true
	case ed25519.PublicKey:
		return "Ed25519", true
	case *ecdsa.PublicKey:
		curve := k.Curve.Params().Name

		if version == tls.VersionTLS13 {
			hash := map[string]string{"P-256": "SHA256", "P-384": "SHA384", "P-521": "SHA512"}[curve]

			return "ECDSA " + curve + " with " + hash, true
		}

		return "ECDSA " + curve, false
	case *rsa.PublicKey:
		if version == tls.VersionTLS13 {
			return fmt.Sprintf("RSA-PSS, %d bits", k.N.BitLen()), false
		}

		return fmt.Sprintf("RSA, %d bits", k.N.BitLen()), false
	}

	return fmt.Sprintf("%T", leaf.PublicKey), false
}

// SignatureSchemeName is a scheme a client offered, by its TLS name.
func SignatureSchemeName(s tls.SignatureScheme) string {
	switch s {
	case tls.MLDSA44:
		return "mldsa44"
	case tls.MLDSA65:
		return "mldsa65"
	case tls.MLDSA87:
		return "mldsa87"
	}

	return s.String()
}
