package pki

import (
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Digest is a hash a fingerprint is taken with: SHA-2 or SHA-3, never SHA-1 or MD5.
type Digest string

// The digests.
const (
	SHA256   Digest = "sha256"
	SHA384   Digest = "sha384"
	SHA512   Digest = "sha512"
	SHA3_256 Digest = "sha3-256"
	SHA3_384 Digest = "sha3-384"
	SHA3_512 Digest = "sha3-512"
)

// Digests is every digest, in the order help lists them.
var Digests = []Digest{SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512}

// ParseDigest reads a digest's name, with or without its dash.
func ParseDigest(s string) (Digest, error) {
	norm := strings.ReplaceAll(strings.ToLower(s), "-", "")

	for _, d := range Digests {
		if strings.ReplaceAll(string(d), "-", "") == norm {
			return d, nil
		}
	}

	if norm == "sha1" || norm == "md5" {
		return "", fmt.Errorf("%s is not a fingerprint this takes: it is not a hash FIPS 140-3 approves", s)
	}

	return "", fmt.Errorf("%q is not a digest: sha256, sha384, sha512, sha3-256, sha3-384 or sha3-512", s)
}

// Sum is b's digest.
func (d Digest) Sum(b []byte) []byte {
	switch d {
	case SHA384:
		s := sha512.Sum384(b)

		return s[:]
	case SHA512:
		s := sha512.Sum512(b)

		return s[:]
	case SHA3_256:
		s := sha3.Sum256(b)

		return s[:]
	case SHA3_384:
		s := sha3.Sum384(b)

		return s[:]
	case SHA3_512:
		s := sha3.Sum512(b)

		return s[:]
	default:
		s := sha256.Sum256(b)

		return s[:]
	}
}

// Fingerprint is one object's digest.
type Fingerprint struct {
	Of     string `json:"of"` // what was hashed
	Digest Digest `json:"digest"`
	Hex    string `json:"hex"`
	Base64 string `json:"base64"`
}

// FingerprintOf takes o's fingerprint: of its whole encoding, or with spki of its public key's
// SubjectPublicKeyInfo -- the form a pin takes. A private key's is always its public key's.
func FingerprintOf(o Object, d Digest, spki bool) (Fingerprint, error) {
	var (
		b  []byte
		of string
	)

	switch o.Kind {
	case KindCertificate, KindRequest, KindPublicKey, KindPrivateKey:
		pub, err := PublicKeyOf(o)
		if err != nil {
			return Fingerprint{}, err
		}

		if spki || o.Kind == KindPublicKey || o.Kind == KindPrivateKey {
			if b, err = x509.MarshalPKIXPublicKey(pub); err != nil {
				return Fingerprint{}, err
			}

			of = "public key"
		} else {
			b, of = o.DER, o.Kind.Name()
		}
	case KindCRL:
		if spki {
			return Fingerprint{}, errors.New("a revocation list has no public key to take the fingerprint of")
		}

		b, of = o.DER, "revocation list"
	case KindEncryptedKey:
		return Fingerprint{}, errors.New("this key is encrypted: take the fingerprint of its certificate, or decrypt it first")
	}

	sum := d.Sum(b)

	return Fingerprint{Of: of, Digest: d, Hex: colonHex(sum), Base64: base64.StdEncoding.EncodeToString(sum)}, nil
}

// PublicKeyOf is the public key a certificate, request, public key or private key in the
// clear holds.
func PublicKeyOf(o Object) (any, error) {
	switch o.Kind {
	case KindCertificate:
		c, err := x509.ParseCertificate(o.DER)
		if err != nil {
			return nil, err
		}

		return c.PublicKey, nil
	case KindRequest:
		r, err := x509.ParseCertificateRequest(o.DER)
		if err != nil {
			return nil, err
		}

		return r.PublicKey, nil
	case KindPublicKey:
		return ParsePublicKey(o.DER)
	case KindPrivateKey:
		k, err := ParsePrivateKey(o.DER)
		if err != nil {
			return nil, err
		}

		return k.Public(), nil
	}

	return nil, fmt.Errorf("a %s holds no public key", o.Kind.Name())
}

// colonHex is bytes as OpenSSL prints a fingerprint: upper-case hex pairs between colons.
func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))

	var sb strings.Builder

	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}

		sb.WriteString(h[i : i+2])
	}

	return sb.String()
}
