package pki

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/sha3"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Private keys are PKCS#8 (RFC 5958), and an ML-DSA key in it is its 32-byte seed alone
// (RFC 9881's seed form): FIPS 204 rebuilds the whole key from the seed, so nothing else
// is worth keeping, and the seed is the smallest thing there is to protect.

// MarshalPrivateKey is a key's PKCS#8 encoding.
func MarshalPrivateKey(k crypto.Signer) ([]byte, error) {
	if err := supported(k.Public()); err != nil {
		return nil, err
	}

	return x509.MarshalPKCS8PrivateKey(k)
}

// ParsePrivateKey reads a PKCS#8 private key, an ML-DSA one in any of RFC 9881's three
// forms but the one without its seed.
//
// x509 reads the seed form, and refuses the form OpenSSL writes by default, the seed beside
// the expanded key: that one is read here, from its seed, and the expanded half checked
// against what the seed derives, so a file whose two halves are two different keys is
// refused rather than read as whichever half was looked at.
func ParsePrivateKey(der []byte) (crypto.Signer, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("a %T is not a key that signs", k)
		}

		if err := supported(s.Public()); err != nil {
			return nil, err
		}

		return s, nil
	}

	var p8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}

	if rest, aerr := asn1.Unmarshal(der, &p8); aerr != nil || len(rest) != 0 {
		return nil, err
	}

	params, ok := mldsaParams(p8.Algo.Algorithm)
	if !ok || len(p8.PrivateKey) == 0 {
		return nil, err
	}

	switch p8.PrivateKey[0] {
	case 0x30: // both
		return parseMLDSABoth(params, p8.PrivateKey)
	case 0x04: // expandedKey alone
		return nil, errors.New("this ML-DSA key is its expanded form alone, without the seed it came from, " +
			"and conflux reads ML-DSA keys from their seed (FIPS 204 rebuilds the whole key from it). " +
			"A key with no seed cannot be given one: make a new key")
	}

	return nil, err
}

// The ML-DSA OIDs, id-ml-dsa-44, -65 and -87 (NIST's sigAlgs arc).
var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

func mldsaParams(oid asn1.ObjectIdentifier) (mldsa.Parameters, bool) {
	switch {
	case oid.Equal(oidMLDSA44):
		return mldsa.MLDSA44(), true
	case oid.Equal(oidMLDSA65):
		return mldsa.MLDSA65(), true
	case oid.Equal(oidMLDSA87):
		return mldsa.MLDSA87(), true
	}

	return mldsa.Parameters{}, false
}

// mldsaShape is a parameter set's k and l, and its expanded private key's length (FIPS 204,
// table 2).
func mldsaShape(p mldsa.Parameters) (k, l byte, expanded int) {
	switch p {
	case mldsa.MLDSA44():
		return 4, 4, 2560
	case mldsa.MLDSA65():
		return 6, 5, 4032
	default:
		return 8, 7, 4896
	}
}

// parseMLDSABoth reads RFC 9881's both form, SEQUENCE { seed OCTET STRING (32), expandedKey
// OCTET STRING }, as the key its seed makes, once the expanded key is found to be that key's.
//
// The expanded key begins ρ ‖ K ‖ tr (FIPS 204, skEncode). ρ and K are the first and last 32
// bytes of H(ξ ‖ k ‖ l, 128), H being SHAKE256 and ξ the seed (ML-DSA.KeyGen_internal), and
// tr is H(pk, 64): an expanded key made from another seed differs from this one's in all
// three. What follows, the secret vectors s1, s2 and t0, only the module's own key
// generation recomputes, and it does not return them: the check stops at what it can make
// with SHAKE256 alone.
func parseMLDSABoth(p mldsa.Parameters, b []byte) (crypto.Signer, error) {
	var both struct {
		Seed     []byte
		Expanded []byte
	}

	if rest, err := asn1.Unmarshal(b, &both); err != nil || len(rest) != 0 {
		return nil, errors.New("this ML-DSA key's seed and expanded key are not encoded as RFC 9881 says")
	}

	k, l, size := mldsaShape(p)
	if len(both.Seed) != mldsa.PrivateKeySize || len(both.Expanded) != size {
		return nil, fmt.Errorf("this %s key's seed is %d bytes and its expanded key %d, not %d and %d",
			p, len(both.Seed), len(both.Expanded), mldsa.PrivateKeySize, size)
	}

	sk, err := mldsa.NewPrivateKey(p, both.Seed)
	if err != nil {
		return nil, err
	}

	h := sha3.SumSHAKE256(append(bytes.Clone(both.Seed), k, l), 128)
	rho, key := h[:32], h[96:128]
	tr := sha3.SumSHAKE256(sk.PublicKey().Bytes(), 64)

	if !bytes.Equal(both.Expanded[:32], rho) || !bytes.Equal(both.Expanded[32:64], key) ||
		!bytes.Equal(both.Expanded[64:128], tr) {
		return nil, fmt.Errorf("this %s key's expanded key is not the one its seed makes: "+
			"the file holds two different keys, and is refused rather than read as either", p)
	}

	return sk, nil
}

// MarshalPublicKey is a public key's SubjectPublicKeyInfo.
func MarshalPublicKey(pub crypto.PublicKey) ([]byte, error) { return x509.MarshalPKIXPublicKey(pub) }

// ParsePublicKey reads a SubjectPublicKeyInfo.
func ParsePublicKey(der []byte) (crypto.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	return pub, supported(pub)
}

// SamePublicKey reports whether two public keys are the same key.
func SamePublicKey(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })

	return ok && eq.Equal(b)
}
