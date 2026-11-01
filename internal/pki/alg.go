package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"slices"
	"strings"
)

// Alg is a key algorithm the toolkit makes keys for.
type Alg string

// The algorithms, ML-DSA first: it is the default, and the reason the toolkit exists.
const (
	MLDSA44   Alg = "ml-dsa-44"
	MLDSA65   Alg = "ml-dsa-65"
	MLDSA87   Alg = "ml-dsa-87"
	ECDSAP256 Alg = "ecdsa-p256"
	ECDSAP384 Alg = "ecdsa-p384"
	ECDSAP521 Alg = "ecdsa-p521"
	RSA2048   Alg = "rsa-2048"
	RSA3072   Alg = "rsa-3072"
	RSA4096   Alg = "rsa-4096"
	Ed25519   Alg = "ed25519"
)

// DefaultAlg is ML-DSA-87: anchor signs with it, and CNSA 2.0 asks for it.
const DefaultAlg = MLDSA87

// Algs is every algorithm, in the order help lists them.
var Algs = []Alg{MLDSA44, MLDSA65, MLDSA87, ECDSAP256, ECDSAP384, ECDSAP521, RSA2048, RSA3072, RSA4096, Ed25519}

// ParseAlg reads an algorithm's name, in any case, with or without its dashes.
func ParseAlg(s string) (Alg, error) {
	norm := strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(s))

	for _, a := range Algs {
		if strings.ReplaceAll(string(a), "-", "") == norm {
			return a, nil
		}
	}

	names := make([]string, len(Algs))
	for i, a := range Algs {
		names[i] = string(a)
	}

	return "", fmt.Errorf("%q is not a key algorithm this makes: %s", s, strings.Join(names, ", "))
}

// Generate makes a key, from the module's DRBG.
func (a Alg) Generate() (crypto.Signer, error) {
	switch a {
	case MLDSA44:
		return mldsa.GenerateKey(mldsa.MLDSA44())
	case MLDSA65:
		return mldsa.GenerateKey(mldsa.MLDSA65())
	case MLDSA87:
		return mldsa.GenerateKey(mldsa.MLDSA87())
	case ECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case ECDSAP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case RSA2048, RSA3072, RSA4096:
		bits := map[Alg]int{RSA2048: 2048, RSA3072: 3072, RSA4096: 4096}[a]

		return rsa.GenerateKey(rand.Reader, bits)
	case Ed25519:
		_, k, err := ed25519.GenerateKey(rand.Reader)

		return k, err
	}

	return nil, fmt.Errorf("no key algorithm %q", a)
}

// KeyInfo describes a public key: its algorithm as a person reads it, and whether it
// resists a quantum computer.
type KeyInfo struct {
	Name  string `json:"algorithm"`
	Class string `json:"class"` // "pqc" or "classical"
}

// Describe is a public key's KeyInfo.
func Describe(pub crypto.PublicKey) KeyInfo {
	switch k := pub.(type) {
	case *mldsa.PublicKey:
		return KeyInfo{k.Parameters().String(), ClassPQC}
	case *ecdsa.PublicKey:
		return KeyInfo{"ECDSA " + k.Curve.Params().Name, ClassClassical}
	case *rsa.PublicKey:
		return KeyInfo{fmt.Sprintf("RSA %d", k.N.BitLen()), ClassClassical}
	case ed25519.PublicKey:
		return KeyInfo{"Ed25519", ClassClassical}
	}

	return KeyInfo{fmt.Sprintf("%T", pub), ClassClassical}
}

// supported reports whether pub is a key the toolkit signs and checks with: one of Algs.
func supported(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *mldsa.PublicKey, ed25519.PublicKey:
		return nil
	case *ecdsa.PublicKey:
		if slices.Contains([]string{"P-256", "P-384", "P-521"}, k.Curve.Params().Name) {
			return nil
		}
	case *rsa.PublicKey:
		if b := k.N.BitLen(); b >= 2048 && b%2 == 0 {
			return nil
		}
	}

	return fmt.Errorf("a %s key is not one this signs with: %s", Describe(pub).Name, "ML-DSA, ECDSA P-256/384/521, RSA of 2048 bits or more, Ed25519")
}
