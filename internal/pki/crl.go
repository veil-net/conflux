package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// Revocation reasons (RFC 5280, 5.3.1), by the names OpenSSL uses. certificateHold is not
// one of them: a revocation here is final, and a hold is the one reason that is not.
var reasons = []struct {
	name string
	code int
}{
	{"unspecified", 0},
	{"keyCompromise", 1},
	{"cACompromise", 2},
	{"affiliationChanged", 3},
	{"superseded", 4},
	{"cessationOfOperation", 5},
	{"privilegeWithdrawn", 9},
	{"aACompromise", 10},
}

// ParseReason reads a reason by name, in any case.
func ParseReason(s string) (int, error) {
	for _, r := range reasons {
		if strings.EqualFold(r.name, s) {
			return r.code, nil
		}
	}

	if strings.EqualFold(s, "certificateHold") || strings.EqualFold(s, "removeFromCRL") {
		return 0, fmt.Errorf("%s is not a reason here: a revocation is final", s)
	}

	names := make([]string, len(reasons))
	for i, r := range reasons {
		names[i] = r.name
	}

	return 0, fmt.Errorf("%q is not a revocation reason: %s", s, strings.Join(names, ", "))
}

// ReasonName is a reason code's name.
func ReasonName(code int) string {
	for _, r := range reasons {
		if r.code == code {
			return r.name
		}
	}

	if code == 6 {
		return "certificateHold"
	}

	return strconv.Itoa(code)
}

// ParseSerial reads a serial number in hex, with or without colons or 0x, as show prints it.
func ParseSerial(s string) (*big.Int, error) {
	h := strings.TrimPrefix(strings.TrimPrefix(strings.ReplaceAll(s, ":", ""), "0x"), "0X")

	n, ok := new(big.Int).SetString(h, 16)
	if !ok || n.Sign() <= 0 {
		return nil, fmt.Errorf("%q is not a serial number in hex", s)
	}

	return n, nil
}

// FormatSerial is a serial number as show prints it: hex in colon-separated bytes.
func FormatSerial(n *big.Int) string { return colonHex(n.Bytes()) }

// Revoked is one entry of a revocation list.
type Revoked struct {
	Serial *big.Int
	Reason int
	At     time.Time
}

// CRL makes a revocation list numbered number, signed by issuer's key, valid from now for
// days.
func CRL(issuer *x509.Certificate, key crypto.Signer, revoked []Revoked, number *big.Int, now time.Time, days int, pss bool) ([]byte, error) {
	switch {
	case days < 1:
		return nil, errors.New("a revocation list is valid for a day or more")
	case !SamePublicKey(issuer.PublicKey, key.Public()):
		return nil, fmt.Errorf("the key given is not the one %q certifies", issuer.Subject)
	case issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCRLSign == 0:
		return nil, fmt.Errorf("%q's key usage does not include signing revocation lists", issuer.Subject)
	case number == nil || number.Sign() < 0:
		return nil, errors.New("a revocation list's number is zero or more")
	}

	alg, err := SignatureAlgorithm(key.Public(), pss)
	if err != nil {
		return nil, err
	}

	entries := make([]x509.RevocationListEntry, len(revoked))
	for i, r := range revoked {
		entries[i] = x509.RevocationListEntry{SerialNumber: r.Serial, RevocationTime: r.At.UTC(), ReasonCode: r.Reason}
	}

	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm:        alg,
		RevokedCertificateEntries: entries,
		Number:                    number,
		ThisUpdate:                now.UTC().Truncate(time.Second),
		NextUpdate:                now.Add(time.Duration(days) * 24 * time.Hour).UTC().Truncate(time.Second),
	}, issuer, key)
}
