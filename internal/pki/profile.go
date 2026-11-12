package pki

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
)

// Profile is what a certificate is for: the key usage, extended key usage and basic
// constraints it is issued with.
type Profile string

// The profiles.
const (
	ProfileServer       Profile = "server"
	ProfileClient       Profile = "client"
	ProfileServerClient Profile = "server+client"
	ProfileCA           Profile = "ca"
)

// Profiles is every profile, in the order help lists them.
var Profiles = []Profile{ProfileServer, ProfileClient, ProfileServerClient, ProfileCA}

// ParseProfile reads a profile's name.
func ParseProfile(s string) (Profile, error) {
	for _, p := range Profiles {
		if string(p) == strings.ToLower(s) {
			return p, nil
		}
	}

	return "", fmt.Errorf("%q is not a profile: server, client, server+client or ca", s)
}

// NeedsName reports whether a certificate of the profile is useless without a subject
// alternative name: a TLS client checks a server's against the name it dialled.
func (p Profile) NeedsName() bool { return p == ProfileServer || p == ProfileServerClient }

// apply sets the profile's usages on t, for a certificate of pub. pathLen bounds the CAs a CA
// may have below it; -1 leaves it unbounded.
func (p Profile) apply(t *x509.Certificate, pub crypto.PublicKey, pathLen int) {
	t.BasicConstraintsValid = true

	if p == ProfileCA {
		t.IsCA = true
		t.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		t.MaxPathLen, t.MaxPathLenZero = pathLen, pathLen == 0

		return
	}

	t.KeyUsage = x509.KeyUsageDigitalSignature

	// TLS 1.2's RSA key transport enciphers with the certificate's key. FIPS-mode TLS never
	// does it, and a peer outside it may.
	if _, ok := pub.(*rsa.PublicKey); ok {
		t.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	switch p {
	case ProfileServer:
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case ProfileClient:
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case ProfileServerClient:
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
}
