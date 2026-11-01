package pki

import (
	"crypto"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)

func mustName(t *testing.T, s string) Template {
	t.Helper()

	n, err := ParseName(s)
	if err != nil {
		t.Fatal(err)
	}

	return Template{Subject: n, Days: 365, PathLen: -1}
}

func mustKey(t *testing.T, a Alg) crypto.Signer {
	t.Helper()

	k, err := a.Generate()
	if err != nil {
		t.Fatal(err)
	}

	return k
}

func mustParse(t *testing.T, der []byte, err error) *x509.Certificate {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}

	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return c
}

// ca is a self-signed CA of alg.
func ca(t *testing.T, alg Alg, name string, days int) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	k := mustKey(t, alg)
	tm := mustName(t, name)
	tm.Profile, tm.Days = ProfileCA, days

	der, err := Issue(tm, k.Public(), nil, k, now)

	return mustParse(t, der, err), k
}

func leaf(t *testing.T, alg Alg, p Profile, issuer *x509.Certificate, key crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	k := mustKey(t, alg)
	tm := mustName(t, "CN=host.example")
	tm.Profile, tm.Days = p, 30

	if err := tm.SANs.AddSAN("host.example"); err != nil {
		t.Fatal(err)
	}

	der, err := Issue(tm, k.Public(), issuer, key, now)

	return mustParse(t, der, err), k
}

// TestEveryAlgorithmIssuesAndVerifies: a CA of each algorithm issues a server certificate of
// each, which verifies for its name and purpose, signed with the algorithm the issuer's key
// pairs with, and is classed pqc exactly when the leaf key and its signature are ML-DSA.
func TestEveryAlgorithmIssuesAndVerifies(t *testing.T) {
	for _, ia := range Algs {
		root, rk := ca(t, ia, "CN=Root "+string(ia), 3650)

		for _, la := range []Alg{MLDSA65, ECDSAP256, RSA2048, Ed25519} {
			c, _ := leaf(t, la, ProfileServer, root, rk)

			r := Verify(c, VerifyOptions{Roots: []*x509.Certificate{root}, Purpose: PurposeServer, Name: "host.example", At: now})
			if !r.Valid {
				t.Errorf("%s under %s: %s", la, ia, r.Problem)

				continue
			}

			want := ClassClassical
			if strings.HasPrefix(string(ia), "ml-dsa") && strings.HasPrefix(string(la), "ml-dsa") {
				want = ClassPQC
			}

			if r.Authentication != want {
				t.Errorf("%s under %s: authentication %s, want %s", la, ia, r.Authentication, want)
			}

			wantSig, _ := SignatureAlgorithm(rk.Public(), false)
			if c.SignatureAlgorithm != wantSig {
				t.Errorf("%s under %s: signed %s, want %s", la, ia, c.SignatureAlgorithm, wantSig)
			}
		}
	}
}

// TestProfiles: each profile's usages are its own, and the leaf's validity starts five
// minutes back and its SKI is RFC 7093's.
func TestProfiles(t *testing.T) {
	root, rk := ca(t, MLDSA87, "CN=Root", 3650)

	if !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 || root.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Errorf("the ca profile gave IsCA %v, key usage %v", root.IsCA, root.KeyUsage)
	}

	for p, want := range map[Profile][]x509.ExtKeyUsage{
		ProfileServer:       {x509.ExtKeyUsageServerAuth},
		ProfileClient:       {x509.ExtKeyUsageClientAuth},
		ProfileServerClient: {x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	} {
		c, k := leaf(t, MLDSA65, p, root, rk)

		if c.IsCA || len(c.ExtKeyUsage) != len(want) || c.ExtKeyUsage[0] != want[0] {
			t.Errorf("%s: IsCA %v, ext key usage %v, want %v", p, c.IsCA, c.ExtKeyUsage, want)
		}

		if c.KeyUsage != x509.KeyUsageDigitalSignature {
			t.Errorf("%s: key usage %v", p, c.KeyUsage)
		}

		if !c.NotBefore.Equal(now.Add(-Backdate)) {
			t.Errorf("%s: not before %s, want %s", p, c.NotBefore, now.Add(-Backdate))
		}

		if ski, _ := SubjectKeyID(k.Public()); string(c.SubjectKeyId) != string(ski) || len(ski) != 20 {
			t.Errorf("%s: SKI %x, want %x", p, c.SubjectKeyId, ski)
		}

		if string(c.AuthorityKeyId) != string(root.SubjectKeyId) {
			t.Errorf("%s: AKI %x is not the root's SKI %x", p, c.AuthorityKeyId, root.SubjectKeyId)
		}
	}

	rsaLeaf, _ := leaf(t, RSA2048, ProfileServer, root, rk)
	if rsaLeaf.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
		t.Errorf("an RSA server's key usage is %v", rsaLeaf.KeyUsage)
	}

	r := Verify(rsaLeaf, VerifyOptions{Roots: []*x509.Certificate{root}, Purpose: PurposeClient, At: now})
	if r.Valid {
		t.Error("a server certificate verified for client authentication")
	}
}

// TestIssuingRefuses: what would make a certificate nothing trusts is refused before it is
// signed.
func TestIssuingRefuses(t *testing.T) {
	root, rk := ca(t, ECDSAP256, "CN=Root", 100)
	server, sk := leaf(t, ECDSAP256, ProfileServer, root, rk)
	other := mustKey(t, ECDSAP256)

	tm := mustName(t, "CN=x")
	tm.Profile = ProfileClient

	for _, c := range []struct {
		name   string
		tm     Template
		issuer *x509.Certificate
		key    crypto.Signer
		says   string
	}{
		{"an issuer that is no CA", tm, server, sk, "not a CA"},
		{"a key that is not the issuer's", tm, root, other, "not the one"},
		{"outliving the issuer", func() Template { t := tm; t.Days = 1000; return t }(), root, rk, "outlive"},
		{"a server with no name", func() Template { t := tm; t.Profile = ProfileServer; return t }(), root, rk, "--san"},
		{"no days", func() Template { t := tm; t.Days = 0; return t }(), root, rk, "a day"},
	} {
		if _, err := Issue(c.tm, mustKey(t, MLDSA44).Public(), c.issuer, c.key, now); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v, want a refusal saying %q", c.name, err, c.says)
		}
	}

	if _, err := Issue(tm, other.Public(), nil, rk, now); err == nil {
		t.Error("a self-signed certificate of another key than the signer's was made")
	}
}

// TestRevocation: a revoked leaf fails verification, naming its reason; a list out of date
// fails it too; a list from no issuer in the chain is noted and not used; an intermediate's
// list is checked against the intermediate it names.
func TestRevocation(t *testing.T) {
	root, rk := ca(t, MLDSA87, "CN=Root", 3650)

	ik := mustKey(t, MLDSA65)
	itm := mustName(t, "CN=Intermediate")
	itm.Profile, itm.Days, itm.PathLen = ProfileCA, 1000, 0
	ider, err := Issue(itm, ik.Public(), root, rk, now)
	inter := mustParse(t, ider, err)

	c, _ := leaf(t, MLDSA65, ProfileServer, inter, ik)

	crl := func(issuer *x509.Certificate, key crypto.Signer, at time.Time, revoked ...Revoked) *x509.RevocationList {
		der, err := CRL(issuer, key, revoked, big.NewInt(1), at, 7, false)
		if err != nil {
			t.Fatal(err)
		}

		l, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatal(err)
		}

		return l
	}

	opts := func(crls ...*x509.RevocationList) VerifyOptions {
		return VerifyOptions{Roots: []*x509.Certificate{root}, Intermediates: []*x509.Certificate{inter}, CRLs: crls, At: now.Add(time.Hour)}
	}

	if r := Verify(c, opts(crl(inter, ik, now), crl(root, rk, now))); !r.Valid || len(r.Revocation) != 2 ||
		r.Revocation[0].Status != "good" || r.Revocation[1].Status != "good" || r.Authentication != ClassPQC {
		t.Errorf("an unrevoked chain: %+v", r)
	}

	r := Verify(c, opts(crl(inter, ik, now, Revoked{c.SerialNumber, 1, now})))
	if r.Valid || !strings.Contains(r.Problem, "revoked (keyCompromise") || r.Revocation[0].Status != "revoked" {
		t.Errorf("a revoked leaf: %+v", r)
	}

	r = Verify(c, opts(crl(root, rk, now, Revoked{inter.SerialNumber, 2, now})))
	if r.Valid || !strings.Contains(r.Problem, "Intermediate is revoked") {
		t.Errorf("a revoked intermediate: %+v", r)
	}

	if r := Verify(c, opts(crl(inter, ik, now.Add(-30*24*time.Hour)))); r.Valid || !strings.Contains(r.Problem, "valid from") {
		t.Errorf("a list out of date: %+v", r)
	}

	stranger, sk := ca(t, MLDSA44, "CN=Stranger", 100)
	if r := Verify(c, opts(crl(stranger, sk, now))); !r.Valid || len(r.Notes) != 1 || r.Revocation[0].Status != "not checked" {
		t.Errorf("a stranger's list: %+v", r)
	}

	if _, err := ParseReason("certificateHold"); err == nil {
		t.Error("certificateHold was accepted")
	}
}

// TestRequests: a request carries its subject and names to the certificate exactly, and one
// whose signature does not verify is refused.
func TestRequests(t *testing.T) {
	root, rk := ca(t, MLDSA87, "CN=Root", 3650)
	k := mustKey(t, MLDSA65)

	name, _ := ParseName("/C=AU/O=Example/CN=svc.example")

	var sans SANs
	_ = sans.AddSAN("svc.example")
	_ = sans.AddSAN("10.0.0.1")

	der, err := Request(name, sans, k, false)
	if err != nil {
		t.Fatal(err)
	}

	csr, _ := x509.ParseCertificateRequest(der)

	rawSubject, got, err := FromRequest(csr)
	if err != nil {
		t.Fatal(err)
	}

	tm := Template{RawSubject: rawSubject, SANs: got, Profile: ProfileServer, Days: 30, PathLen: -1}

	cder, err := Issue(tm, csr.PublicKey, root, rk, now)
	c := mustParse(t, cder, err)
	if string(c.RawSubject) != string(csr.RawSubject) || c.Subject.String() != "CN=svc.example,O=Example,C=AU" ||
		len(c.IPAddresses) != 1 || c.DNSNames[0] != "svc.example" {
		t.Errorf("the certificate's subject %s, names %v %v", c.Subject, c.DNSNames, c.IPAddresses)
	}

	der[len(der)-1] ^= 1
	if bad, err := x509.ParseCertificateRequest(der); err == nil {
		if _, _, err := FromRequest(bad); err == nil {
			t.Error("a request with a broken signature was accepted")
		}
	}
}

// TestNames: both ways of writing a subject encode the same, most general first; escapes
// hold; and a SAN's type is taken from its shape.
func TestNames(t *testing.T) {
	a, _ := ParseName("/C=AU/O=Ex\\/ample/CN=host")
	b, _ := ParseName("CN=host, O=Ex/ample, C=AU")

	if a.String() != b.String() || a.String() != "CN=host,O=Ex/ample,C=AU" {
		t.Errorf("%q and %q", a, b)
	}

	if _, err := ParseName("CN=x,C=Australia"); err == nil {
		t.Error("a three-letter country was accepted")
	}

	if _, err := ParseName("XX=y"); err == nil {
		t.Error("an unknown attribute was accepted")
	}

	var s SANs
	for _, v := range []string{"a.example", "*.b.example", "192.0.2.1", "2001:db8::1", "me@example.com", "spiffe://x/y", "DNS:c.example"} {
		if err := s.AddSAN(v); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}

	if len(s.DNS) != 3 || len(s.IP) != 2 || len(s.Email) != 1 || len(s.URI) != 1 {
		t.Errorf("%+v", s)
	}

	for _, bad := range []string{"*.example", "a..b", "-a.b", "IP:300.1.1.1", "a_b.example"} {
		if err := s.AddSAN(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func bigOne() *big.Int { return big.NewInt(1) }
