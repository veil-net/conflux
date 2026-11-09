package tlsprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/pki"
)

// chain is a root of rootAlg and a server certificate of leafAlg for "server.test" and
// 127.0.0.1 under it.
func chain(t *testing.T, rootAlg, leafAlg pki.Alg, p pki.Profile) (*x509.Certificate, tls.Certificate) {
	t.Helper()

	return chainAt(t, rootAlg, leafAlg, p, time.Now())
}

// chainAt is chain issued at: a root for 60 days and a leaf for 10.
func chainAt(t *testing.T, rootAlg, leafAlg pki.Alg, p pki.Profile, at time.Time) (*x509.Certificate, tls.Certificate) {
	t.Helper()

	rk, err := rootAlg.Generate()
	if err != nil {
		t.Fatal(err)
	}

	name, _ := pki.ParseName("CN=Probe Root")
	rootDER, err := pki.Issue(pki.Template{Subject: name, Profile: pki.ProfileCA, Days: 60, PathLen: -1}, rk.Public(), nil, rk, at)
	if err != nil {
		t.Fatal(err)
	}

	root, _ := x509.ParseCertificate(rootDER)

	lk, err := leafAlg.Generate()
	if err != nil {
		t.Fatal(err)
	}

	tm := pki.Template{Profile: p, Days: 10, PathLen: -1}
	tm.Subject, _ = pki.ParseName("CN=server.test")
	_ = tm.SANs.AddSAN("server.test")
	_ = tm.SANs.AddSAN("127.0.0.1")

	leafDER, err := pki.Issue(tm, lk.Public(), root, rk, at)
	if err != nil {
		t.Fatal(err)
	}

	return root, tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: lk}
}

// serve answers on a loopback port until the test ends, sending what it sees to the channel.
func serve(t *testing.T, opts ServeOptions) (string, <-chan Seen) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	opts.Listener = l
	seen := make(chan Seen, 8)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() { done <- Serve(ctx, opts, func(s Seen) { seen <- s }) }()

	t.Cleanup(func() {
		cancel()

		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	return l.Addr().String(), seen
}

// TestAPostQuantumHandshake: a FIPS 140-3 mode client offering the ML-KEM groups, and a
// server with an ML-DSA chain, agree on TLS 1.3, a hybrid group and an ML-DSA signature;
// the chain verifies for its name and is pqc throughout; and the server saw the groups and
// the ML-DSA schemes offered.
func TestAPostQuantumHandshake(t *testing.T) {
	root, cert := chain(t, pki.MLDSA87, pki.MLDSA65, pki.ProfileServer)
	addr, seen := serve(t, ServeOptions{Cert: cert})

	groups, _ := ParseGroups("pq")

	r, err := Probe(t.Context(), Options{Address: addr, ServerName: "server.test", Roots: []*x509.Certificate{root}, Groups: groups})
	if err != nil {
		t.Fatal(err)
	}

	// The server picks, in its own order: Go's puts X25519MLKEM768 first.
	if r.Version != "TLS 1.3" || r.Group != "X25519MLKEM768" || r.GroupClass != pki.ClassHybrid {
		t.Errorf("negotiated %s, %s (%s)", r.Version, r.Group, r.GroupClass)
	}

	if r.Signature != "ML-DSA-65" || !r.SignatureExact || r.SignatureClass != pki.ClassPQC {
		t.Errorf("signature %s (exact %v, %s)", r.Signature, r.SignatureExact, r.SignatureClass)
	}

	if !r.Chain.Valid || r.Chain.Authentication != pki.ClassPQC || !r.KeyExchangePQ() || !r.AuthenticationPQ() {
		t.Errorf("chain %+v", r.Chain)
	}

	assertLeaf(t, r.Leaf, cert)

	s := <-seen
	if s.Error != "" || s.GroupClass != pki.ClassHybrid || s.Offered.ServerName != "server.test" ||
		!strings.Contains(strings.Join(s.Offered.Groups, ","), "SecP384r1MLKEM1024") ||
		!strings.Contains(strings.Join(s.Offered.Signatures, ","), "mldsa65") {
		t.Errorf("the server saw %+v", s)
	}

	if strings.Contains(strings.Join(s.Offered.Groups, ","), "x25519,") {
		t.Errorf("a FIPS 140-3 mode client offered X25519 alone: %v", s.Offered.Groups)
	}

	// A server that prefers ML-KEM-1024 with P-384 gets it.
	strongest, _ := ParseGroups("SecP384r1MLKEM1024")
	addr, _ = serve(t, ServeOptions{Cert: cert, Groups: strongest})

	if r, err := Probe(t.Context(), Options{Address: addr, ServerName: "server.test", Roots: []*x509.Certificate{root}, Groups: groups}); err != nil ||
		r.Group != "SecP384r1MLKEM1024" {
		t.Errorf("against a server preferring SecP384r1MLKEM1024: %s, %v", r.Group, err)
	}

	// And ML-KEM-1024 alone is pqc.
	pure, _ := ParseGroups("MLKEM1024")
	addr, _ = serve(t, ServeOptions{Cert: cert, Groups: pure})

	if r, err := Probe(t.Context(), Options{Address: addr, ServerName: "server.test", Roots: []*x509.Certificate{root}, Groups: pure}); err != nil ||
		r.GroupClass != pki.ClassPQC {
		t.Errorf("ML-KEM-1024 alone: %s (%s), %v", r.Group, r.GroupClass, err)
	}
}

// TestClassicalIsSaidSo: classical groups make a classical key exchange; an ECDSA leaf under an
// ML-DSA root a classical authentication; and TLS 1.2 is reported, with ECDSA's hash unknown.
func TestClassicalIsSaidSo(t *testing.T) {
	root, cert := chain(t, pki.MLDSA87, pki.ECDSAP256, pki.ProfileServer)
	addr, _ := serve(t, ServeOptions{Cert: cert})

	classical, _ := ParseGroups("classical")

	r, err := Probe(t.Context(), Options{Address: addr, ServerName: "server.test", Roots: []*x509.Certificate{root}, Groups: classical})
	if err != nil {
		t.Fatal(err)
	}

	if r.GroupClass != pki.ClassClassical || r.KeyExchangePQ() || !r.Chain.Valid || r.Chain.Authentication != pki.ClassClassical || r.AuthenticationPQ() {
		t.Errorf("%+v", r)
	}

	r, err = Probe(t.Context(), Options{Address: addr, ServerName: "server.test", Roots: []*x509.Certificate{root}, Version: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}

	if r.Version != "TLS 1.2" || r.SignatureExact || r.Signature != "ECDSA P-256" || r.GroupClass != pki.ClassClassical {
		t.Errorf("TLS 1.2: %+v", r)
	}
}

// TestAChainThatDoesNotVerifyIsReported: the handshake is described, and the chain's problem
// said, rather than the connection only refused.
func TestAChainThatDoesNotVerifyIsReported(t *testing.T) {
	_, cert := chain(t, pki.MLDSA87, pki.MLDSA65, pki.ProfileServer)
	other, _ := chain(t, pki.MLDSA87, pki.MLDSA65, pki.ProfileServer)
	addr, _ := serve(t, ServeOptions{Cert: cert})

	r, err := Probe(t.Context(), Options{Address: addr, ServerName: "server.test", Roots: []*x509.Certificate{other}})
	if err != nil {
		t.Fatal(err)
	}

	if r.Chain.Valid || r.Chain.Problem == "" || r.Presented != pki.ClassPQC || r.AuthenticationPQ() {
		t.Errorf("%+v", r)
	}

	// The leaf is described all the same: a chain from another CA is dated too.
	assertLeaf(t, r.Leaf, cert)

	r, _ = Probe(t.Context(), Options{Address: addr, ServerName: "wrong.test", Roots: []*x509.Certificate{other}})
	if r.Chain.Valid {
		t.Error("a chain for another name verified")
	}
}

// TestAnExpiredCertificateIsDated: a leaf whose time has passed fails its chain, and the report
// still says when it ran out, so its expiry can be shown rather than only its failure.
func TestAnExpiredCertificateIsDated(t *testing.T) {
	root, cert := chainAt(t, pki.MLDSA87, pki.MLDSA65, pki.ProfileServer, time.Now().AddDate(0, 0, -30))
	addr, _ := serve(t, ServeOptions{Cert: cert})

	r, err := Probe(t.Context(), Options{Address: addr, ServerName: "server.test", Roots: []*x509.Certificate{root}})
	if err != nil {
		t.Fatal(err)
	}

	if r.Chain.Valid || r.Chain.Problem == "" {
		t.Errorf("an expired leaf verified: %+v", r.Chain)
	}

	assertLeaf(t, r.Leaf, cert)

	if !r.Leaf.NotAfter.Before(time.Now()) {
		t.Errorf("the expired leaf runs to %s", r.Leaf.NotAfter)
	}
}

// assertLeaf: l describes the leaf cert sends, in UTC, its serial as the CA tools write it.
func assertLeaf(t *testing.T, l Leaf, cert tls.Certificate) {
	t.Helper()

	c, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	want := Leaf{
		Subject:   "CN=server.test",
		Issuer:    "CN=Probe Root",
		Serial:    pki.FormatSerial(c.SerialNumber),
		NotBefore: c.NotBefore.UTC(),
		NotAfter:  c.NotAfter.UTC(),
	}

	if l != want {
		t.Errorf("the leaf is described as %+v, not %+v", l, want)
	}

	if l.NotBefore.Location() != time.UTC || l.NotAfter.Location() != time.UTC {
		t.Errorf("the leaf is dated outside UTC: %s, %s", l.NotBefore, l.NotAfter)
	}
}

// TestClientCertificates: a server asking for one verifies it and names it; a client
// without one is refused, and the server says so.
func TestClientCertificates(t *testing.T) {
	root, cert := chain(t, pki.MLDSA87, pki.MLDSA65, pki.ProfileServer)
	_, client := chain(t, pki.MLDSA87, pki.MLDSA44, pki.ProfileClient)

	clientRoot, _ := x509.ParseCertificate(client.Certificate[1])
	addr, seen := serve(t, ServeOptions{Cert: cert, ClientCAs: []*x509.Certificate{clientRoot}})

	if _, err := Probe(t.Context(), Options{Address: addr, ServerName: "server.test", Roots: []*x509.Certificate{root}, ClientCert: &client}); err != nil {
		t.Fatal(err)
	}

	if s := <-seen; s.Client != "CN=server.test" || s.Error != "" {
		t.Errorf("the server saw %+v", s)
	}

	_, _ = Probe(t.Context(), Options{Address: addr, ServerName: "server.test", Roots: []*x509.Certificate{root}})

	if s := <-seen; s.Error == "" {
		t.Errorf("a client with no certificate was answered: %+v", s)
	}
}

// TestGroups: pq and classical name the groups; x25519 alone is refused, naming the hybrid
// that carries it.
func TestGroups(t *testing.T) {
	if g, err := ParseGroups("X25519MLKEM768, secp384r1"); err != nil || len(g) != 2 || g[0] != tls.X25519MLKEM768 || g[1] != tls.CurveP384 {
		t.Errorf("%v %v", g, err)
	}

	if _, err := ParseGroups("x25519"); err == nil || !strings.Contains(err.Error(), "X25519MLKEM768") {
		t.Errorf("x25519: %v", err)
	}

	if GroupClass(tls.MLKEM1024) != pki.ClassPQC || GroupClass(tls.X25519MLKEM768) != pki.ClassHybrid || GroupClass(tls.CurveP256) != pki.ClassClassical {
		t.Error("the classes are wrong")
	}
}
