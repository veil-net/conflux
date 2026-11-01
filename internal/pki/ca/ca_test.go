package ca

import (
	"crypto/x509"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/pki"
)

var now = time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)

var pass = []byte("the CA's passphrase")

func initCA(t *testing.T, intermediate bool) *CA {
	t.Helper()

	c, err := Init(filepath.Join(t.TempDir(), "ca"), InitOptions{
		Name: "Test", Org: "Conflux, Tests", RootAlg: pki.MLDSA87, Intermediate: intermediate, IntermediateAlg: pki.MLDSA65,
		RootDays: 3650, IntermediateDays: 1825, LeafDays: 90, CRLDays: 7, CRLURLs: []string{"http://ca.test/crl.pem"},
		Passphrase: pass,
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(c.Close)

	return c
}

func server(t *testing.T, name string) (pki.Template, any) {
	t.Helper()

	k, err := pki.MLDSA44.Generate()
	if err != nil {
		t.Fatal(err)
	}

	tm := pki.Template{Profile: pki.ProfileServer, PathLen: -1}
	tm.Subject, _ = pki.ParseName("CN=" + name)
	_ = tm.SANs.AddSAN(name)

	return tm, k.Public()
}

func roots(t *testing.T, c *CA) (root *x509.Certificate, intermediates []*x509.Certificate) {
	t.Helper()

	chain, err := c.Chain()
	if err != nil {
		t.Fatal(err)
	}

	return chain[len(chain)-1], chain[:len(chain)-1]
}

func crls(t *testing.T, c *CA) []*x509.RevocationList {
	t.Helper()

	var out []*x509.RevocationList

	for _, f := range []string{"crl.pem", "root.crl"} {
		objs, err := pki.ReadFile(c.path(f))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}

		if err != nil {
			t.Fatal(err)
		}

		l, err := x509.ParseRevocationList(objs[0].DER)
		if err != nil {
			t.Fatal(err)
		}

		out = append(out, l)
	}

	return out
}

// TestACAIssuesRevokesAndPublishes: a root and an issuing CA, the names escaped; three
// certificates issued, each recorded under its serial; one revoked, and the CRLs then fail
// it and pass the others, through the whole chain; list says which.
func TestACAIssuesRevokesAndPublishes(t *testing.T) {
	c := initCA(t, true)
	root, inter := roots(t, c)

	if root.Subject.String() != `CN=Test Root CA,O=Conflux\, Tests` || inter[0].Subject.CommonName != "Test Issuing CA" ||
		root.MaxPathLen != 1 || !inter[0].MaxPathLenZero {
		t.Errorf("root %s (path %d), intermediate %s", root.Subject, root.MaxPathLen, inter[0].Subject)
	}

	var issued []*x509.Certificate

	for _, n := range []string{"a.test", "b.test", "c.test"} {
		tm, pub := server(t, n)

		x, err := c.Issue(tm, pub, pass, now)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := os.Stat(c.serialFile(x.SerialNumber)); err != nil {
			t.Errorf("%s was not recorded: %v", n, err)
		}

		if !x.NotAfter.Equal(now.Add(90*24*time.Hour)) || x.CRLDistributionPoints[0] != "http://ca.test/crl.pem" {
			t.Errorf("%s: not after %s, CRL %v", n, x.NotAfter, x.CRLDistributionPoints)
		}

		issued = append(issued, x)
	}

	if err := c.Revoke(issued[1].SerialNumber, 1, pass, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	for i, x := range issued {
		r := pki.Verify(x, pki.VerifyOptions{Roots: []*x509.Certificate{root}, Intermediates: inter, CRLs: crls(t, c), At: now.Add(2 * time.Hour)})
		if r.Valid == (i == 1) || r.Authentication != pki.ClassPQC && r.Valid {
			t.Errorf("%s: valid %v (%s), revocation %+v", x.Subject, r.Valid, r.Problem, r.Revocation)
		}
	}

	list, err := c.List(now.Add(time.Hour))
	if err != nil || len(list) != 3 {
		t.Fatalf("list: %v %v", list, err)
	}

	revoked := 0

	for _, e := range list {
		if e.Status == "revoked" {
			revoked++

			if e.Serial != pki.FormatSerial(issued[1].SerialNumber) || e.Reason != "keyCompromise" {
				t.Errorf("the revoked entry %+v", e)
			}
		}
	}

	if revoked != 1 {
		t.Errorf("list has %d revoked", revoked)
	}

	if err := c.Revoke(issued[1].SerialNumber, 1, pass, now); err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("a second revocation: %v", err)
	}

	if err := c.Revoke(big.NewInt(12345), 0, pass, now); err == nil || !strings.Contains(err.Error(), "issued no certificate") {
		t.Errorf("revoking a serial never issued: %v", err)
	}
}

// TestCRLNumbersOnlyGrow: each publication moves both numbers on, and a revocation publishes.
func TestCRLNumbersOnlyGrow(t *testing.T) {
	c := initCA(t, true)

	number := func() (int64, int64) {
		ls := crls(t, c)

		return ls[0].Number.Int64(), ls[1].Number.Int64()
	}

	if a, b := number(); a != 1 || b != 1 {
		t.Errorf("init published %d and %d, want 1 and 1", a, b)
	}

	if err := c.CRL(pass, now); err != nil {
		t.Fatal(err)
	}

	tm, pub := server(t, "x.test")

	x, err := c.Issue(tm, pub, pass, now)
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Revoke(x.SerialNumber, 4, pass, now); err != nil {
		t.Fatal(err)
	}

	if a, b := number(); a != 3 || b != 3 {
		t.Errorf("after a publication and a revocation: %d and %d, want 3 and 3", a, b)
	}
}

// TestASerialIsNeverIssuedTwice: a serial already in issued/ is drawn again, and the record
// there is left as it was.
func TestASerialIsNeverIssuedTwice(t *testing.T) {
	c := initCA(t, false)

	taken := big.NewInt(0xbeef)
	if err := os.WriteFile(c.serialFile(taken), []byte("an earlier certificate"), 0o644); err != nil {
		t.Fatal(err)
	}

	draws := 0
	was := newSerial
	newSerial = func() (*big.Int, error) {
		draws++
		if draws == 1 {
			return taken, nil
		}

		return was()
	}

	t.Cleanup(func() { newSerial = was })

	tm, pub := server(t, "y.test")

	x, err := c.Issue(tm, pub, pass, now)
	if err != nil {
		t.Fatal(err)
	}

	if x.SerialNumber.Cmp(taken) == 0 || draws != 2 {
		t.Errorf("issued serial %s after %d draws", x.SerialNumber, draws)
	}

	if b, _ := os.ReadFile(c.serialFile(taken)); string(b) != "an earlier certificate" {
		t.Error("the earlier record was replaced")
	}
}

// TestTheCAIsGuarded: a second command in a CA one holds is refused; the keys need their
// passphrase; a CA is made only in an empty directory; it issues no CA, and nothing past
// its issuer.
func TestTheCAIsGuarded(t *testing.T) {
	c := initCA(t, false)

	if _, err := Open(c.Dir); !errors.Is(err, ErrBusy) {
		t.Errorf("opening a CA another holds: %v", err)
	}

	c.Close()

	d, err := Open(c.Dir)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(d.Close)

	tm, pub := server(t, "z.test")

	if _, err := d.Issue(tm, pub, []byte("not the passphrase"), now); !errors.Is(err, pki.ErrPassphrase) {
		t.Errorf("a wrong passphrase: %v", err)
	}

	if _, err := d.Issue(tm, pub, nil, now); err == nil {
		t.Error("an encrypted CA issued with no passphrase")
	}

	tm.Profile = pki.ProfileCA
	if _, err := d.Issue(tm, pub, pass, now); err == nil {
		t.Error("a managed CA issued a CA")
	}

	tm.Profile, tm.Days = pki.ProfileServer, 4000
	if _, err := d.Issue(tm, pub, pass, now); err == nil || !strings.Contains(err.Error(), "outlive") {
		t.Errorf("a certificate past its issuer: %v", err)
	}

	if _, err := Init(c.Dir, InitOptions{Name: "Again", RootAlg: pki.Ed25519, RootDays: 10, CRLDays: 1}, now); err == nil {
		t.Error("a CA was made over another")
	}

	if _, err := Open(t.TempDir()); err == nil || !strings.Contains(err.Error(), "ca.json") {
		t.Errorf("opening a directory with no CA: %v", err)
	}

	for _, f := range []string{"root.key"} {
		b, _ := os.ReadFile(c.path(f))
		if !strings.Contains(string(b), "ENCRYPTED PRIVATE KEY") {
			t.Errorf("%s is not encrypted", f)
		}
	}
}
