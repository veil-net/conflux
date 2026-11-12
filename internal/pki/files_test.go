package pki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestParseTellsKindsApart: PEM by its label, and DER by its shape, each kind is read as
// itself; an EC or RSA key in its legacy form is read as the PKCS#8 of the same key.
func TestParseTellsKindsApart(t *testing.T) {
	root, rk := ca(t, ECDSAP256, "CN=r", 30)
	p8, _ := MarshalPrivateKey(rk)
	enc, _ := EncryptPrivateKey(p8, []byte("a passphrase"))
	pub, _ := MarshalPublicKey(rk.Public())
	req, _ := Request(root.Subject, SANs{}, rk, false)
	crl, _ := CRL(root, rk, nil, bigOne(), now, 1, false)

	for kind, der := range map[Kind][]byte{
		KindCertificate: root.Raw, KindPrivateKey: p8, KindEncryptedKey: enc,
		KindPublicKey: pub, KindRequest: req, KindCRL: crl,
	} {
		objs, err := Parse(der)
		if err != nil || len(objs) != 1 || objs[0].Kind != kind {
			t.Errorf("the DER of a %s read as %+v, %v", kind, objs, err)
		}

		objs, err = Parse(Object{kind, der}.PEM())
		if err != nil || len(objs) != 1 || objs[0].Kind != kind {
			t.Errorf("the PEM of a %s read as %+v, %v", kind, objs, err)
		}
	}

	sec1, _ := x509.MarshalECPrivateKey(rk.(*ecdsa.PrivateKey))

	objs, err := Parse(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))
	if err != nil || objs[0].Kind != KindPrivateKey {
		t.Fatalf("a SEC 1 key: %+v %v", objs, err)
	}

	if k, err := ParsePrivateKey(objs[0].DER); err != nil || !SamePublicKey(k.Public(), rk.Public()) {
		t.Errorf("a SEC 1 key was not read as itself: %v", err)
	}

	legacy := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{
		"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00000000000000000000000000000000",
	}, Bytes: []byte("junk")})

	if _, err := Parse(legacy); err == nil || !strings.Contains(err.Error(), "MD5") {
		t.Errorf("a legacy encrypted PEM: %v, want a refusal naming MD5", err)
	}

	chain := append(Object{KindCertificate, root.Raw}.PEM(), Object{KindCertificate, root.Raw}.PEM()...)
	if objs, err := Parse(chain); err != nil || len(objs) != 2 {
		t.Errorf("a chain of two read as %d: %v", len(objs), err)
	}
}

// TestWriteKeepsKeys: a key in the clear is written 0600, and never over a file that is
// there unless forced; a certificate is replaced; a key in the clear is not printed to a
// terminal.
func TestWriteKeepsKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.pem")
	key := []Object{{KindPrivateKey, []byte("k")}}

	if err := Write(path, key, false, false); err != nil {
		t.Fatal(err)
	}

	if st, _ := os.Stat(path); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("the key was written %v", st.Mode().Perm())
	}

	if err := Write(path, key, false, false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("a second write over the key: %v", err)
	}

	if err := Write(path, []Object{{KindEncryptedKey, []byte("e")}}, false, false); err == nil {
		t.Error("an encrypted key replaced the key")
	}

	if err := Write(path, key, false, true); err != nil {
		t.Errorf("a forced write: %v", err)
	}

	cert := filepath.Join(dir, "c.pem")
	for range 2 {
		if err := Write(cert, []Object{{KindCertificate, []byte("c")}}, false, false); err != nil {
			t.Errorf("a certificate: %v", err)
		}
	}

	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("the writes left %d files, want the 2 named", len(entries))
	}

	was := StdoutIsTerminal
	StdoutIsTerminal = func() bool { return true }

	defer func() { StdoutIsTerminal = was }()

	if err := Write("-", key, false, false); err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Errorf("a key to a terminal: %v", err)
	}
}
