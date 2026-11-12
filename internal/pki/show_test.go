package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the show goldens (and, where missing, the fixtures they read)")

// fixtures are public material alone -- certificates, a request, a list and a public key --
// made once by -update and committed; the keys that made them are thrown away.
var fixtures = []string{"root.pem", "server.pem", "request.pem", "crl.pem", "public.pem"}

func makeFixtures(t *testing.T, dir string) {
	t.Helper()

	root, rk := ca(t, MLDSA87, "/C=AU/O=Conflux Test/CN=Conflux Test Root", 3650)

	k := mustKey(t, MLDSA65)
	tm := mustName(t, "/O=Conflux Test/CN=server.test")
	tm.Profile, tm.Days, tm.CRLURLs = ProfileServer, 90, []string{"http://ca.test/root.crl"}

	for _, s := range []string{"server.test", "192.0.2.10"} {
		_ = tm.SANs.AddSAN(s)
	}

	server, err := Issue(tm, k.Public(), root, rk, now)
	if err != nil {
		t.Fatal(err)
	}

	rq, _ := ParseName("CN=client.test")

	var sans SANs
	_ = sans.AddSAN("ops@client.test")

	req, err := Request(rq, sans, mustKey(t, ECDSAP256), false)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := CRL(root, rk, []Revoked{{big.NewInt(0x1234), 4, now}}, big.NewInt(7), now, 7, false)
	if err != nil {
		t.Fatal(err)
	}

	pub, _ := MarshalPublicKey(mustKey(t, Ed25519).Public())

	for name, o := range map[string]Object{
		"root.pem": {KindCertificate, root.Raw}, "server.pem": {KindCertificate, server},
		"request.pem": {KindRequest, req}, "crl.pem": {KindCRL, crl}, "public.pem": {KindPublicKey, pub},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), o.PEM(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestShowGoldens: show's text and JSON for each fixture, as of a fixed now, are the
// committed ones.
func TestShowGoldens(t *testing.T) {
	dir := filepath.Join("testdata", "show")

	if _, err := os.Stat(filepath.Join(dir, "root.pem")); os.IsNotExist(err) && *update {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}

		makeFixtures(t, dir)
	}

	for _, f := range fixtures {
		objs, err := ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}

		s, err := Show(objs[0], now.Add(24*60*60*1e9))
		if err != nil {
			t.Fatal(err)
		}

		var text bytes.Buffer
		s.Text(&text)

		js, _ := json.MarshalIndent(s, "", "  ")

		for ext, got := range map[string][]byte{".txt": text.Bytes(), ".json": append(js, '\n')} {
			golden := filepath.Join(dir, f[:len(f)-4]+ext)

			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}

				continue
			}

			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (go test ./internal/pki -update writes it)", err)
			}

			if !bytes.Equal(got, want) {
				t.Errorf("%s changed:\n--- got\n%s\n--- want\n%s", golden, got, want)
			}
		}
	}
}

// TestShowNeverPrintsAPrivateKey: a private key is shown by its public half, and nothing of
// the key itself is in what show prints.
func TestShowNeverPrintsAPrivateKey(t *testing.T) {
	k := mustKey(t, Ed25519)
	p8, _ := MarshalPrivateKey(k)

	s, err := Show(Object{KindPrivateKey, p8}, now)
	if err != nil {
		t.Fatal(err)
	}

	var text bytes.Buffer
	s.Text(&text)

	js, _ := json.Marshal(s)

	seed := p8[len(p8)-32:]
	for _, out := range [][]byte{text.Bytes(), js} {
		if bytes.Contains(out, seed) || bytes.Contains(bytes.ToLower(out), []byte(colonHexLower(seed))) {
			t.Errorf("show printed the key: %s", out)
		}
	}

	if s.Key == nil || s.Key.Name != "Ed25519" {
		t.Errorf("show did not describe the key: %+v", s)
	}

	enc, _ := EncryptPrivateKey(p8, []byte("a passphrase"))

	s, err = Show(Object{KindEncryptedKey, enc}, now)
	if err != nil || s.Encryption != "PBES2: PBKDF2-HMAC-SHA-256, 600000 iterations, 16-byte salt; AES-256-CBC" {
		t.Errorf("an encrypted key showed %q, %v", s.Encryption, err)
	}
}

func colonHexLower(b []byte) string {
	return string(bytes.ToLower([]byte(colonHex(b))))
}

// TestFingerprints: a certificate's fingerprint is its DER's digest, its --spki one its
// public key's, and a private key's is always its public key's.
func TestFingerprints(t *testing.T) {
	root, rk := ca(t, MLDSA44, "CN=r", 30)

	f, err := FingerprintOf(Object{KindCertificate, root.Raw}, SHA256, false)
	if err != nil || f.Hex != colonHex(SHA256.Sum(root.Raw)) {
		t.Errorf("certificate: %+v %v", f, err)
	}

	spki, err := FingerprintOf(Object{KindCertificate, root.Raw}, SHA3_256, true)
	if err != nil || spki.Hex != colonHex(SHA3_256.Sum(root.RawSubjectPublicKeyInfo)) {
		t.Errorf("spki: %+v %v", spki, err)
	}

	p8, _ := MarshalPrivateKey(rk)

	kf, err := FingerprintOf(Object{KindPrivateKey, p8}, SHA3_256, false)
	if err != nil || kf.Hex != spki.Hex {
		t.Errorf("a private key's fingerprint %+v is not its public key's %s", kf, spki.Hex)
	}

	for _, bad := range []string{"sha1", "md5", "sha-1"} {
		if _, err := ParseDigest(bad); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}

	if d, err := ParseDigest("SHA3-512"); err != nil || d != SHA3_512 {
		t.Errorf("SHA3-512: %s %v", d, err)
	}

	_ = x509.ParseCertificate
}
