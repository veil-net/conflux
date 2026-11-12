package pki

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

var p12Pass = []byte("a bundle's passphrase")

// bundleOf is a key of alg, its certificate under an ML-DSA root, and the root.
func bundleOf(t *testing.T, alg Alg) (*x509.Certificate, *x509.Certificate, crypto.Signer) {
	t.Helper()

	root, rk := ca(t, MLDSA87, "CN=P12 Root", 100)
	c, k := leaf(t, alg, ProfileServer, root, rk)

	return c, root, k
}

// TestPKCS12RoundTrips: every algorithm's key and chain come back from a bundle as they went
// in, the key's certificate first; a wrong passphrase is refused by the MAC, before any bag is
// opened; a bundle one byte of whose contents changed is refused the same way.
func TestPKCS12RoundTrips(t *testing.T) {
	for _, a := range []Alg{MLDSA44, MLDSA65, MLDSA87, ECDSAP384, RSA2048, Ed25519} {
		c, root, k := bundleOf(t, a)

		// The root first, to show the key's certificate is found, not assumed.
		der, err := EncodePKCS12(k, []*x509.Certificate{c, root}, p12Pass, "server.test")
		if err != nil {
			t.Fatalf("%s: %v", a, err)
		}

		if !IsPKCS12(der) {
			t.Errorf("%s: the bundle does not look like one", a)
		}

		gk, certs, err := DecodePKCS12(der, p12Pass)
		if err != nil {
			t.Fatalf("%s: %v", a, err)
		}

		if !SamePublicKey(gk.Public(), k.Public()) || len(certs) != 2 || !certs[0].Equal(c) || !certs[1].Equal(root) {
			t.Errorf("%s: came back as %d certificates, the key matching %v", a, len(certs), SamePublicKey(gk.Public(), k.Public()))
		}

		if _, _, err := DecodePKCS12(der, []byte("not the passphrase")); err == nil || !strings.Contains(err.Error(), "does not open") {
			t.Errorf("%s: a wrong passphrase: %v", a, err)
		}

		tampered := append([]byte{}, der...)
		tampered[len(tampered)/2] ^= 1

		if _, _, err := DecodePKCS12(tampered, p12Pass); err == nil {
			t.Errorf("%s: a tampered bundle was opened", a)
		}
	}

	c, _, k := bundleOf(t, Ed25519)
	other, _, _ := bundleOf(t, Ed25519)

	if _, err := EncodePKCS12(k, []*x509.Certificate{other}, p12Pass, ""); err == nil {
		t.Error("a bundle of a key and another key's certificate was made")
	}

	if _, err := EncodePKCS12(k, []*x509.Certificate{c}, []byte("short"), ""); err == nil {
		t.Error("a bundle under a short passphrase was made")
	}
}

// TestPBMAC1KnownAnswer: under a fixed salt, the MAC is PBKDF2-HMAC-SHA-256 at 600,000
// iterations into a 32-byte key, then HMAC-SHA-256 of the authSafe -- the digest Python's
// hashlib computes independently -- and its parameters are RFC 9579's, the key length
// present, the MacData's own salt and count the RFC's placeholders.
func TestPBMAC1KnownAnswer(t *testing.T) {
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = 0x11
	}

	md, err := pbmac1With([]byte("the authSafe octets"), []byte("conflux-kat"), salt)
	if err != nil {
		t.Fatal(err)
	}

	// python3 -c "import hashlib,hmac; k=hashlib.pbkdf2_hmac('sha256', b'conflux-kat', b'\x11'*16, 600000, 32);
	//   print(hmac.new(k, b'the authSafe octets', 'sha256').hexdigest())"
	const want = "9e64b7fae7562e5da8c2c60a3690ad3e751ba3f230797e873561fc9aefa544d5"
	if got := hex.EncodeToString(md.Mac.Digest); got != want {
		t.Errorf("the MAC is %s, want %s", got, want)
	}

	params, _ := asn1.Marshal(md.Mac.Algorithm)

	// SEQUENCE { PBMAC1, SEQUENCE { SEQUENCE { PBKDF2, SEQUENCE { salt, 600000, 32,
	// SEQUENCE { hmacWithSHA256, NULL } } }, SEQUENCE { hmacWithSHA256, NULL } } }
	const wantParams = "305206092a864886f70d01050e3045303506092a864886f70d01050c3028" +
		"041011111111111111111111111111111111" + "02030927c0" + "020120" + "300c06082a864886f70d02090500" +
		"300c06082a864886f70d02090500"

	if got := hex.EncodeToString(params); got != wantParams {
		t.Errorf("the PBMAC1 parameters:\n got %s\nwant %s", got, wantParams)
	}

	if string(md.Salt) != "NOT USED" || md.Iterations != 1 {
		t.Errorf("the MacData's own salt %q and count %d", md.Salt, md.Iterations)
	}

	if err := checkPBMAC1(macDataIn(md), []byte("the authSafe octets"), []byte("conflux-kat")); err != nil {
		t.Errorf("the known answer does not verify: %v", err)
	}
}

// pfxWith is a PFX around authSafe with md as its MAC.
func pfxWith(t *testing.T, authSafe []byte, md macDataOut) []byte {
	t.Helper()

	data, _ := asn1.Marshal(authSafe)

	der, err := asn1.Marshal(pfxOut{Version: 3, AuthSafe: contentInfo{ContentType: oidData, Content: explicit0(data)}, MacData: md})
	if err != nil {
		t.Fatal(err)
	}

	return der
}

// TestUnapprovedBundlesAreRefused: the PKCS#12 most tools write -- PKCS#12's own MAC, its
// SHA-1 and 3DES bag encryption, a key in the clear -- is refused by name, with the line
// that rewrites it; and PBMAC1 without a key length, or with a short salt, is refused too.
func TestUnapprovedBundlesAreRefused(t *testing.T) {
	c, _, k := bundleOf(t, ECDSAP256)

	good, err := EncodePKCS12(k, []*x509.Certificate{c}, p12Pass, "")
	if err != nil {
		t.Fatal(err)
	}

	var pfx pfxIn
	if _, err := asn1.Unmarshal(good, &pfx); err != nil {
		t.Fatal(err)
	}

	var authSafe []byte
	_, _ = asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &authSafe)

	sha1MAC := macDataOut{
		Mac:  digestInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, Parameters: asn1.NullRawValue}, Digest: make([]byte, 20)},
		Salt: make([]byte, 8), Iterations: 2048,
	}

	// A PBMAC1 whose PBKDF2 parameters are given.
	pbmacWith := func(kdf pbkdf2Params) macDataOut {
		kd, _ := asn1.Marshal(kdf)
		p, _ := asn1.Marshal(pbmac1Params{
			KDF:    pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kd}},
			Scheme: pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue},
		})

		return macDataOut{Mac: digestInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBMAC1, Parameters: asn1.RawValue{FullBytes: p}}, Digest: make([]byte, 32)},
			Salt: macSaltUnused, Iterations: 1}
	}

	sha256PRF := pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue}

	// An authSafe of one SafeContents in the clear, holding bag.
	withBag := func(b safeBag) []byte {
		bags, _ := asn1.Marshal([]safeBag{b})
		data, _ := asn1.Marshal(bags)
		as, _ := asn1.Marshal([]contentInfo{{ContentType: oidData, Content: explicit0(data)}})

		return as
	}

	// An authSafe of one SafeContents under PKCS#12's own SHA-1 and 3DES encryption.
	pbe3DES := func() []byte {
		ed, _ := asn1.Marshal(encryptedData{Info: encryptedContentInfo{ContentType: oidData,
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}}, Content: make([]byte, 16)}})
		as, _ := asn1.Marshal([]contentInfo{{ContentType: oidEncryptedData, Content: explicit0(ed)}})

		return as
	}

	// A PBMAC1 that verifies, over as, so what is refused is what is inside.
	valid := func(as []byte) macDataOut {
		md, err := pbmac1(as, p12Pass)
		if err != nil {
			t.Fatal(err)
		}

		return md
	}

	for _, c := range []struct {
		name string
		der  []byte
		says string
	}{
		{"PKCS#12's own MAC", pfxWith(t, authSafe, sha1MAC), "PKCS#12's own MAC"},
		{"PBMAC1 with no key length", pfxWith(t, authSafe, pbmacWith(pbkdf2Params{Salt: make([]byte, 16), Iterations: 1000, PRF: sha256PRF})), "no key length"},
		{"PBMAC1 with an 8-byte salt", pfxWith(t, authSafe, pbmacWith(pbkdf2Params{Salt: make([]byte, 8), Iterations: 1000, KeyLength: 32, PRF: sha256PRF})), "8-byte PBMAC1 salt"},
		{"PBMAC1 under HMAC-SHA-1", pfxWith(t, authSafe, pbmacWith(pbkdf2Params{Salt: make([]byte, 16), Iterations: 1000, KeyLength: 32})), "HMAC-SHA-1"},
		{"bags under SHA-1 and 3DES", pfxWith(t, pbe3DES(), valid(pbe3DES())), "for its certificates"},
		{"a key in the clear", pfxWith(t, withBag(safeBag{ID: oidKeyBag, Value: explicit0([]byte{0x30, 0})}), valid(withBag(safeBag{ID: oidKeyBag, Value: explicit0([]byte{0x30, 0})}))), "keyBag"},
	} {
		_, _, err := DecodePKCS12(c.der, p12Pass)

		var refused P12Refusal
		if err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v, want a refusal saying %q", c.name, err, c.says)
		} else if errors.As(err, &refused) && !strings.Contains(err.Error(), p12Rewrite) {
			t.Errorf("%s: the refusal does not give the line that rewrites it", c.name)
		}
	}
}

// TestABundleIsNotMistakenForAKey: a bundle begins with an INTEGER, as PKCS#8 does, and is
// read as a bundle, pointing at p12 import.
func TestABundleIsNotMistakenForAKey(t *testing.T) {
	c, _, k := bundleOf(t, Ed25519)

	der, err := EncodePKCS12(k, []*x509.Certificate{c}, p12Pass, "")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Parse(der); err == nil || !strings.Contains(err.Error(), "p12 import") {
		t.Errorf("a bundle parsed as %v", err)
	}
}
