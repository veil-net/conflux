package pki

import (
	"bytes"
	"crypto/fips140"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha3"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// TestMLDSAIsAvailable: the build carries a module with ML-DSA in it, running in FIPS 140-3
// mode. v1.0.0, the certified one, has none, and a build against it would make every ML-DSA
// command fail at its first key.
func TestMLDSAIsAvailable(t *testing.T) {
	if !fips140.Enabled() {
		t.Fatal("the tests run outside FIPS 140-3 mode: run them through make, which builds against the module")
	}

	if err := CheckFIPS(); err != nil {
		t.Fatal(err)
	}

	k, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("module %s makes no ML-DSA key: %v", fips140.Version(), err)
	}

	sig, err := k.Sign(rand.Reader, []byte("m"), nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := mldsa.Verify(k.PublicKey(), []byte("m"), sig, nil); err != nil {
		t.Fatal(err)
	}
}

// TestEveryAlgorithmRoundTrips: each algorithm's key comes back from its PKCS#8 as the same
// key, and ML-DSA's PKCS#8 is the seed form, 32 bytes of key.
func TestEveryAlgorithmRoundTrips(t *testing.T) {
	for _, a := range Algs {
		t.Run(string(a), func(t *testing.T) {
			k, err := a.Generate()
			if err != nil {
				t.Fatal(err)
			}

			der, err := MarshalPrivateKey(k)
			if err != nil {
				t.Fatal(err)
			}

			back, err := ParsePrivateKey(der)
			if err != nil {
				t.Fatal(err)
			}

			if !SamePublicKey(k.Public(), back.Public()) {
				t.Error("the parsed key is not the key marshalled")
			}

			if strings.HasPrefix(string(a), "ml-dsa") && len(der) != 54 {
				t.Errorf("an ML-DSA key's PKCS#8 is %d bytes; the seed form is 54", len(der))
			}

			if got, err := ParseAlg(strings.ToUpper(strings.ReplaceAll(string(a), "-", ""))); err != nil || got != a {
				t.Errorf("ParseAlg(%s) = %s, %v", a, got, err)
			}
		})
	}
}

// both is RFC 9881's both form of the ML-DSA-65 key from seed, with an expanded key whose
// first 128 bytes, ρ ‖ K ‖ tr, are what seed makes (or, with wrongSeed, what another seed
// makes) and whose remainder is filler: the parser checks no further.
func both(t *testing.T, seed []byte, wrongSeed bool) []byte {
	t.Helper()

	sk, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		t.Fatal(err)
	}

	from := seed
	if wrongSeed {
		from = bytes.Repeat([]byte{7}, 32)
	}

	h := sha3.SumSHAKE256(append(bytes.Clone(from), 6, 5), 128)
	expanded := make([]byte, 4032)
	copy(expanded, h[:32])
	copy(expanded[32:], h[96:128])
	copy(expanded[64:], sha3.SumSHAKE256(sk.PublicKey().Bytes(), 64))

	inner, err := asn1.Marshal(struct{ Seed, Expanded []byte }{seed, expanded})
	if err != nil {
		t.Fatal(err)
	}

	der, err := asn1.Marshal(struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: oidMLDSA65}, inner})
	if err != nil {
		t.Fatal(err)
	}

	return der
}

// TestTheBothFormIsReadFromItsSeed: OpenSSL's default ML-DSA key, the seed beside the
// expanded key, is read as the key its seed makes; one whose expanded key came from another
// seed is refused; one with no seed is refused, saying so.
func TestTheBothFormIsReadFromItsSeed(t *testing.T) {
	seed := bytes.Repeat([]byte{1}, 32)

	k, err := ParsePrivateKey(both(t, seed, false))
	if err != nil {
		t.Fatal(err)
	}

	want, _ := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if !SamePublicKey(k.Public(), want.Public()) {
		t.Error("the both form was not read as its seed's key")
	}

	if _, err := ParsePrivateKey(both(t, seed, true)); err == nil || !strings.Contains(err.Error(), "two different keys") {
		t.Errorf("a both form whose halves disagree = %v, want a refusal naming two keys", err)
	}

	expandedOnly, _ := asn1.Marshal(struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: oidMLDSA65}, append([]byte{0x04, 0x82, 0x0f, 0xc0}, make([]byte, 4032)...)})

	if _, err := ParsePrivateKey(expandedOnly); err == nil || !strings.Contains(err.Error(), "without the seed") {
		t.Errorf("an expanded-only key = %v, want a refusal naming the missing seed", err)
	}
}

// TestPBES2RoundTrips: every algorithm's key comes back from its encryption under the right
// passphrase, and under a wrong one the answer is ErrPassphrase, not a key.
func TestPBES2RoundTrips(t *testing.T) {
	for _, a := range []Alg{MLDSA87, ECDSAP384, RSA2048, Ed25519} {
		k, _ := a.Generate()
		p8, _ := MarshalPrivateKey(k)

		enc, err := EncryptPrivateKey(p8, []byte("correct horse"))
		if err != nil {
			t.Fatal(err)
		}

		got, err := DecryptPrivateKey(enc, []byte("correct horse"))
		if err != nil || !bytes.Equal(got, p8) {
			t.Errorf("%s: decrypt = %v", a, err)
		}

		if _, err := DecryptPrivateKey(enc, []byte("wrong horse!")); !errors.Is(err, ErrPassphrase) {
			t.Errorf("%s: a wrong passphrase gave %v, want ErrPassphrase", a, err)
		}
	}

	if _, err := EncryptPrivateKey([]byte{0}, []byte("short")); err == nil {
		t.Error("a passphrase under 8 characters was accepted")
	}
}

// TestPBES2KnownAnswer: under a fixed salt and IV, the encryption is these exact bytes -- the
// PBES2 parameters as RFC 8018 encodes PBKDF2-HMAC-SHA-256 at 600,000 iterations and
// AES-256-CBC, and the ciphertext the module's PBKDF2 and AES make of a fixed plaintext.
// OpenSSL 3.5's `openssl pkcs8 -inform DER -passin pass:conflux-kat` opens the same bytes to
// the same key.
func TestPBES2KnownAnswer(t *testing.T) {
	salt := bytes.Repeat([]byte{0x11}, 16)
	iv := bytes.Repeat([]byte{0x22}, 16)

	// The PKCS#8 of the Ed25519 key whose seed is 32 bytes of 0x33.
	p8, _ := hex.DecodeString("302e020100300506032b657004220420" + strings.Repeat("33", 32))

	got, err := encryptWith(p8, []byte("conflux-kat"), salt, iv)
	if err != nil {
		t.Fatal(err)
	}

	// SEQUENCE { PBES2, SEQUENCE { SEQUENCE { PBKDF2, SEQUENCE { salt, 600000,
	// SEQUENCE { hmacWithSHA256, NULL } } }, SEQUENCE { aes256-CBC, iv } } }
	const params = "306006092a864886f70d01050d3053303206092a864886f70d01050c3025" +
		"0410" + "11111111111111111111111111111111" + "02030927c0" +
		"300c06082a864886f70d02090500" +
		"301d060960864801650304012a0410" + "22222222222222222222222222222222"

	h := hex.EncodeToString(got)
	if !strings.HasPrefix(h, "3081a4"+params) {
		t.Errorf("the PBES2 parameters are not RFC 8018's encoding:\n got %s\nwant 3081a4%s...", h, params)
	}

	if h != pbes2KAT {
		t.Errorf("the encryption changed:\n got %s\nwant %s", h, pbes2KAT)
	}

	back, err := DecryptPrivateKey(got, []byte("conflux-kat"))
	if err != nil || !bytes.Equal(back, p8) {
		t.Errorf("the known answer does not decrypt: %v", err)
	}
}

// pbes2KAT is the known answer, frozen once OpenSSL 3.5.9 had opened it to p8.
const pbes2KAT = "3081a4306006092a864886f70d01050d3053303206092a864886f70d01050c3025041011111111111111111111111111111111" +
	"02030927c0300c06082a864886f70d02090500301d060960864801650304012a0410222222222222222222222222222222220440" +
	"0f31dcb426e239d1acdfff1b49f2847b3746ca256034e18d1c0b7cbbb466ce938185c53731ecfe94228a31d8de254ed315d174ce1e54ce0b1aca763a3ab8a547"

// encrypted is an EncryptedPrivateKeyInfo with the scheme given and junk to decrypt.
func encrypted(t *testing.T, algo pkix.AlgorithmIdentifier) []byte {
	t.Helper()

	der, err := asn1.Marshal(encryptedPrivateKeyInfo{Algo: algo, Data: make([]byte, 48)})
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func raw(t *testing.T, v any) asn1.RawValue {
	t.Helper()

	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return asn1.RawValue{FullBytes: b}
}

func pbes2With(t *testing.T, kdf, enc pkix.AlgorithmIdentifier) pkix.AlgorithmIdentifier {
	return pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: raw(t, pbes2Params{KDF: kdf, Enc: enc})}
}

// TestUnapprovedEncryptionIsRefused: each scheme FIPS 140-3 does not approve is refused by
// name, with the OpenSSL line that re-encrypts it, before any passphrase is used.
func TestUnapprovedEncryptionIsRefused(t *testing.T) {
	salt16 := bytes.Repeat([]byte{1}, 16)
	iv := raw(t, bytes.Repeat([]byte{2}, 16))
	aes256 := pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: iv}
	sha256PRF := pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue}

	kdf := func(salt []byte, prf pkix.AlgorithmIdentifier) pkix.AlgorithmIdentifier {
		return pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: raw(t, pbkdf2Params{Salt: salt, Iterations: 2048, PRF: prf})}
	}

	for _, c := range []struct {
		name string
		algo pkix.AlgorithmIdentifier
		says string
	}{
		{"PBES1 SHA-1 3DES", pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}}, "PBES1"},
		{"PBES1 MD5 DES", pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}}, "PBES1"},
		{"the default PRF, HMAC-SHA-1", pbes2With(t, kdf(salt16, pkix.AlgorithmIdentifier{}), aes256), "HMAC-SHA-1"},
		{"HMAC-SHA-1 named", pbes2With(t, kdf(salt16, pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA1, Parameters: asn1.NullRawValue}), aes256), "HMAC-SHA-1"},
		{"scrypt", pbes2With(t, pkix.AlgorithmIdentifier{Algorithm: oidScrypt}, aes256), "scrypt"},
		{"3DES", pbes2With(t, kdf(salt16, sha256PRF), pkix.AlgorithmIdentifier{Algorithm: oidDESEDE3CBC, Parameters: raw(t, make([]byte, 8))}), "3DES"},
		{"an 8-byte salt", pbes2With(t, kdf(salt16[:8], sha256PRF), aes256), "8-byte salt"},
	} {
		_, err := DecryptPrivateKey(encrypted(t, c.algo), []byte("anything at all"))
		if err == nil || !strings.Contains(err.Error(), c.says) || !strings.Contains(err.Error(), reencrypt) {
			t.Errorf("%s: %v, want a refusal naming %q and the line that re-encrypts it", c.name, err, c.says)
		}
	}
}
