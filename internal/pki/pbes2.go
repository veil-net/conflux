package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
)

// PBES2 (RFC 8018), the one way a key here is encrypted: an EncryptedPrivateKeyInfo
// (RFC 5958) whose key PBKDF2 derives with HMAC-SHA-2, enciphered with AES-CBC. Each piece is
// one v1.0.0's Security Policy approves -- PBKDF2 under SP 800-132, AES-CBC under SP 800-38A
// -- and this is the only file conflux's code may build AES-CBC in (approved_test.go).
//
// Written: PBKDF2-HMAC-SHA-256, a 16-byte salt, 600,000 iterations (anchor's parameters, and
// OWASP's for SHA-256), AES-256-CBC. Read: PBKDF2 under any SHA-2 HMAC, with a salt of 16
// bytes or more, and AES-128, -192 or -256 in CBC. Anything else is refused, naming the
// command that re-encrypts it.

// The parameters written.
const (
	pbkdf2Iterations = 600_000
	pbkdf2SaltSize   = 16

	// maxIterations bounds what is read: enough for any real file, and short of a file
	// that would hold the machine for hours.
	maxIterations = 10_000_000

	// MinPassphrase is the shortest passphrase a key is encrypted under.
	MinPassphrase = 8
)

var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}

	oidHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	// oidPKCS5 and oidPKCS12PBE are the arcs PBES1 and PKCS#12's own schemes sit under:
	// DES, RC2, RC4, 3DES, MD5 and SHA-1, none of them approved.
	oidPKCS5      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5}
	oidPKCS12PBE  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1}
	oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

// prfs are the HMACs read, by OID: SHA-2's, which the module approves for PBKDF2.
var prfs = []struct {
	oid  asn1.ObjectIdentifier
	name string
	new  func() hash.Hash
}{
	{oidHMACSHA224, "HMAC-SHA-224", sha256.New224},
	{oidHMACSHA256, "HMAC-SHA-256", sha256.New},
	{oidHMACSHA384, "HMAC-SHA-384", sha512.New384},
	{oidHMACSHA512, "HMAC-SHA-512", sha512.New},
}

// ciphers are the AES-CBC key sizes read, by OID.
var ciphers = []struct {
	oid  asn1.ObjectIdentifier
	name string
	size int
}{
	{oidAES128CBC, "AES-128-CBC", 16},
	{oidAES192CBC, "AES-192-CBC", 24},
	{oidAES256CBC, "AES-256-CBC", 32},
}

type encryptedPrivateKeyInfo struct {
	Algo pkix.AlgorithmIdentifier
	Data []byte
}

type pbes2Params struct {
	KDF pkix.AlgorithmIdentifier
	Enc pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

// reencrypt is the line that rewrites a key OpenSSL can read in the form this reads: OpenSSL
// opens it, asking its passphrase, and conflux encrypts what comes down the pipe, asking a new
// one, so the key is never in the clear on disk. It works with any OpenSSL; one before 3.2
// has no -saltlen and writes an 8-byte salt, so it cannot write this form itself.
const reencrypt = "openssl pkey -in KEY | conflux cert convert - --encrypt --out KEY.new"

// ErrPassphrase is a passphrase that does not open the key: wrong, or the file damaged.
var ErrPassphrase = errors.New("the passphrase does not open this key: it is wrong, or the file is damaged")

// EncryptPrivateKey wraps a PKCS#8 key in an EncryptedPrivateKeyInfo under passphrase.
func EncryptPrivateKey(p8, passphrase []byte) ([]byte, error) {
	if len(passphrase) < MinPassphrase {
		return nil, fmt.Errorf("a passphrase is %d characters or more", MinPassphrase)
	}

	salt := make([]byte, pbkdf2SaltSize)
	iv := make([]byte, aes.BlockSize)

	rand.Read(salt)
	rand.Read(iv)

	return encryptWith(p8, passphrase, salt, iv)
}

// encryptWith is EncryptPrivateKey with its salt and IV given, for the known-answer test.
func encryptWith(p8, passphrase, salt, iv []byte) ([]byte, error) {
	kdf, err := asn1.Marshal(pbkdf2Params{
		Salt:       salt,
		Iterations: pbkdf2Iterations,
		PRF:        pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue},
	})
	if err != nil {
		return nil, err
	}

	ivDER, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}

	params, err := asn1.Marshal(pbes2Params{
		KDF: pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdf}},
		Enc: pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	if err != nil {
		return nil, err
	}

	key, err := pbkdf2.Key(sha256.New, string(passphrase), salt, pbkdf2Iterations, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	pad := aes.BlockSize - len(p8)%aes.BlockSize
	data := append(append([]byte{}, p8...), bytesOf(byte(pad), pad)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)

	return asn1.Marshal(encryptedPrivateKeyInfo{
		Algo: pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: params}},
		Data: data,
	})
}

// pbes2Scheme is a parsed EncryptedPrivateKeyInfo's scheme, everything decryption needs but
// the passphrase.
type pbes2Scheme struct {
	salt       []byte
	iterations int
	prf        string
	newHash    func() hash.Hash
	cipher     string
	keySize    int
	iv         []byte
	data       []byte
}

// String is the scheme as show prints it.
func (s pbes2Scheme) String() string {
	return fmt.Sprintf("PBES2: PBKDF2-%s, %d iterations, %d-byte salt; %s", s.prf, s.iterations, len(s.salt), s.cipher)
}

// parseEncrypted reads an EncryptedPrivateKeyInfo, refusing a scheme that is not approved.
func parseEncrypted(der []byte) (pbes2Scheme, error) {
	var info encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil || len(rest) != 0 {
		return pbes2Scheme{}, errors.New("not an encrypted PKCS#8 key")
	}

	alg := info.Algo.Algorithm

	switch {
	case alg.Equal(oidPBES2):
	case hasPrefix(alg, oidPKCS5) || hasPrefix(alg, oidPKCS12PBE):
		return pbes2Scheme{}, refuseScheme("PBES1 or PKCS#12's own encryption (DES, RC2, RC4, 3DES, MD5 or SHA-1)")
	default:
		return pbes2Scheme{}, refuseScheme("encryption " + alg.String())
	}

	var params pbes2Params
	if rest, err := asn1.Unmarshal(info.Algo.Parameters.FullBytes, &params); err != nil || len(rest) != 0 {
		return pbes2Scheme{}, errors.New("this key's PBES2 parameters are damaged")
	}

	s := pbes2Scheme{data: info.Data}

	switch {
	case params.KDF.Algorithm.Equal(oidPBKDF2):
	case params.KDF.Algorithm.Equal(oidScrypt):
		return pbes2Scheme{}, refuseScheme("scrypt")
	default:
		return pbes2Scheme{}, refuseScheme("key derivation " + params.KDF.Algorithm.String())
	}

	var kdf pbkdf2Params
	if rest, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil || len(rest) != 0 {
		return pbes2Scheme{}, errors.New("this key's PBKDF2 parameters are damaged")
	}

	switch prf := kdf.PRF.Algorithm; {
	case len(prf) == 0, prf.Equal(oidHMACSHA1):
		// Absent, the PRF is HMAC-SHA-1 (RFC 8018, A.2).
		return pbes2Scheme{}, refuseScheme("PBKDF2 with HMAC-SHA-1")
	default:
		for _, p := range prfs {
			if prf.Equal(p.oid) {
				s.prf, s.newHash = p.name, p.new
			}
		}

		if s.newHash == nil {
			return pbes2Scheme{}, refuseScheme("PBKDF2 with PRF " + prf.String())
		}
	}

	switch {
	case len(kdf.Salt) < pbkdf2SaltSize:
		return pbes2Scheme{}, refuseScheme(fmt.Sprintf("a %d-byte salt; SP 800-132 asks for 16 or more", len(kdf.Salt)))
	case kdf.Iterations < 1 || kdf.Iterations > maxIterations:
		return pbes2Scheme{}, fmt.Errorf("this key asks for %d PBKDF2 iterations; conflux reads 1 to %d", kdf.Iterations, maxIterations)
	}

	s.salt, s.iterations = kdf.Salt, kdf.Iterations

	for _, c := range ciphers {
		if params.Enc.Algorithm.Equal(c.oid) {
			s.cipher, s.keySize = c.name, c.size
		}
	}

	switch {
	case s.keySize != 0:
	case params.Enc.Algorithm.Equal(oidDESEDE3CBC):
		return pbes2Scheme{}, refuseScheme("3DES")
	default:
		return pbes2Scheme{}, refuseScheme("cipher " + params.Enc.Algorithm.String())
	}

	if kdf.KeyLength != 0 && kdf.KeyLength != s.keySize {
		return pbes2Scheme{}, fmt.Errorf("this key's PBKDF2 key length, %d, is not %s's", kdf.KeyLength, s.cipher)
	}

	if rest, err := asn1.Unmarshal(params.Enc.Parameters.FullBytes, &s.iv); err != nil || len(rest) != 0 ||
		len(s.iv) != aes.BlockSize {
		return pbes2Scheme{}, errors.New("this key's AES-CBC IV is damaged")
	}

	if len(s.data) == 0 || len(s.data)%aes.BlockSize != 0 {
		return pbes2Scheme{}, errors.New("this key's encrypted data is not whole AES blocks: the file is damaged")
	}

	return s, nil
}

// DecryptPrivateKey opens an EncryptedPrivateKeyInfo, returning the PKCS#8 key inside.
func DecryptPrivateKey(der, passphrase []byte) ([]byte, error) {
	s, err := parseEncrypted(der)
	if err != nil {
		return nil, err
	}

	if len(passphrase) == 0 {
		return nil, ErrPassphrase
	}

	key, err := pbkdf2.Key(s.newHash, string(passphrase), s.salt, s.iterations, s.keySize)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(s.data))
	cipher.NewCBCDecrypter(block, s.iv).CryptBlocks(out, s.data)

	// The padding, checked whole: a wrong passphrase leaves noise that ends in a plausible
	// pad byte about one time in 256, and the structure below catches what this misses.
	pad := int(out[len(out)-1])
	if pad == 0 || pad > aes.BlockSize ||
		subtle.ConstantTimeCompare(out[len(out)-pad:], bytesOf(byte(pad), pad)) != 1 {
		return nil, ErrPassphrase
	}

	// What a wrong passphrase decrypts is not PKCS#8. What the right one decrypts is, and a
	// key inside it this does not read is refused by name where the key is parsed.
	p8 := out[:len(out)-pad]

	var info struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}

	if rest, err := asn1.Unmarshal(p8, &info); err != nil || len(rest) != 0 {
		return nil, ErrPassphrase
	}

	return p8, nil
}

func refuseScheme(what string) error {
	return fmt.Errorf("this key is encrypted with %s. conflux reads PBES2 alone, with PBKDF2-HMAC-SHA-2 and "+
		"AES-CBC, which FIPS 140-3 approves. To re-encrypt it with OpenSSL:\n  %s", what, reencrypt)
}

func hasPrefix(oid, arc asn1.ObjectIdentifier) bool {
	return len(oid) > len(arc) && oid[:len(arc)].Equal(arc)
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}

	return out
}
