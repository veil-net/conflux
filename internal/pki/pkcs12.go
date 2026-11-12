package pki

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"unicode/utf16"
)

// PKCS#12 (RFC 7292) in the one profile every part of which FIPS 140-3 approves: the key in a
// shrouded key bag under PBES2 (PBKDF2-HMAC-SHA-256, AES-256-CBC, as pbes2.go writes a key),
// the certificates in a SafeContents encrypted the same way, and the whole held by a PBMAC1
// MAC (RFC 9579: PBKDF2-HMAC-SHA-256 and HMAC-SHA-256). PKCS#12's own KDF, SHA-1, 3DES and
// RC2 -- what most PKCS#12 files are made of -- are never used, and a file made of them is
// refused, naming the line that rewrites it.
//
// The passphrase is its UTF-8 bytes throughout, as OpenSSL uses it for PBES2 and PBMAC1 and
// as RFC 9579's own test vectors are made, whatever its prose says of BMPStrings.

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	oidKeyBag         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidShroudedKeyBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidX509Cert       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}

	oidFriendlyName = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidLocalKeyID   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}

	oidPBMAC1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
)

// macSaltUnused is what the MacData's salt holds under PBMAC1, which ignores it (RFC 9579,
// 4): not empty, for the readers that look, as the RFC's vectors write it.
var macSaltUnused = []byte("NOT USED")

// p12Rewrite is the line that rewrites a bundle in the form read here: OpenSSL opens it, and
// conflux writes what comes down the pipe, the key never on disk in the clear.
const p12Rewrite = "openssl pkcs12 -in OLD.p12 -nodes | conflux cert p12 export --in - --out NEW.p12"

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type encryptedData struct {
	Version int
	Info    encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Algorithm   pkix.AlgorithmIdentifier
	Content     []byte `asn1:"tag:0,optional"`
}

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type macDataOut struct {
	Mac        digestInfo
	Salt       []byte
	Iterations int
}

type macDataIn struct {
	Mac        digestInfo
	Salt       []byte
	Iterations int `asn1:"optional,default:1"`
}

type pfxOut struct {
	Version  int
	AuthSafe contentInfo
	MacData  macDataOut
}

type pfxIn struct {
	Version  int
	AuthSafe contentInfo
	MacData  macDataIn `asn1:"optional"`
}

type pbmac1Params struct {
	KDF    pkix.AlgorithmIdentifier
	Scheme pkix.AlgorithmIdentifier
}

// EncodePKCS12 bundles key with its certificate, the first of certs, and the rest of the
// chain, under passphrase. name, when given, is the friendly name importers show.
func EncodePKCS12(key crypto.Signer, certs []*x509.Certificate, passphrase []byte, name string) ([]byte, error) {
	if len(passphrase) < MinPassphrase {
		return nil, fmt.Errorf("a passphrase is %d characters or more", MinPassphrase)
	}

	if len(certs) == 0 {
		return nil, errors.New("a bundle needs the key's certificate")
	}

	if !SamePublicKey(certs[0].PublicKey, key.Public()) {
		return nil, errors.New("the key is not the one the first certificate certifies")
	}

	// The key and its certificate are paired by a local key ID, which importers match.
	// OpenSSL takes SHA-1 of the certificate; here it is SHA-256's first 160 bits.
	sum := sha256.Sum256(certs[0].Raw)
	attrs, err := bagAttributes(sum[:20], name)
	if err != nil {
		return nil, err
	}

	p8, err := MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}

	shrouded, err := EncryptPrivateKey(p8, passphrase)
	if err != nil {
		return nil, err
	}

	keyBags, err := asn1.Marshal([]safeBag{{ID: oidShroudedKeyBag, Value: explicit0(shrouded), Attributes: attrs}})
	if err != nil {
		return nil, err
	}

	bags := make([]safeBag, len(certs))

	for i, c := range certs {
		b, err := asn1.Marshal(certBag{ID: oidX509Cert, Data: c.Raw})
		if err != nil {
			return nil, err
		}

		bags[i] = safeBag{ID: oidCertBag, Value: explicit0(b)}
		if i == 0 {
			bags[i].Attributes = attrs
		}
	}

	certContents, err := asn1.Marshal(bags)
	if err != nil {
		return nil, err
	}

	algo, sealed, err := pbes2SealFresh(certContents, passphrase)
	if err != nil {
		return nil, err
	}

	encCerts, err := asn1.Marshal(encryptedData{Info: encryptedContentInfo{ContentType: oidData, Algorithm: algo, Content: sealed}})
	if err != nil {
		return nil, err
	}

	keyData, err := asn1.Marshal(keyBags)
	if err != nil {
		return nil, err
	}

	authSafe, err := asn1.Marshal([]contentInfo{
		{ContentType: oidEncryptedData, Content: explicit0(encCerts)},
		{ContentType: oidData, Content: explicit0(keyData)},
	})
	if err != nil {
		return nil, err
	}

	mac, err := pbmac1(authSafe, passphrase)
	if err != nil {
		return nil, err
	}

	authSafeData, err := asn1.Marshal(authSafe)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(pfxOut{Version: 3, AuthSafe: contentInfo{ContentType: oidData, Content: explicit0(authSafeData)}, MacData: mac})
}

// explicit0 is der as the [0] EXPLICIT a ContentInfo or a SafeBag carries its content in.
func explicit0(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der}
}

func bagAttributes(localKeyID []byte, name string) ([]pkcs12Attribute, error) {
	id, err := asn1.Marshal(localKeyID)
	if err != nil {
		return nil, err
	}

	attrs := []pkcs12Attribute{{ID: oidLocalKeyID, Value: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: id}}}

	if name != "" {
		attrs = append(attrs, pkcs12Attribute{ID: oidFriendlyName, Value: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: bmpString(name)}})
	}

	return attrs, nil
}

// bmpString is s as an ASN.1 BMPString, the friendly name's type.
func bmpString(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, 2*len(u))

	for _, r := range u {
		b = append(b, byte(r>>8), byte(r))
	}

	der, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagBMPString, Bytes: b})

	return der
}

// pbmac1 is the MacData holding authSafe's octets: HMAC-SHA-256 under a key PBKDF2-HMAC-SHA-256
// derives, its parameters in the PBMAC1 AlgorithmIdentifier.
func pbmac1(authSafe, passphrase []byte) (macDataOut, error) {
	salt := make([]byte, pbkdf2SaltSize)
	rand.Read(salt)

	return pbmac1With(authSafe, passphrase, salt)
}

// pbmac1With is pbmac1 with its salt given, for the known-answer test.
func pbmac1With(authSafe, passphrase, salt []byte) (macDataOut, error) {
	kdf, err := asn1.Marshal(pbkdf2Params{
		Salt: salt, Iterations: pbkdf2Iterations, KeyLength: sha256.Size,
		PRF: pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue},
	})
	if err != nil {
		return macDataOut{}, err
	}

	params, err := asn1.Marshal(pbmac1Params{
		KDF:    pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdf}},
		Scheme: pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue},
	})
	if err != nil {
		return macDataOut{}, err
	}

	key, err := pbkdf2.Key(sha256.New, string(passphrase), salt, pbkdf2Iterations, sha256.Size)
	if err != nil {
		return macDataOut{}, err
	}

	m := hmac.New(sha256.New, key)
	m.Write(authSafe)

	return macDataOut{
		Mac:        digestInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBMAC1, Parameters: asn1.RawValue{FullBytes: params}}, Digest: m.Sum(nil)},
		Salt:       macSaltUnused,
		Iterations: 1,
	}, nil
}

// P12Refusal is a bundle refused as made of what FIPS 140-3 does not approve.
type P12Refusal struct{ What string }

func (r P12Refusal) Error() string {
	return fmt.Sprintf("this PKCS#12 bundle uses %s, which conflux does not read: it reads PBES2 (PBKDF2-HMAC-SHA-2, "+
		"AES-CBC) bags under a PBMAC1 MAC alone, every part of it FIPS 140-3 approved. To rewrite it so:\n  %s", r.What, p12Rewrite)
}

// DecodePKCS12 opens a bundle in the profile EncodePKCS12 writes: its MAC is checked first,
// then its bags decrypted. It returns the key and the certificates, the key's own first.
func DecodePKCS12(der, passphrase []byte) (crypto.Signer, []*x509.Certificate, error) {
	var pfx pfxIn
	if rest, err := asn1.Unmarshal(der, &pfx); err != nil || len(rest) != 0 {
		return nil, nil, errors.New("this is not a PKCS#12 bundle")
	}

	switch {
	case pfx.Version != 3:
		return nil, nil, fmt.Errorf("this PKCS#12 bundle is version %d, not 3", pfx.Version)
	case pfx.AuthSafe.ContentType.Equal(oidSignedData):
		return nil, nil, P12Refusal{"public-key integrity (a signed authSafe)"}
	case !pfx.AuthSafe.ContentType.Equal(oidData):
		return nil, nil, errors.New("this PKCS#12 bundle's authSafe is neither data nor signed data")
	case len(pfx.MacData.Mac.Digest) == 0:
		return nil, nil, P12Refusal{"no MAC, so nothing holds it to its passphrase"}
	}

	var authSafe []byte
	if _, err := asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &authSafe); err != nil {
		return nil, nil, errors.New("this PKCS#12 bundle's authSafe is damaged")
	}

	if err := checkPBMAC1(pfx.MacData, authSafe, passphrase); err != nil {
		return nil, nil, err
	}

	var infos []contentInfo
	if rest, err := asn1.Unmarshal(authSafe, &infos); err != nil || len(rest) != 0 {
		return nil, nil, errors.New("this PKCS#12 bundle's contents are damaged")
	}

	var (
		keys  []crypto.Signer
		certs []*x509.Certificate
	)

	for _, ci := range infos {
		contents, err := openContent(ci, passphrase)
		if err != nil {
			return nil, nil, err
		}

		var bags []safeBag
		if rest, err := asn1.Unmarshal(contents, &bags); err != nil || len(rest) != 0 {
			return nil, nil, errors.New("this PKCS#12 bundle's bags are damaged")
		}

		for _, b := range bags {
			k, c, err := openBag(b, passphrase)
			if err != nil {
				return nil, nil, err
			}

			if k != nil {
				keys = append(keys, k)
			}

			if c != nil {
				certs = append(certs, c)
			}
		}
	}

	switch {
	case len(keys) == 0:
		return nil, nil, errors.New("this PKCS#12 bundle holds no private key")
	case len(keys) > 1:
		return nil, nil, fmt.Errorf("this PKCS#12 bundle holds %d private keys, and conflux reads bundles of one", len(keys))
	}

	// The key's certificate first, the rest in the order given.
	for i, c := range certs {
		if SamePublicKey(c.PublicKey, keys[0].Public()) {
			certs[0], certs[i] = certs[i], certs[0]

			return keys[0], certs, nil
		}
	}

	return nil, nil, errors.New("no certificate in this PKCS#12 bundle is the key's")
}

// macHashes are the HMACs a PBMAC1 MAC is read under, by OID: SHA-2's.
var macHashes = []struct {
	oid asn1.ObjectIdentifier
	new func() hash.Hash
}{
	{oidHMACSHA224, sha256.New224},
	{oidHMACSHA256, sha256.New},
	{oidHMACSHA384, sha512.New384},
	{oidHMACSHA512, sha512.New},
}

func macHash(oid asn1.ObjectIdentifier) func() hash.Hash {
	for _, h := range macHashes {
		if oid.Equal(h.oid) {
			return h.new
		}
	}

	return nil
}

// checkPBMAC1 verifies a PBMAC1 MAC over authSafe, refusing any other MAC: PKCS#12's own, the
// one most bundles carry, derives its key with PKCS#12's KDF, which is not approved.
func checkPBMAC1(md macDataIn, authSafe, passphrase []byte) error {
	if alg := md.Mac.Algorithm.Algorithm; !alg.Equal(oidPBMAC1) {
		hash := map[string]string{"1.3.14.3.2.26": "SHA-1", "2.16.840.1.101.3.4.2.1": "SHA-256",
			"2.16.840.1.101.3.4.2.2": "SHA-384", "2.16.840.1.101.3.4.2.3": "SHA-512"}[alg.String()]
		if hash == "" {
			hash = alg.String()
		}

		return P12Refusal{"PKCS#12's own MAC, its key from PKCS#12's KDF with " + hash}
	}

	var params pbmac1Params
	if rest, err := asn1.Unmarshal(md.Mac.Algorithm.Parameters.FullBytes, &params); err != nil || len(rest) != 0 {
		return errors.New("this PKCS#12 bundle's PBMAC1 parameters are damaged")
	}

	if !params.KDF.Algorithm.Equal(oidPBKDF2) {
		return P12Refusal{"a PBMAC1 key derivation other than PBKDF2"}
	}

	var kdf pbkdf2Params
	if rest, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil || len(rest) != 0 {
		return errors.New("this PKCS#12 bundle's PBMAC1 PBKDF2 parameters are damaged")
	}

	prf := macHash(kdf.PRF.Algorithm)
	scheme := macHash(params.Scheme.Algorithm)

	switch {
	case prf == nil:
		return P12Refusal{"a PBMAC1 key derived with HMAC-SHA-1, or a PRF not SHA-2's"}
	case scheme == nil:
		return P12Refusal{"a PBMAC1 MAC that is not an HMAC with SHA-2"}
	case kdf.KeyLength == 0:
		// RFC 9579, 5: a reader MUST NOT accept PBKDF2 parameters without the key length.
		return errors.New("this PKCS#12 bundle's PBMAC1 names no key length, which RFC 9579 requires")
	case kdf.KeyLength < 20 || kdf.KeyLength > 64:
		return fmt.Errorf("this PKCS#12 bundle's PBMAC1 key is %d bytes; conflux reads 20 to 64", kdf.KeyLength)
	case len(kdf.Salt) < pbkdf2SaltSize:
		return P12Refusal{fmt.Sprintf("a %d-byte PBMAC1 salt; SP 800-132 asks for 16 or more", len(kdf.Salt))}
	case kdf.Iterations < 1 || kdf.Iterations > maxIterations:
		return fmt.Errorf("this PKCS#12 bundle asks for %d PBKDF2 iterations; conflux reads 1 to %d", kdf.Iterations, maxIterations)
	}

	key, err := pbkdf2.Key(prf, string(passphrase), kdf.Salt, kdf.Iterations, kdf.KeyLength)
	if err != nil {
		return err
	}

	m := hmac.New(scheme, key)
	m.Write(authSafe)

	if !hmac.Equal(m.Sum(nil), md.Mac.Digest) {
		return errors.New("the passphrase does not open this PKCS#12 bundle: it is wrong, or the file is damaged")
	}

	return nil
}

// openContent is one ContentInfo of the authSafe as its SafeContents' octets: in the clear,
// or decrypted where PBES2 encrypted it.
func openContent(ci contentInfo, passphrase []byte) ([]byte, error) {
	switch {
	case ci.ContentType.Equal(oidData):
		var b []byte
		if _, err := asn1.Unmarshal(ci.Content.Bytes, &b); err != nil {
			return nil, errors.New("this PKCS#12 bundle's contents are damaged")
		}

		return b, nil
	case ci.ContentType.Equal(oidEncryptedData):
		var ed encryptedData
		if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
			return nil, errors.New("this PKCS#12 bundle's encrypted contents are damaged")
		}

		s, err := parseScheme(ed.Info.Algorithm, ed.Info.Content)

		var refused SchemeRefusal
		if errors.As(err, &refused) {
			return nil, P12Refusal{refused.What + " for its certificates"}
		}

		if err != nil {
			return nil, err
		}

		out, err := pbes2Open(s, passphrase)
		if err != nil {
			return nil, err
		}

		return out, nil
	}

	return nil, P12Refusal{"contents of type " + ci.ContentType.String() + " (enveloped, say)"}
}

// openBag reads one bag: a shrouded key, or an X.509 certificate. Any other is refused: a key
// in the clear has no business in a bundle that has a passphrase.
func openBag(b safeBag, passphrase []byte) (crypto.Signer, *x509.Certificate, error) {
	switch {
	case b.ID.Equal(oidShroudedKeyBag):
		p8, err := DecryptPrivateKey(b.Value.Bytes, passphrase)

		var refused SchemeRefusal
		if errors.As(err, &refused) {
			return nil, nil, P12Refusal{refused.What + " for its key"}
		}

		if err != nil {
			return nil, nil, err
		}

		k, err := ParsePrivateKey(p8)

		return k, nil, err
	case b.ID.Equal(oidCertBag):
		var cb certBag
		if _, err := asn1.Unmarshal(b.Value.Bytes, &cb); err != nil {
			return nil, nil, errors.New("this PKCS#12 bundle's certificate bag is damaged")
		}

		if !cb.ID.Equal(oidX509Cert) {
			return nil, nil, fmt.Errorf("this PKCS#12 bundle holds a certificate of type %s, not X.509", cb.ID)
		}

		c, err := x509.ParseCertificate(cb.Data)

		return nil, c, err
	case b.ID.Equal(oidKeyBag):
		return nil, nil, P12Refusal{"a key in the clear (a keyBag)"}
	}

	return nil, nil, fmt.Errorf("this PKCS#12 bundle holds a bag of type %s, which conflux does not read", b.ID)
}

// IsPKCS12 reports whether der has the shape of a PFX: SEQUENCE { INTEGER 3, SEQUENCE ... }.
func IsPKCS12(der []byte) bool {
	var pfx struct {
		Version  int
		AuthSafe asn1.RawValue
		Rest     asn1.RawValue `asn1:"optional"`
	}

	rest, err := asn1.Unmarshal(der, &pfx)

	return err == nil && len(rest) == 0 && pfx.Version == 3 && bytes.HasPrefix(pfx.AuthSafe.FullBytes, []byte{0x30})
}
