package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Backdate is how far before now a certificate's validity starts, for the clocks that run a
// little behind the issuer's.
const Backdate = 5 * time.Minute

// Template is what a certificate is issued from, beyond the key it certifies.
type Template struct {
	Subject pkix.Name

	// RawSubject, when set, is the subject as DER, written as it is: a request's, whose
	// encoding the certificate keeps exactly.
	RawSubject []byte

	SANs    SANs
	Profile Profile
	Days    int

	// PathLen bounds the CAs below a ca-profile certificate; -1 leaves it unbounded.
	PathLen int

	// CRLURLs are where a relying party fetches the issuer's revocation list.
	CRLURLs []string

	// RSAPSS signs with RSASSA-PSS where the issuer's key is RSA, rather than PKCS #1 v1.5.
	RSAPSS bool
}

// SignatureAlgorithm is the algorithm a key signs certificates, requests and lists with:
// ML-DSA and Ed25519 pure, ECDSA with the SHA-2 its curve pairs with, RSA with the SHA-2
// its size does.
func SignatureAlgorithm(pub crypto.PublicKey, pss bool) (x509.SignatureAlgorithm, error) {
	switch k := pub.(type) {
	case *mldsa.PublicKey:
		switch k.Parameters() {
		case mldsa.MLDSA44():
			return x509.MLDSA44, nil
		case mldsa.MLDSA65():
			return x509.MLDSA65, nil
		default:
			return x509.MLDSA87, nil
		}
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return x509.ECDSAWithSHA256, nil
		case 384:
			return x509.ECDSAWithSHA384, nil
		default:
			return x509.ECDSAWithSHA512, nil
		}
	case *rsa.PublicKey:
		bits := k.N.BitLen()

		switch {
		case bits <= 2048 && pss:
			return x509.SHA256WithRSAPSS, nil
		case bits <= 2048:
			return x509.SHA256WithRSA, nil
		case bits <= 3072 && pss:
			return x509.SHA384WithRSAPSS, nil
		case bits <= 3072:
			return x509.SHA384WithRSA, nil
		case pss:
			return x509.SHA512WithRSAPSS, nil
		default:
			return x509.SHA512WithRSA, nil
		}
	case ed25519.PublicKey:
		return x509.PureEd25519, nil
	}

	return 0, supported(pub)
}

// Issue makes a certificate for pub from t, signed by issuerKey: as issuer when there is one,
// self-signed when issuer is nil. now is when it is issued.
func Issue(t Template, pub crypto.PublicKey, issuer *x509.Certificate, issuerKey crypto.Signer, now time.Time) ([]byte, error) {
	if err := supported(pub); err != nil {
		return nil, err
	}

	if t.Days < 1 {
		return nil, errors.New("a certificate is valid for a day or more")
	}

	if t.Profile.NeedsName() && t.SANs.Empty() {
		return nil, fmt.Errorf("a %s certificate needs a name a client checks: --san", t.Profile)
	}

	serial, err := Serial()
	if err != nil {
		return nil, err
	}

	ski, err := SubjectKeyID(pub)
	if err != nil {
		return nil, err
	}

	alg, err := SignatureAlgorithm(issuerKey.Public(), t.RSAPSS)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               t.Subject,
		RawSubject:            t.RawSubject,
		NotBefore:             now.Add(-Backdate).UTC().Truncate(time.Second),
		NotAfter:              now.Add(time.Duration(t.Days) * 24 * time.Hour).UTC().Truncate(time.Second),
		SubjectKeyId:          ski,
		DNSNames:              t.SANs.DNS,
		IPAddresses:           t.SANs.IP,
		EmailAddresses:        t.SANs.Email,
		URIs:                  t.SANs.URI,
		CRLDistributionPoints: t.CRLURLs,
		SignatureAlgorithm:    alg,
	}

	t.Profile.apply(tmpl, pub, t.PathLen)

	parent := tmpl

	if issuer != nil {
		if err := CanIssue(issuer, issuerKey); err != nil {
			return nil, err
		}

		if tmpl.NotAfter.After(issuer.NotAfter) {
			return nil, fmt.Errorf("the certificate would outlive its issuer, which expires %s: issue it for %d days or fewer",
				issuer.NotAfter.UTC().Format(time.DateTime), int(issuer.NotAfter.Sub(now).Hours()/24))
		}

		parent = issuer
	} else if !SamePublicKey(pub, issuerKey.Public()) {
		return nil, errors.New("a self-signed certificate certifies the key that signs it")
	}

	return x509.CreateCertificate(rand.Reader, tmpl, parent, pub, issuerKey)
}

// CanIssue refuses an issuer that cannot sign certificates, or a key that is not its own.
func CanIssue(issuer *x509.Certificate, key crypto.Signer) error {
	switch {
	case !issuer.BasicConstraintsValid || !issuer.IsCA:
		return fmt.Errorf("%q is not a CA certificate, so nothing it signs is trusted", issuer.Subject)
	case issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCertSign == 0:
		return fmt.Errorf("%q's key usage does not include signing certificates", issuer.Subject)
	case !SamePublicKey(issuer.PublicKey, key.Public()):
		return fmt.Errorf("the key given is not the one %q certifies", issuer.Subject)
	}

	return nil
}

// Serial is a fresh serial number: 128 random bits, positive, and short of RFC 5280's 20 bytes.
func Serial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)

	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}

		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// SubjectKeyID is RFC 7093's first method: SHA-256 of the subjectPublicKey's bits, cut to 160
// bits, which x509 uses for the CAs it makes and this for every certificate.
func SubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	var spki struct {
		Algo      pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}

	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}

	sum := sha256.Sum256(spki.PublicKey.Bytes)

	return sum[:20], nil
}

// Request makes a certificate signing request for key's public half, signed by it.
func Request(subject pkix.Name, sans SANs, key crypto.Signer, pss bool) ([]byte, error) {
	alg, err := SignatureAlgorithm(key.Public(), pss)
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            subject,
		DNSNames:           sans.DNS,
		IPAddresses:        sans.IP,
		EmailAddresses:     sans.Email,
		URIs:               sans.URI,
		SignatureAlgorithm: alg,
	}, key)
}

// FromRequest is what a request asks for, once its signature is checked: its subject, as it
// encoded it, and its names. Nothing else in it is copied; the profile decides what the
// certificate may be used for.
func FromRequest(csr *x509.CertificateRequest) (rawSubject []byte, sans SANs, err error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, SANs{}, fmt.Errorf("the request's signature does not verify: %w", err)
	}

	if err := supported(csr.PublicKey); err != nil {
		return nil, SANs{}, err
	}

	return csr.RawSubject, SANs{DNS: csr.DNSNames, IP: csr.IPAddresses, Email: csr.EmailAddresses, URI: csr.URIs}, nil
}
