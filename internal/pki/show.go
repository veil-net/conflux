package pki

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/url"
	"strings"
	"time"
)

// Shown is what show prints of one object, the same fields as text and as JSON.
type Shown struct {
	Kind string `json:"kind"`

	Subject string    `json:"subject,omitempty"`
	Issuer  string    `json:"issuer,omitempty"`
	Serial  string    `json:"serial,omitempty"`
	From    time.Time `json:"notBefore,omitzero"`
	Until   time.Time `json:"notAfter,omitzero"`
	Status  string    `json:"status,omitempty"`

	Key       *KeyInfo `json:"key,omitempty"`
	KeySHA256 string   `json:"keySHA256,omitempty"`
	Signature string   `json:"signature,omitempty"`
	SigClass  string   `json:"signatureClass,omitempty"`

	CA          *bool    `json:"ca,omitempty"`
	PathLen     *int     `json:"pathLen,omitempty"`
	KeyUsage    []string `json:"keyUsage,omitempty"`
	ExtKeyUsage []string `json:"extKeyUsage,omitempty"`
	DNS         []string `json:"dnsNames,omitempty"`
	IP          []string `json:"ipAddresses,omitempty"`
	Email       []string `json:"emailAddresses,omitempty"`
	URI         []string `json:"uris,omitempty"`
	SKI         string   `json:"subjectKeyId,omitempty"`
	AKI         string   `json:"authorityKeyId,omitempty"`
	CRLURLs     []string `json:"crlDistributionPoints,omitempty"`
	Other       []string `json:"otherExtensions,omitempty"`

	// A revocation list's.
	Number     string        `json:"crlNumber,omitempty"`
	ThisUpdate time.Time     `json:"thisUpdate,omitzero"`
	NextUpdate time.Time     `json:"nextUpdate,omitzero"`
	Revoked    []ShownRevoke `json:"revoked,omitempty"`

	// An encrypted key's.
	Encryption string `json:"encryption,omitempty"`

	SHA256 string `json:"sha256,omitempty"`
}

// ShownRevoke is one revoked certificate a list names.
type ShownRevoke struct {
	Serial string    `json:"serial"`
	At     time.Time `json:"revokedAt"`
	Reason string    `json:"reason"`
}

// Show describes o as of now. A private key is described by its public half alone.
func Show(o Object, now time.Time) (Shown, error) {
	s := Shown{Kind: o.Kind.Name()}

	switch o.Kind {
	case KindCertificate:
		c, err := x509.ParseCertificate(o.DER)
		if err != nil {
			return s, err
		}

		s.certificate(c, now)
		s.SHA256 = colonHex(SHA256.Sum(o.DER))
	case KindRequest:
		r, err := x509.ParseCertificateRequest(o.DER)
		if err != nil {
			return s, err
		}

		s.Subject = r.Subject.String()
		s.signature(r.SignatureAlgorithm)
		s.key(r.PublicKey)
		s.sans(r.DNSNames, r.IPAddresses, r.EmailAddresses, r.URIs)

		if err := r.CheckSignature(); err != nil {
			s.Status = "its signature does not verify: " + err.Error()
		} else {
			s.Status = "signature verifies"
		}
	case KindCRL:
		l, err := x509.ParseRevocationList(o.DER)
		if err != nil {
			return s, err
		}

		s.Issuer = l.Issuer.String()
		s.signature(l.SignatureAlgorithm)
		s.ThisUpdate, s.NextUpdate = l.ThisUpdate.UTC(), l.NextUpdate.UTC()
		s.AKI = colonHex(l.AuthorityKeyId)

		if l.Number != nil {
			s.Number = l.Number.String()
		}

		switch {
		case now.Before(l.ThisUpdate):
			s.Status = "not yet current"
		case !l.NextUpdate.IsZero() && now.After(l.NextUpdate):
			s.Status = "out of date"
		default:
			s.Status = "current"
		}

		for _, e := range l.RevokedCertificateEntries {
			s.Revoked = append(s.Revoked, ShownRevoke{FormatSerial(e.SerialNumber), e.RevocationTime.UTC(), ReasonName(e.ReasonCode)})
		}

		s.SHA256 = colonHex(SHA256.Sum(o.DER))
	case KindPrivateKey, KindPublicKey:
		pub, err := PublicKeyOf(o)
		if err != nil {
			return s, err
		}

		s.key(pub)
	case KindEncryptedKey:
		sch, err := parseEncrypted(o.DER)
		if err != nil {
			return s, err
		}

		s.Encryption = sch.String()
	}

	return s, nil
}

func (s *Shown) certificate(c *x509.Certificate, now time.Time) {
	s.Subject, s.Issuer, s.Serial = c.Subject.String(), c.Issuer.String(), FormatSerial(c.SerialNumber)
	s.From, s.Until = c.NotBefore.UTC(), c.NotAfter.UTC()

	switch {
	case now.Before(c.NotBefore):
		s.Status = "not yet valid"
	case now.After(c.NotAfter):
		s.Status = "expired"
	default:
		s.Status = "valid, " + left(c.NotAfter.Sub(now)) + " left"
	}

	s.key(c.PublicKey)
	s.signature(c.SignatureAlgorithm)

	if c.BasicConstraintsValid {
		ca := c.IsCA
		s.CA = &ca

		if ca && (c.MaxPathLen > 0 || c.MaxPathLenZero) {
			n := c.MaxPathLen
			s.PathLen = &n
		}
	}

	for u := c.KeyUsage; u != 0; u &= u - 1 {
		s.KeyUsage = append(s.KeyUsage, (x509.KeyUsage(1) << bits.TrailingZeros(uint(u))).String())
	}

	for _, u := range c.ExtKeyUsage {
		s.ExtKeyUsage = append(s.ExtKeyUsage, u.String())
	}

	for _, u := range c.UnknownExtKeyUsage {
		s.ExtKeyUsage = append(s.ExtKeyUsage, u.String())
	}

	s.sans(c.DNSNames, c.IPAddresses, c.EmailAddresses, c.URIs)
	s.SKI, s.AKI, s.CRLURLs = colonHex(c.SubjectKeyId), colonHex(c.AuthorityKeyId), c.CRLDistributionPoints

	for _, e := range c.Extensions {
		if !knownExtension(e.Id) {
			crit := ""
			if e.Critical {
				crit = " (critical)"
			}

			s.Other = append(s.Other, e.Id.String()+crit)
		}
	}
}

// knownExtensions are the extensions show prints by name.
var knownExtensions = []asn1.ObjectIdentifier{
	{2, 5, 29, 14}, // subject key identifier
	{2, 5, 29, 15}, // key usage
	{2, 5, 29, 17}, // subject alternative name
	{2, 5, 29, 19}, // basic constraints
	{2, 5, 29, 31}, // CRL distribution points
	{2, 5, 29, 35}, // authority key identifier
	{2, 5, 29, 37}, // extended key usage
}

func knownExtension(id asn1.ObjectIdentifier) bool {
	for _, k := range knownExtensions {
		if id.Equal(k) {
			return true
		}
	}

	return false
}

func (s *Shown) key(pub any) {
	info := Describe(pub)
	s.Key = &info

	if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
		s.KeySHA256 = colonHex(SHA256.Sum(der))
	}
}

func (s *Shown) signature(a x509.SignatureAlgorithm) {
	s.Signature, s.SigClass = a.String(), SignatureClass(a)
}

func (s *Shown) sans(dns []string, ips []net.IP, email []string, uris []*url.URL) {
	s.DNS, s.Email = dns, email

	for _, ip := range ips {
		s.IP = append(s.IP, ip.String())
	}

	for _, u := range uris {
		s.URI = append(s.URI, u.String())
	}
}

// left is a duration as show prints what remains of a validity: days, else hours, else
// minutes.
func left(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	case d >= 2*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}

// Text writes s the way show prints it to a person.
func (s Shown) Text(w io.Writer) {
	fmt.Fprintf(w, "%s\n", titleCase(s.Kind))

	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "  %-15s %s\n", k, v)
		}
	}

	rows := func(k string, vs []string) {
		if len(vs) > 0 {
			row(k, strings.Join(vs, ", "))
		}
	}

	row("subject", s.Subject)
	row("issuer", s.Issuer)
	row("serial", s.Serial)

	if !s.From.IsZero() {
		row("valid", s.From.Format(time.DateTime)+" to "+s.Until.Format(time.DateTime)+" UTC")
	}

	if !s.ThisUpdate.IsZero() {
		row("this update", s.ThisUpdate.Format(time.DateTime)+" UTC")
		row("next update", s.NextUpdate.Format(time.DateTime)+" UTC")
	}

	row("crl number", s.Number)
	row("status", s.Status)

	if s.Key != nil {
		row("key", s.Key.Name+" ("+s.Key.Class+")")
		row("key sha256", s.KeySHA256)
	}

	if s.Signature != "" {
		row("signature", s.Signature+" ("+s.SigClass+")")
	}

	if s.CA != nil {
		ca := "no"

		if *s.CA {
			ca = "yes"
			if s.PathLen != nil {
				ca = fmt.Sprintf("yes, path length %d", *s.PathLen)
			}
		}

		row("ca", ca)
	}

	rows("key usage", s.KeyUsage)
	rows("ext key usage", s.ExtKeyUsage)
	rows("dns names", s.DNS)
	rows("ip addresses", s.IP)
	rows("emails", s.Email)
	rows("uris", s.URI)
	row("subject key id", s.SKI)
	row("authority key", s.AKI)
	rows("crl urls", s.CRLURLs)
	rows("other ext", s.Other)
	row("encryption", s.Encryption)

	if s.Revoked != nil || s.Kind == KindCRL.Name() {
		row("revoked", fmt.Sprintf("%d", len(s.Revoked)))

		for _, r := range s.Revoked {
			fmt.Fprintf(w, "    %s  %s UTC  %s\n", r.Serial, r.At.Format(time.DateTime), r.Reason)
		}
	}

	row("sha256", s.SHA256)
}

func titleCase(s string) string {
	if s == "" {
		return s
	}

	return strings.ToUpper(s[:1]) + s[1:]
}
