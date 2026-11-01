package pki

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"fmt"
	"time"
)

// Purpose is what a certificate is checked for: the extended key usage its chain must allow.
type Purpose string

// The purposes.
const (
	PurposeServer Purpose = "server"
	PurposeClient Purpose = "client"
	PurposeAny    Purpose = "any"
)

// ParsePurpose reads a purpose's name.
func ParsePurpose(s string) (Purpose, error) {
	switch p := Purpose(s); p {
	case PurposeServer, PurposeClient, PurposeAny:
		return p, nil
	}

	return "", fmt.Errorf("%q is not a purpose: server, client or any", s)
}

func (p Purpose) usages() []x509.ExtKeyUsage {
	switch p {
	case PurposeServer:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case PurposeClient:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	return []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
}

// VerifyOptions are what a certificate is checked against.
type VerifyOptions struct {
	// Roots are the trust anchors; none is the system's.
	Roots []*x509.Certificate

	// Intermediates are certificates a chain may be built through, trusted for nothing.
	Intermediates []*x509.Certificate

	// CRLs are revocation lists the chain's certificates are checked against, each where it
	// is its issuer's.
	CRLs []*x509.RevocationList

	Purpose Purpose
	Name    string // a DNS name or an IP address the leaf must be valid for; empty checks none
	At      time.Time
}

// Link is one certificate of a verified chain.
type Link struct {
	Subject   string    `json:"subject"`
	Serial    string    `json:"serial"`
	Key       KeyInfo   `json:"key"`
	Signature string    `json:"signature"`
	SigClass  string    `json:"signatureClass"`
	NotAfter  time.Time `json:"notAfter"`
	Root      bool      `json:"root,omitempty"`
}

// RevocationCheck is what one certificate's issuer's list said of it.
type RevocationCheck struct {
	Subject string    `json:"subject"`
	Status  string    `json:"status"` // good, revoked, or not checked
	CRL     string    `json:"crl,omitempty"`
	Number  string    `json:"crlNumber,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	At      time.Time `json:"revokedAt,omitzero"`
}

// Result is a verification's answer.
type Result struct {
	Valid   bool   `json:"valid"`
	Problem string `json:"problem,omitempty"`

	Chain      []Link            `json:"chain,omitempty"`
	Revocation []RevocationCheck `json:"revocation,omitempty"`
	Notes      []string          `json:"notes,omitempty"`

	// Authentication is pqc when the leaf's key and every signature below the root are
	// ML-DSA: nothing in the chain a quantum computer could forge. One classical link
	// makes it classical.
	Authentication string `json:"authentication,omitempty"`

	Purpose Purpose   `json:"purpose"`
	Name    string    `json:"name,omitempty"`
	At      time.Time `json:"at"`
}

// Verify checks leaf against opts.
func Verify(leaf *x509.Certificate, opts VerifyOptions) Result {
	if opts.At.IsZero() {
		opts.At = time.Now()
	}

	if opts.Purpose == "" {
		opts.Purpose = PurposeAny
	}

	r := Result{Purpose: opts.Purpose, Name: opts.Name, At: opts.At.UTC().Truncate(time.Second)}

	vo := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		DNSName:       opts.Name,
		CurrentTime:   opts.At,
		KeyUsages:     opts.Purpose.usages(),
	}

	if len(opts.Roots) > 0 {
		vo.Roots = x509.NewCertPool()
		for _, c := range opts.Roots {
			vo.Roots.AddCert(c)
		}
	}

	for _, c := range opts.Intermediates {
		vo.Intermediates.AddCert(c)
	}

	chains, err := leaf.Verify(vo)
	if err != nil {
		r.Problem = err.Error()

		return r
	}

	chain := chains[0]

	for i, c := range chain {
		r.Chain = append(r.Chain, Link{
			Subject:   c.Subject.String(),
			Serial:    FormatSerial(c.SerialNumber),
			Key:       Describe(c.PublicKey),
			Signature: c.SignatureAlgorithm.String(),
			SigClass:  SignatureClass(c.SignatureAlgorithm),
			NotAfter:  c.NotAfter.UTC(),
			Root:      i == len(chain)-1,
		})
	}

	r.Authentication = ChainClass(chain)
	r.Valid = true

	r.checkRevocation(chain, opts)

	return r
}

// ChainClass is pqc when the leaf's key and every signature but the root's on itself are
// ML-DSA: a chain leaf first, its root (or its last certificate) last.
func ChainClass(chain []*x509.Certificate) string {
	if len(chain) == 0 {
		return ClassClassical
	}

	if _, ok := chain[0].PublicKey.(*mldsa.PublicKey); !ok {
		return ClassClassical
	}

	for _, c := range chain[:len(chain)-1] {
		if SignatureClass(c.SignatureAlgorithm) != ClassPQC {
			return ClassClassical
		}
	}

	return ClassPQC
}

// checkRevocation checks each certificate below the root against its issuer's list, where
// one was given, and fails the result for a revoked certificate or a list out of date.
func (r *Result) checkRevocation(chain []*x509.Certificate, opts VerifyOptions) {
	if len(opts.CRLs) == 0 {
		return
	}

	used := make([]bool, len(opts.CRLs))

	for i, c := range chain[:len(chain)-1] {
		issuer := chain[i+1]
		check := RevocationCheck{Subject: c.Subject.String(), Status: "not checked"}

		for j, l := range opts.CRLs {
			if !bytes.Equal(l.RawIssuer, issuer.RawSubject) || l.CheckSignatureFrom(issuer) != nil {
				continue
			}

			used[j] = true
			check.CRL, check.Status = l.Issuer.String(), "good"

			if l.Number != nil {
				check.Number = l.Number.String()
			}

			if opts.At.Before(l.ThisUpdate) || (!l.NextUpdate.IsZero() && opts.At.After(l.NextUpdate)) {
				r.fail(fmt.Sprintf("the revocation list from %s is valid from %s to %s, not at %s",
					l.Issuer, l.ThisUpdate.UTC().Format(time.DateTime), l.NextUpdate.UTC().Format(time.DateTime),
					opts.At.UTC().Format(time.DateTime)))
			}

			for _, e := range l.RevokedCertificateEntries {
				if e.SerialNumber.Cmp(c.SerialNumber) == 0 {
					check.Status, check.Reason, check.At = "revoked", ReasonName(e.ReasonCode), e.RevocationTime.UTC()
					r.fail(fmt.Sprintf("%s is revoked (%s, %s)", c.Subject, check.Reason, check.At.Format(time.DateTime)))
				}
			}

			break
		}

		r.Revocation = append(r.Revocation, check)
	}

	for j, u := range used {
		if !u {
			r.Notes = append(r.Notes, fmt.Sprintf("the revocation list from %s was issued by no certificate in the chain, "+
				"or its signature does not verify, and was not used", opts.CRLs[j].Issuer))
		}
	}
}

func (r *Result) fail(problem string) {
	if r.Valid {
		r.Valid, r.Problem = false, problem
	}
}
