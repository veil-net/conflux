package tlsprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/veil-net/conflux/internal/pki"
)

// Options are what a probe connects with.
type Options struct {
	Address    string // host:port
	ServerName string // the name sent and checked; the host's when empty

	// Roots are the trust anchors the server's chain is checked against; none is the
	// system's.
	Roots []*x509.Certificate

	Groups     []tls.CurveID // offered in this order; none is the module's default
	ALPN       []string
	Version    uint16 // only this version; 0 is 1.2 or 1.3
	ClientCert *tls.Certificate
	Timeout    time.Duration
}

// Report is what a probe found.
type Report struct {
	Address    string `json:"address"`
	Peer       string `json:"peer"`
	ServerName string `json:"serverName"`

	Version    string `json:"version"`
	Cipher     string `json:"cipher"`
	Group      string `json:"group"`
	GroupClass string `json:"groupClass"`
	ALPN       string `json:"alpn,omitempty"`

	Signature      string `json:"signature"`
	SignatureExact bool   `json:"signatureExact"`
	SignatureClass string `json:"signatureClass"`

	// Chain is the server's chain as checked: Valid, the chain built, and its
	// authentication class, pqc only when every link is ML-DSA.
	Chain pki.Result `json:"chain"`

	// Presented is the class of the chain the server sent, whether or not it verified.
	Presented string `json:"presentedClass"`

	// Leaf is the certificate the server sent first, whether or not its chain verified.
	Leaf Leaf `json:"leaf"`
}

// Leaf names a certificate and dates it, as it was sent: one that has expired, or that comes
// from a CA the probe was not given, is described all the same, so whoever reads the report
// can say when it runs out.
type Leaf struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}

// leafOf describes c as Leaf does.
func leafOf(c *x509.Certificate) Leaf {
	return Leaf{
		Subject:   c.Subject.String(),
		Issuer:    c.Issuer.String(),
		Serial:    pki.FormatSerial(c.SerialNumber),
		NotBefore: c.NotBefore.UTC(),
		NotAfter:  c.NotAfter.UTC(),
	}
}

// KeyExchangePQ reports whether the key exchange resists a quantum computer: ML-KEM, alone or
// beside a classical group.
func (r Report) KeyExchangePQ() bool { return r.GroupClass != pki.ClassClassical }

// AuthenticationPQ reports whether the server's authentication does: a verified chain that is
// ML-DSA throughout.
func (r Report) AuthenticationPQ() bool {
	return r.Chain.Valid && r.Chain.Authentication == pki.ClassPQC
}

// Probe connects to opts.Address, completes a handshake, and checks what the server sent.
// The chain is checked here rather than by crypto/tls, so a chain that does not verify is
// reported, not just refused; nothing is sent over the connection but the handshake.
func Probe(ctx context.Context, opts Options) (Report, error) {
	host, _, err := net.SplitHostPort(opts.Address)
	if err != nil {
		return Report{}, err
	}

	if opts.ServerName == "" {
		opts.ServerName = host
	}

	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	cfg := &tls.Config{
		ServerName:       opts.ServerName,
		CurvePreferences: opts.Groups,
		NextProtos:       opts.ALPN,
		MinVersion:       tls.VersionTLS12,

		// The chain is checked below, by pki.Verify, so that one which does not verify can be
		// described rather than only refused. Nothing but the handshake crosses this
		// connection, and its answer is no better than that check's.
		InsecureSkipVerify: true, //nolint:gosec // verified in Probe, as above
	}

	if opts.Version != 0 {
		cfg.MinVersion, cfg.MaxVersion = opts.Version, opts.Version
	}

	if opts.ClientCert != nil {
		cfg.Certificates = []tls.Certificate{*opts.ClientCert}
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	d := tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}

	conn, err := d.DialContext(ctx, "tcp", opts.Address)
	if err != nil {
		return Report{}, explain(err)
	}

	defer conn.Close()

	st := conn.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return Report{}, errors.New("the server sent no certificate")
	}

	leaf := st.PeerCertificates[0]
	sig, exact := Signature(st.Version, leaf)

	r := Report{
		Address:        opts.Address,
		Peer:           conn.RemoteAddr().String(),
		ServerName:     opts.ServerName,
		Version:        tls.VersionName(st.Version),
		Cipher:         tls.CipherSuiteName(st.CipherSuite),
		Group:          GroupName(st.CurveID),
		GroupClass:     GroupClass(st.CurveID),
		ALPN:           st.NegotiatedProtocol,
		Signature:      sig,
		SignatureExact: exact,
		SignatureClass: pki.SignatureClass(sigAlgOf(leaf)),
		Presented:      pki.ChainClass(st.PeerCertificates),
		Leaf:           leafOf(leaf),
	}

	r.Chain = pki.Verify(leaf, pki.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: st.PeerCertificates[1:],
		Purpose:       pki.PurposeServer,
		Name:          opts.ServerName,
	})

	return r, nil
}

// sigAlgOf is the certificate signature algorithm a key of leaf's kind signs with, for its
// class: a handshake signed with an ML-DSA key is ML-DSA's.
func sigAlgOf(leaf *x509.Certificate) x509.SignatureAlgorithm {
	alg, err := pki.SignatureAlgorithm(leaf.PublicKey, false)
	if err != nil {
		return x509.UnknownSignatureAlgorithm
	}

	return alg
}

// explain names what a FIPS 140-3 mode client most often fails on.
func explain(err error) error {
	var alert tls.AlertError
	if errors.As(err, &alert) && (alert == 40 || alert == 71) { // handshake_failure, insufficient_security
		return fmt.Errorf("%w: the server and a FIPS 140-3 mode client share no version, group, cipher or "+
			"signature; this offers TLS 1.2 and 1.3, AES-GCM, P-256/384/521 and ML-KEM, and ML-DSA, ECDSA, RSA and Ed25519", err)
	}

	return err
}
