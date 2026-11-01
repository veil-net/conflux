package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/pki"
	"github.com/veil-net/conflux/internal/pki/tlsprobe"
	"github.com/veil-net/conflux/internal/ui"
)

// cert probe and cert serve: a FIPS 140-3 mode TLS client and server that say what was
// negotiated, in the observer's words.

// tlsFlags are what probe and serve both take.
type tlsFlags struct {
	groups, alpn *string
	certPath     *string
	keyPath      *string
	pass         passFlags
}

func registerTLS(fs *flag.FlagSet, certWhat string) tlsFlags {
	return tlsFlags{
		groups:   fs.String("groups", "", "the key exchange groups to allow: pq (every ML-KEM group), classical, or names such as SecP384r1MLKEM1024,X25519MLKEM768; every group FIPS 140-3 mode allows when empty. crypto/tls orders them"),
		alpn:     fs.String("alpn", "", "application protocols to offer, comma-separated, such as h2,http/1.1"),
		certPath: fs.String("cert", "", certWhat+": the certificate, then its chain"),
		keyPath:  fs.String("key", "", "the private key of --cert"),
		pass:     registerPass(fs, "", "to open --key"),
	}
}

// keyPair is --cert and --key as one TLS certificate, the key checked to be the leaf's.
func (f tlsFlags) keyPair(ctx context.Context) (*tls.Certificate, error) {
	if *f.certPath == "" && *f.keyPath == "" {
		return nil, nil
	}

	if *f.certPath == "" || *f.keyPath == "" {
		return nil, errors.New("--cert and --key go together")
	}

	chain, err := loadCerts(*f.certPath)
	if err != nil {
		return nil, err
	}

	k, err := loadKey(ctx, *f.keyPath, f.pass)
	if err != nil {
		return nil, err
	}

	if !pki.SamePublicKey(chain[0].PublicKey, k.Public()) {
		return nil, fmt.Errorf("%s is not the key %s certifies", *f.keyPath, *f.certPath)
	}

	c := &tls.Certificate{PrivateKey: k, Leaf: chain[0]}
	for _, x := range chain {
		c.Certificate = append(c.Certificate, x.Raw)
	}

	return c, nil
}

func splitList(s string) []string {
	var out []string

	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}

	return out
}

func runCertProbe(ctx context.Context, args []string) int {
	fs := certFlags("probe")

	var cas repeated

	fs.Var(&cas, "ca", "a trusted root for the server's chain; repeat for more. None trusts the system's roots")
	name := fs.String("name", "", "the server name to send and check the chain for; the host's when empty")
	version := fs.String("tls", "", "only this TLS version: 1.2 or 1.3")
	timeout := fs.Duration("timeout", 10*time.Second, "how long the connection and handshake may take")
	requirePQ := fs.Bool("require-pq", false, "fail unless both the key exchange and the authentication are post-quantum")
	requireKex := fs.Bool("require-pq-kex", false, "fail unless the key exchange is ML-KEM, alone or in a hybrid")
	requireAuth := fs.Bool("require-pq-auth", false, "fail unless the server's chain verifies and is ML-DSA throughout")
	asJSON := fs.Bool("json", false, "answer in JSON")
	tf := registerTLS(fs, "a client certificate to present")

	pos, code, ok := certParse(fs, args, func(n int) bool { return n == 1 })
	if !ok {
		return code
	}

	opts := tlsprobe.Options{Address: hostPort(pos[0]), ServerName: *name, Timeout: *timeout, ALPN: splitList(*tf.alpn)}

	var err error

	if opts.Roots, err = loadAllCerts(cas); err != nil {
		return fail(err)
	}

	if opts.Groups, err = tlsprobe.ParseGroups(*tf.groups); err != nil {
		return fail(err)
	}

	if opts.Version, err = tlsprobe.ParseVersion(*version); err != nil {
		return fail(err)
	}

	if opts.ClientCert, err = tf.keyPair(ctx); err != nil {
		return fail(err)
	}

	r, err := tlsprobe.Probe(ctx, opts)
	if err != nil {
		return fail(fmt.Errorf("%s: %w", opts.Address, err))
	}

	var unmet []string

	if (*requirePQ || *requireKex) && !r.KeyExchangePQ() {
		unmet = append(unmet, "the key exchange is classical")
	}

	if (*requirePQ || *requireAuth) && !r.AuthenticationPQ() {
		unmet = append(unmet, "the authentication is not ML-DSA throughout a verified chain")
	}

	if *asJSON {
		out := struct {
			tlsprobe.Report
			Unmet []string `json:"unmet,omitempty"`
		}{r, unmet}

		if err := printJSON(out); err != nil {
			return fail(err)
		}
	} else {
		printProbe(r, len(opts.Roots) == 0, unmet)
	}

	if !r.Chain.Valid || len(unmet) > 0 {
		return ExitCheckFailed
	}

	return ExitOK
}

// hostPort is HOST[:PORT] with 443 where no port is given.
func hostPort(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}

	return net.JoinHostPort(strings.Trim(s, "[]"), "443")
}

func printProbe(r tlsprobe.Report, system bool, unmet []string) {
	ui.Printf("Connected to %s (%s), as %s\n", r.Address, r.Peer, r.ServerName)

	row := func(k, v string) { ui.Printf("  %-15s %s\n", k, v) }

	row("tls", r.Version+", "+r.Cipher)
	row("key exchange", r.Group+" ("+r.GroupClass+")")

	sig := r.Signature + " (" + r.SignatureClass + ")"
	if !r.SignatureExact {
		sig += ", from the leaf's key; the padding and hash are not reported"
	}

	row("signature", sig)

	if r.ALPN != "" {
		row("alpn", r.ALPN)
	}

	if r.Chain.Valid {
		row("chain", "verified for "+r.ServerName+", authentication "+r.Chain.Authentication)
	} else {
		row("chain", "not verified: "+r.Chain.Problem)
		row("", "the chain presented is "+r.Presented)
	}

	for i, l := range r.Chain.Chain {
		role := "leaf"

		switch {
		case l.Root && system:
			role = "system root"
		case l.Root:
			role = "root"
		case i > 0:
			role = "intermediate"
		}

		ui.Printf("    %-13s %s: %s key, signed %s\n", role, l.Subject, l.Key.Name, l.Signature)
	}

	yes := func(b bool) string {
		if b {
			return "yes"
		}

		return "no"
	}

	row("post-quantum", "key exchange "+yes(r.KeyExchangePQ())+"; authentication "+yes(r.AuthenticationPQ()))

	for _, u := range unmet {
		row("required", u)
	}
}

func runCertServe(ctx context.Context, args []string) int {
	fs := certFlags("serve")
	listen := fs.String("listen", "127.0.0.1:8443", "the address to listen on")

	var clientCAs repeated

	fs.Var(&clientCAs, "client-ca", "require every client to present a certificate that verifies against this root; repeat for more")
	once := fs.Bool("once", false, "stop after the first client")
	asJSON := fs.Bool("json", false, "report each client as a line of JSON")
	tf := registerTLS(fs, "the server's certificate")

	if _, code, ok := certParse(fs, args, none); !ok {
		return code
	}

	if err := required(fs, "cert", "key"); err != nil {
		return fail(err)
	}

	cert, err := tf.keyPair(ctx)
	if err != nil {
		return fail(err)
	}

	opts := tlsprobe.ServeOptions{Cert: *cert, Once: *once, ALPN: splitList(*tf.alpn)}

	if opts.Groups, err = tlsprobe.ParseGroups(*tf.groups); err != nil {
		return fail(err)
	}

	if opts.ClientCAs, err = loadAllCerts(clientCAs); err != nil {
		return fail(err)
	}

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return fail(err)
	}

	opts.Listener = l

	info := pki.Describe(cert.Leaf.PublicKey)
	note("Serving TLS on %s as %s, its key %s (%s). Ctrl-C stops it.", l.Addr(), cert.Leaf.Subject, info.Name, info.Class)

	failed := false

	err = tlsprobe.Serve(ctx, opts, func(s tlsprobe.Seen) {
		failed = failed || s.Error != ""

		if *asJSON {
			b, _ := json.Marshal(s)
			ui.Printf("%s\n", b)

			return
		}

		ui.Printf("%s\n", s.Text())
	})
	if err != nil {
		return fail(err)
	}

	if *once && failed {
		return ExitError
	}

	return ExitOK
}
