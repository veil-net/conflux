package tlsprobe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// ServeOptions are what a server answers with.
type ServeOptions struct {
	Listener net.Listener
	Cert     tls.Certificate

	// ClientCAs, when set, are the roots a client's certificate must verify against; every
	// client must present one.
	ClientCAs []*x509.Certificate

	Groups []tls.CurveID
	ALPN   []string // advertised; none advertises http/1.1, so curl and browsers are answered

	// Once stops the server after its first handshake, completed or not.
	Once bool
}

// Seen is one client: what it offered and what was negotiated.
type Seen struct {
	Remote string    `json:"remote"`
	At     time.Time `json:"at"`

	Offered struct {
		ServerName string   `json:"serverName,omitempty"`
		Versions   []string `json:"versions"`
		Groups     []string `json:"groups"`
		Signatures []string `json:"signatures"`
		Ciphers    []string `json:"ciphers"`
		ALPN       []string `json:"alpn,omitempty"`
	} `json:"offered"`

	Version    string `json:"version,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	Group      string `json:"group,omitempty"`
	GroupClass string `json:"groupClass,omitempty"`
	ALPN       string `json:"alpn,omitempty"`

	// Signature is this server's handshake signature, inferred from its key as Signature says.
	Signature string `json:"signature,omitempty"`

	Client string `json:"client,omitempty"` // the client certificate's subject, verified

	Error string `json:"error,omitempty"`
}

// Text is s as serve prints it.
func (s Seen) Text() string {
	var b strings.Builder

	fmt.Fprintf(&b, "%s  %s\n", s.At.UTC().Format(time.DateTime), s.Remote)

	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "  %-15s %s\n", k, v)
		}
	}

	row("sni", s.Offered.ServerName)
	row("offered tls", strings.Join(s.Offered.Versions, ", "))
	row("offered groups", strings.Join(s.Offered.Groups, ", "))
	row("offered sigs", strings.Join(s.Offered.Signatures, ", "))
	row("offered alpn", strings.Join(s.Offered.ALPN, ", "))

	if s.Error != "" {
		row("failed", s.Error)

		return b.String()
	}

	row("tls", s.Version)
	row("cipher", s.Cipher)
	row("group", s.Group+" ("+s.GroupClass+")")
	row("signature", s.Signature)
	row("alpn", s.ALPN)
	row("client", s.Client)

	return b.String()
}

// Serve answers TLS on opts.Listener until ctx ends (or, with Once, after one client),
// reporting each client to seen. A client that sends an HTTP request is answered with the
// report as text/plain, so curl and a browser see what was negotiated; any other is sent the
// report and closed.
func Serve(ctx context.Context, opts ServeOptions, seen func(Seen)) error {
	var (
		mu     sync.Mutex
		hellos = map[net.Conn]*tls.ClientHelloInfo{}
	)

	alpn := opts.ALPN
	if len(alpn) == 0 {
		alpn = []string{"http/1.1"}
	}

	cfg := &tls.Config{
		Certificates:     []tls.Certificate{opts.Cert},
		CurvePreferences: opts.Groups,
		NextProtos:       alpn,
		MinVersion:       tls.VersionTLS12,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			hellos[h.Conn] = h
			mu.Unlock()

			return nil, nil
		},
	}

	if len(opts.ClientCAs) > 0 {
		cfg.ClientAuth, cfg.ClientCAs = tls.RequireAndVerifyClientCert, x509.NewCertPool()
		for _, c := range opts.ClientCAs {
			cfg.ClientCAs.AddCert(c)
		}
	}

	leaf := opts.Cert.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(opts.Cert.Certificate[0]); err != nil {
			return err
		}
	}

	stop := context.AfterFunc(ctx, func() { opts.Listener.Close() })
	defer stop()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		raw, err := opts.Listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			return err
		}

		handle := func() {
			s := answer(ctx, raw, cfg, leaf, func() *tls.ClientHelloInfo {
				mu.Lock()
				defer mu.Unlock()

				h := hellos[raw]
				delete(hellos, raw)

				return h
			})

			seen(s)
		}

		if opts.Once {
			handle()

			return nil
		}

		wg.Add(1)

		go func() {
			defer wg.Done()
			handle()
		}()
	}
}

// answer completes one handshake and answers it.
func answer(ctx context.Context, raw net.Conn, cfg *tls.Config, leaf *x509.Certificate, hello func() *tls.ClientHelloInfo) Seen {
	defer raw.Close()

	s := Seen{Remote: raw.RemoteAddr().String(), At: time.Now()}

	conn := tls.Server(raw, cfg)

	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err := conn.HandshakeContext(hctx)

	if h := hello(); h != nil {
		s.Offered.ServerName = h.ServerName
		s.Offered.ALPN = h.SupportedProtos

		for _, v := range h.SupportedVersions {
			s.Offered.Versions = append(s.Offered.Versions, tls.VersionName(v))
		}

		for _, g := range h.SupportedCurves {
			s.Offered.Groups = append(s.Offered.Groups, GroupName(g))
		}

		for _, sig := range h.SignatureSchemes {
			s.Offered.Signatures = append(s.Offered.Signatures, SignatureSchemeName(sig))
		}

		for _, c := range h.CipherSuites {
			s.Offered.Ciphers = append(s.Offered.Ciphers, tls.CipherSuiteName(c))
		}
	}

	if err != nil {
		s.Error = explain(err).Error()

		return s
	}

	st := conn.ConnectionState()
	sig, _ := Signature(st.Version, leaf)

	s.Version, s.Cipher, s.ALPN, s.Signature = tls.VersionName(st.Version), tls.CipherSuiteName(st.CipherSuite), st.NegotiatedProtocol, sig
	s.Group, s.GroupClass = GroupName(st.CurveID), GroupClass(st.CurveID)

	if len(st.VerifiedChains) > 0 {
		s.Client = st.VerifiedChains[0][0].Subject.String()
	}

	reply(conn, s)

	return s
}

// reply sends s back: as an HTTP response to a client that sent a request, else as it is.
func reply(conn *tls.Conn, s Seen) {
	body := []byte("conflux cert serve\n\n" + s.Text())

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	first := make([]byte, 8)
	n, _ := io.ReadAtLeast(conn, first, 4)

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	for _, m := range []string{"GET ", "POST", "PUT ", "OPTI"} {
		if bytes.HasPrefix(first[:n], []byte(m)) {
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n"+
				"Connection: close\r\n\r\n", len(body))

			break
		}
	}

	_, _ = conn.Write(body)
	_ = conn.CloseWrite()
}
