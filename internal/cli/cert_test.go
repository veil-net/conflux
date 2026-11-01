package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/pki"
	"github.com/veil-net/conflux/internal/pki/tlsprobe"
	"github.com/veil-net/conflux/internal/ui"
)

// certIn runs conflux cert in dir, failing the test unless it exits want.
func certIn(t *testing.T, dir string, want int, args ...string) (stdout, stderr string) {
	t.Helper()

	t.Chdir(dir)

	stdout, stderr, code := capture(t, append([]string{"cert"}, args...)...)
	if code != want {
		t.Fatalf("conflux cert %s exited %d, want %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, want, stdout, stderr)
	}

	return stdout, stderr
}

// TestACertificateAuthorityEndToEnd: an encrypted ML-DSA-87 root, an ML-DSA-65 server under
// it, verified for its name, purpose and post-quantum chain; revoked, it fails with exit 3;
// a key matches its certificate and not another's.
func TestACertificateAuthorityEndToEnd(t *testing.T) {
	dir := t.TempDir()

	t.Setenv("ROOT_PASS", "the root's passphrase")

	certIn(t, dir, ExitOK, "genkey", "--encrypt", "--passphrase-env", "ROOT_PASS", "--out", "root.key")
	certIn(t, dir, ExitOK, "selfsign", "--key", "root.key", "--passphrase-env", "ROOT_PASS",
		"--subject", "CN=Test Root,O=Conflux", "--out", "root.pem")
	certIn(t, dir, ExitOK, "genkey", "--alg", "ml-dsa-65", "--out", "server.key")

	_, stderr := certIn(t, dir, ExitOK, "req", "--key", "server.key", "--subject", "CN=server.test", "--out", "server.csr")
	if !strings.Contains(stderr, "names server.test, its CN") {
		t.Errorf("a request with no --san did not say it took the CN: %s", stderr)
	}

	certIn(t, dir, ExitOK, "sign", "--csr", "server.csr", "--ca", "root.pem", "--ca-key", "root.key",
		"--passphrase-env", "ROOT_PASS", "--days", "30", "--out", "server.pem")

	out, _ := certIn(t, dir, ExitOK, "verify", "server.pem", "--ca", "root.pem", "--name", "server.test",
		"--purpose", "server", "--require-pq")
	if !strings.Contains(out, "Valid") || !strings.Contains(out, "authentication  pqc") {
		t.Errorf("verify said:\n%s", out)
	}

	certIn(t, dir, ExitCheckFailed, "verify", "server.pem", "--ca", "root.pem", "--name", "other.test")
	certIn(t, dir, ExitCheckFailed, "verify", "server.pem", "--ca", "root.pem", "--purpose", "client")
	certIn(t, dir, ExitOK, "match", "server.key", "server.pem")
	certIn(t, dir, ExitCheckFailed, "match", "root.key", "server.pem", "--passphrase-env", "ROOT_PASS")

	js, _ := certIn(t, dir, ExitOK, "show", "--json", "server.pem")

	var shown []struct {
		Serial string `json:"serial"`
		Key    struct{ Algorithm, Class string }
	}

	if err := json.Unmarshal([]byte(js), &shown); err != nil || len(shown) != 1 || shown[0].Key.Algorithm != "ML-DSA-65" {
		t.Fatalf("show --json: %v\n%s", err, js)
	}

	certIn(t, dir, ExitOK, "crl", "--ca", "root.pem", "--ca-key", "root.key", "--passphrase-env", "ROOT_PASS",
		"--revoke", shown[0].Serial+":keyCompromise", "--out", "root.crl")

	out, _ = certIn(t, dir, ExitCheckFailed, "verify", "server.pem", "--ca", "root.pem", "--crl", "root.crl")
	if !strings.Contains(out, "revoked (keyCompromise") {
		t.Errorf("a revoked certificate's verify said:\n%s", out)
	}

	certIn(t, dir, ExitOK, "crl", "--ca", "root.pem", "--ca-key", "root.key", "--passphrase-env", "ROOT_PASS",
		"--from", "root.crl", "--out", "root2.crl")

	out, _ = certIn(t, dir, ExitOK, "show", "root2.crl")
	if !strings.Contains(out, "revoked         1") {
		t.Errorf("--from did not carry the revocation:\n%s", out)
	}
}

// TestKeysAreKept: a key is never written over without --force, nor printed in the clear, and
// a passphrase is asked of nobody when there is no terminal -- it says where one comes from.
func TestKeysAreKept(t *testing.T) {
	dir := t.TempDir()

	certIn(t, dir, ExitOK, "genkey", "--alg", "ed25519", "--out", "k.pem")

	before, _ := os.ReadFile(filepath.Join(dir, "k.pem"))

	_, stderr := certIn(t, dir, ExitError, "genkey", "--alg", "ed25519", "--out", "k.pem")
	if !strings.Contains(stderr, "--force") {
		t.Errorf("a second genkey over the key said: %s", stderr)
	}

	if after, _ := os.ReadFile(filepath.Join(dir, "k.pem")); string(after) != string(before) {
		t.Error("the key was replaced")
	}

	certIn(t, dir, ExitOK, "genkey", "--alg", "ed25519", "--out", "k.pem", "--force")

	was := ui.OpenTerminal
	ui.OpenTerminal = func() (*os.File, error) { return nil, os.ErrNotExist }

	t.Cleanup(func() { ui.OpenTerminal = was })

	_, stderr = certIn(t, dir, ExitError, "genkey", "--encrypt", "--out", "e.pem")
	if !strings.Contains(stderr, "--passphrase-file or --passphrase-env") {
		t.Errorf("an encrypted genkey with no terminal said: %s", stderr)
	}

	if _, err := os.Stat(filepath.Join(dir, "e.pem")); !os.IsNotExist(err) {
		t.Errorf("a key was written with no passphrase to encrypt it: %v", err)
	}

	out, _ := certIn(t, dir, ExitOK, "convert", "k.pem", "--pubout", "-")
	if !strings.Contains(out, "BEGIN PUBLIC KEY") || strings.Contains(out, "PRIVATE") {
		t.Errorf("--pubout - wrote:\n%s", out)
	}
}

// TestConvertRoundTrips: a key encrypted and decrypted again is the same key, DER and PEM.
func TestConvertRoundTrips(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "pass"), []byte("convert passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	certIn(t, dir, ExitOK, "genkey", "--alg", "ecdsa-p384", "--out", "k.pem")
	certIn(t, dir, ExitOK, "convert", "k.pem", "--encrypt", "--new-passphrase-file", "pass", "--to", "der", "--out", "k.der")
	certIn(t, dir, ExitOK, "convert", "k.der", "--decrypt", "--passphrase-file", "pass", "--out", "k2.pem")
	certIn(t, dir, ExitOK, "match", "k.pem", "k2.pem")

	_, stderr := certIn(t, dir, ExitError, "convert", "k.der", "--decrypt", "--passphrase-file", "k.pem", "--out", "k3.pem")
	if !strings.Contains(stderr, "passphrase does not open") {
		t.Errorf("a wrong passphrase said: %s", stderr)
	}

	out, _ := certIn(t, dir, ExitOK, "fingerprint", "--spki", "k.pem", "k2.pem")
	lines := strings.Split(strings.TrimSpace(out), "\n")

	if len(lines) != 2 || strings.Fields(lines[0])[1] != strings.Fields(lines[1])[1] {
		t.Errorf("the two keys' fingerprints differ:\n%s", out)
	}
}

// TestCertRefusesUsageMistakes: an unknown command, a missing flag and a stray argument
// are usage errors; --path-len outside a CA is refused.
func TestCertRefusesUsageMistakes(t *testing.T) {
	dir := t.TempDir()

	certIn(t, dir, ExitUsage, "frobnicate")
	certIn(t, dir, ExitUsage)
	certIn(t, dir, ExitOK, "help")
	certIn(t, dir, ExitOK, "genkey", "-h")
	certIn(t, dir, ExitError, "genkey")
	certIn(t, dir, ExitUsage, "genkey", "--out", "k.pem", "stray")
	certIn(t, dir, ExitUsage, "verify")
	certIn(t, dir, ExitOK, "genkey", "--alg", "ed25519", "--out", "k.pem")

	_, stderr := certIn(t, dir, ExitError, "selfsign", "--key", "k.pem", "--subject", "CN=x", "--profile", "client", "--path-len", "1")
	if !strings.Contains(stderr, "--path-len") {
		t.Errorf("--path-len on a client said: %s", stderr)
	}

	if _, stderr := certIn(t, dir, ExitError, "fingerprint", "--alg", "sha1", "k.pem"); !strings.Contains(stderr, "FIPS 140-3") {
		t.Errorf("a SHA-1 fingerprint said: %s", stderr)
	}
}

// pqServer makes, in dir, an ML-DSA root and a server chain for server.test under it.
func pqServer(t *testing.T, dir string) {
	t.Helper()

	certIn(t, dir, ExitOK, "genkey", "--out", "root.key")
	certIn(t, dir, ExitOK, "selfsign", "--key", "root.key", "--subject", "CN=TLS Root", "--out", "root.pem")
	certIn(t, dir, ExitOK, "genkey", "--alg", "ml-dsa-65", "--out", "server.key")
	certIn(t, dir, ExitOK, "req", "--key", "server.key", "--subject", "CN=server.test", "--san", "server.test", "--out", "server.csr")
	certIn(t, dir, ExitOK, "sign", "--csr", "server.csr", "--ca", "root.pem", "--ca-key", "root.key", "--days", "5",
		"--bundle", "--out", "chain.pem")
}

// freeAddr is a loopback address nothing listens on, for a server told where to listen.
func freeAddr(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer l.Close()

	return l.Addr().String()
}

// TestServeAnswersAndReports: cert serve --once answers one FIPS 140-3 mode client over a
// hybrid group with its ML-DSA chain, reports what the client offered as JSON, and exits 0.
func TestServeAnswersAndReports(t *testing.T) {
	dir := t.TempDir()
	pqServer(t, dir)

	addr := freeAddr(t)

	var out, errBuf bytes.Buffer

	oldOut, oldErr := ui.Out, ui.Errw
	ui.Out, ui.Errw = &out, &errBuf

	t.Cleanup(func() { ui.Out, ui.Errw = oldOut, oldErr })

	code := make(chan int, 1)

	go func() {
		code <- runCertServe(t.Context(), []string{"--cert", filepath.Join(dir, "chain.pem"), "--key", filepath.Join(dir, "server.key"),
			"--listen", addr, "--once", "--json"})
	}()

	root, _ := loadCerts(filepath.Join(dir, "root.pem"))

	var (
		r   tlsprobe.Report
		err error
	)

	for range 50 {
		if r, err = tlsprobe.Probe(t.Context(), tlsprobe.Options{Address: addr, ServerName: "server.test", Roots: root}); err == nil {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	if err != nil {
		t.Fatal(err)
	}

	if c := <-code; c != ExitOK {
		t.Fatalf("serve exited %d: %s", c, errBuf.String())
	}

	if !r.Chain.Valid || r.Chain.Authentication != pki.ClassPQC || r.GroupClass != pki.ClassHybrid {
		t.Errorf("the probe found %+v", r)
	}

	var seen tlsprobe.Seen
	if err := json.Unmarshal(out.Bytes(), &seen); err != nil || seen.Version != "TLS 1.3" || seen.Signature != "ML-DSA-65" {
		t.Errorf("serve reported %s (%v)", out.String(), err)
	}
}

// TestProbeSaysWhatItFound: against a server of its chain, cert probe exits 0 and says the
// handshake is post-quantum both ways; trusting another root, it exits 3 saying why; with
// --require-pq-kex and classical groups, 3; with nothing listening, 1.
func TestProbeSaysWhatItFound(t *testing.T) {
	dir := t.TempDir()
	pqServer(t, dir)

	chain, _ := loadCerts(filepath.Join(dir, "chain.pem"))
	key, err := loadKey(t.Context(), filepath.Join(dir, "server.key"), passFlags{file: new(string), env: new(string)})
	if err != nil {
		t.Fatal(err)
	}

	cert := tls.Certificate{PrivateKey: key, Leaf: chain[0]}
	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})

	go func() {
		_ = tlsprobe.Serve(ctx, tlsprobe.ServeOptions{Listener: l, Cert: cert}, func(tlsprobe.Seen) {})
		close(done)
	}()

	t.Cleanup(func() { cancel(); <-done })

	addr := l.Addr().String()

	out, _ := certIn(t, dir, ExitOK, "probe", addr, "--name", "server.test", "--ca", "root.pem", "--require-pq")
	if !strings.Contains(out, "post-quantum    key exchange yes; authentication yes") {
		t.Errorf("probe said:\n%s", out)
	}

	certIn(t, dir, ExitOK, "genkey", "--out", "other.key")
	certIn(t, dir, ExitOK, "selfsign", "--key", "other.key", "--subject", "CN=Other", "--out", "other.pem")

	out, _ = certIn(t, dir, ExitCheckFailed, "probe", addr, "--name", "server.test", "--ca", "other.pem")
	if !strings.Contains(out, "not verified") {
		t.Errorf("probe against another root said:\n%s", out)
	}

	out, _ = certIn(t, dir, ExitCheckFailed, "probe", addr, "--name", "server.test", "--ca", "root.pem",
		"--groups", "classical", "--require-pq-kex")
	if !strings.Contains(out, "the key exchange is classical") {
		t.Errorf("probe --require-pq-kex over classical groups said:\n%s", out)
	}

	certIn(t, dir, ExitError, "probe", freeAddr(t), "--timeout", "2s")
}

// TestAManagedCAEndToEnd: a CA with an ML-DSA-87 root and an ML-DSA-65 issuing CA issues a
// server certificate that a FIPS 140-3 mode client reaches over a hybrid group with
// authentication pqc throughout; revoked, verify against the CA's lists fails it with 3; an
// ECDSA leaf from the same CA is classical; list says all of it.
func TestAManagedCAEndToEnd(t *testing.T) {
	dir := t.TempDir()

	t.Setenv("CA_PASS", "the managed CA's passphrase")

	certIn(t, dir, ExitOK, "ca", "init", "ca", "--name", "E2E", "--intermediate", "--passphrase-env", "CA_PASS")

	for _, f := range []string{"ca/root.key", "ca/intermediate.key"} {
		if b, _ := os.ReadFile(filepath.Join(dir, f)); !strings.Contains(string(b), "ENCRYPTED PRIVATE KEY") {
			t.Errorf("%s is not encrypted", f)
		}
	}

	certIn(t, dir, ExitOK, "genkey", "--alg", "ml-dsa-65", "--out", "server.key")
	certIn(t, dir, ExitOK, "req", "--key", "server.key", "--subject", "CN=server.test", "--out", "server.csr")

	_, stderr := certIn(t, dir, ExitOK, "ca", "issue", "ca", "--csr", "server.csr", "--bundle", "--passphrase-env", "CA_PASS", "--out", "server.pem")
	if !strings.Contains(stderr, "recorded in ca") {
		t.Errorf("issue said: %s", stderr)
	}

	chain, _ := loadCerts(filepath.Join(dir, "server.pem"))
	if len(chain) != 2 || chain[1].Subject.CommonName != "E2E Issuing CA" {
		t.Fatalf("the bundle is %d certificates", len(chain))
	}

	key, err := loadKey(t.Context(), filepath.Join(dir, "server.key"), passFlags{file: new(string), env: new(string)})
	if err != nil {
		t.Fatal(err)
	}

	cert := tls.Certificate{PrivateKey: key, Leaf: chain[0], Certificate: [][]byte{chain[0].Raw, chain[1].Raw}}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})

	go func() {
		_ = tlsprobe.Serve(ctx, tlsprobe.ServeOptions{Listener: l, Cert: cert}, func(tlsprobe.Seen) {})
		close(done)
	}()

	t.Cleanup(func() { cancel(); <-done })

	js, _ := certIn(t, dir, ExitOK, "probe", l.Addr().String(), "--name", "server.test", "--ca", "ca/root.pem", "--groups", "pq", "--require-pq", "--json")

	var r tlsprobe.Report
	if err := json.Unmarshal([]byte(js), &r); err != nil || r.Version != "TLS 1.3" || r.GroupClass != pki.ClassHybrid ||
		r.Signature != "ML-DSA-65" || r.Chain.Authentication != pki.ClassPQC || len(r.Chain.Chain) != 3 {
		t.Errorf("probe found %+v (%v)", r, err)
	}

	certIn(t, dir, ExitOK, "verify", "server.pem", "--ca", "ca/root.pem", "--crl", "ca/crl.pem", "--crl", "ca/root.crl", "--require-pq")

	serial := pki.FormatSerial(chain[0].SerialNumber)
	certIn(t, dir, ExitOK, "ca", "revoke", "ca", serial, "--reason", "keyCompromise", "--passphrase-env", "CA_PASS")
	certIn(t, dir, ExitCheckFailed, "verify", "server.pem", "--ca", "ca/root.pem", "--crl", "ca/crl.pem", "--crl", "ca/root.crl")
	certIn(t, dir, ExitError, "ca", "revoke", "ca", serial, "--passphrase-env", "CA_PASS")

	certIn(t, dir, ExitOK, "genkey", "--alg", "ecdsa-p256", "--out", "ec.key")
	certIn(t, dir, ExitOK, "req", "--key", "ec.key", "--subject", "CN=ec.test", "--out", "ec.csr")
	certIn(t, dir, ExitOK, "ca", "issue", "ca", "--csr", "ec.csr", "--bundle", "--passphrase-env", "CA_PASS", "--out", "ec.pem")

	out, _ := certIn(t, dir, ExitOK, "verify", "ec.pem", "--ca", "ca/root.pem")
	if !strings.Contains(out, "authentication  classical") {
		t.Errorf("an ECDSA leaf's verify said:\n%s", out)
	}

	certIn(t, dir, ExitCheckFailed, "verify", "ec.pem", "--ca", "ca/root.pem", "--require-pq")
	certIn(t, dir, ExitOK, "ca", "crl", "ca", "--passphrase-env", "CA_PASS")

	js, _ = certIn(t, dir, ExitOK, "ca", "list", "ca", "--json")

	var list []struct{ Serial, Status, Reason, Subject string }
	if err := json.Unmarshal([]byte(js), &list); err != nil || len(list) != 2 {
		t.Fatalf("list: %v\n%s", err, js)
	}

	for _, e := range list {
		if (e.Subject == "CN=server.test") != (e.Status == "revoked" && e.Reason == "keyCompromise") {
			t.Errorf("list says %+v", e)
		}
	}

	certIn(t, dir, ExitError, "ca", "init", "ca", "--name", "Again", "--no-encrypt")
}
