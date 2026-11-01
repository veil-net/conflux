package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
