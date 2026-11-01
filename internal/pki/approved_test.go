package pki

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Only cryptography the Go Cryptographic Module approves, used the way it approves, is in
// conflux's own code (docs/security.md, "FIPS 140-3 and CMVP").
//
// The tests run in fips140=only (the Makefile's FIPSTEST), which refuses most of what is not
// approved as it happens: GCM under a caller's nonce, a short PBKDF2 salt, SHA-1. Not all of
// it. A single AES block -- AES-ECB, which the Security Policy lists as non-approved -- runs
// without complaint, and so does anything outside the module altogether, golang.org/x/crypto
// above all, which the module never sees. So this reads every non-test Go file of the module
// for each of those. The control is that each rule finds the line it is about in a file
// written to break it, and none in a file allowed it.
func TestOnlyApprovedCryptographyIsUsed(t *testing.T) {
	root := filepath.Join("..", "..")
	seen := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "testdata") {
				return filepath.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		seen[filepath.ToSlash(rel)] = true

		for _, broken := range unapproved(src, filepath.ToSlash(rel)) {
			t.Errorf("%s: %s", rel, broken)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// A walk that read nothing would pass: it read the files it is about.
	for _, f := range []string{pbes2File, "main.go", "internal/cli/cert.go", "internal/update/update.go"} {
		if !seen[f] {
			t.Errorf("the scan did not read %s", f)
		}
	}

	for _, r := range rules {
		if got := unapproved([]byte("package x\n"+r.text+"\n"), "x/x.go"); len(got) != 1 || got[0] != r.why {
			t.Errorf("control: a file holding %s gave %q", r.text, got)
		}

		for _, allowed := range r.allowedIn {
			if got := unapproved([]byte("package x\n"+r.text+"\n"), allowed); len(got) != 0 {
				t.Errorf("control: %s, where %s is allowed, gave %q", allowed, r.text, got)
			}
		}
	}
}

// pbes2File is the one file that may build AES-CBC, for PBES2's key encryption.
const pbes2File = "internal/pki/pbes2.go"

// gcmWhy is why GCM under a caller's nonce is refused.
const gcmWhy = "builds AES-GCM under a caller's nonce, which is not approved; use cipher.NewGCMWithRandomNonce"

// rules are the strings no file may contain, and why, but for the files a rule names.
var rules = []struct {
	text, why string
	allowedIn []string
}{
	{`"golang.org/x/crypto/`, "imports golang.org/x/crypto, which is outside the Go Cryptographic Module", nil},
	{`"crypto/md5"`, "imports MD5, which FIPS 140-3 does not approve", nil},
	{`"crypto/sha1"`, "imports SHA-1; approved hashes are SHA-2 and SHA-3", nil},
	{`"crypto/des"`, "imports DES, which FIPS 140-3 does not approve", nil},
	{`"crypto/rc4"`, "imports RC4, which FIPS 140-3 does not approve", nil},
	{`"crypto/dsa"`, "imports DSA, which FIPS 186-5 withdrew", nil},
	{`"crypto/ecdh"`, "imports crypto/ecdh, whose X25519 is not approved; key agreement is TLS's hybrids'", nil},
	{`cipher.NewCTR(`, "builds AES-CTR of its own", nil},
	{`cipher.NewCBC`, "builds AES-CBC, which only PBES2 key encryption may, in " + pbes2File, []string{pbes2File}},
	{`cipher.NewCFB`, "builds AES-CFB, which FIPS 140-3 does not approve", nil},
	{`cipher.NewOFB(`, "builds AES-OFB, which FIPS 140-3 does not approve", nil},
	{`cipher.NewGCM(`, gcmWhy, nil},
	{`cipher.NewGCMWithNonceSize(`, gcmWhy, nil},
	{`cipher.NewGCMWithTagSize(`, gcmWhy, nil},
	{`aes.NewCipher(`, "uses an AES block outside PBES2; one block alone is AES-ECB, which is not approved", []string{pbes2File}},
	{`ed25519.Options`, "uses Ed25519ctx or Ed25519ph; conflux signs with pure Ed25519", nil},
	{`rsa.EncryptPKCS1v15`, "encrypts with RSA PKCS #1 v1.5, which FIPS 140-3 no longer approves", nil},
	{`rsa.DecryptPKCS1v15`, "decrypts RSA PKCS #1 v1.5, which FIPS 140-3 no longer approves", nil},
	{`x509.EncryptPEMBlock`, "encrypts legacy PEM, under a key MD5 derives", nil},
	{`x509.DecryptPEMBlock`, "decrypts legacy PEM, under a key MD5 derives", nil},
	{`fips140.WithoutEnforcement`, "switches the module's enforcement off", nil},
}

// unapproved is what src, the file at rel (slash-separated, from the repository's root), does
// that is not approved.
func unapproved(src []byte, rel string) []string {
	var out []string

	for _, r := range rules {
		if !slices.Contains(r.allowedIn, rel) && bytes.Contains(src, []byte(r.text)) {
			out = append(out, r.why)
		}
	}

	return out
}
