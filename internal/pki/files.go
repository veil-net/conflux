package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/veil-net/conflux/internal/paths"
)

// Kind is what a PEM block or a DER encoding holds.
type Kind string

// The kinds read and written, named by their PEM labels (RFC 7468).
const (
	KindCertificate  Kind = "CERTIFICATE"
	KindRequest      Kind = "CERTIFICATE REQUEST"
	KindCRL          Kind = "X509 CRL"
	KindPrivateKey   Kind = "PRIVATE KEY"
	KindEncryptedKey Kind = "ENCRYPTED PRIVATE KEY"
	KindPublicKey    Kind = "PUBLIC KEY"
)

// Name is the kind as a person reads it, and as JSON names it.
func (k Kind) Name() string {
	switch k {
	case KindRequest:
		return "certificate request"
	case KindCRL:
		return "revocation list"
	}

	return strings.ToLower(string(k))
}

// Object is one thing a file holds, as DER.
type Object struct {
	Kind Kind
	DER  []byte
}

// PEM is the object PEM-encoded.
func (o Object) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: string(o.Kind), Bytes: o.DER})
}

// Secret reports whether the object is a private key in the clear.
func (o Object) Secret() bool { return o.Kind == KindPrivateKey }

// maxInput bounds what is read: no certificate, list or key comes near it, and a mistaken
// path to a disk image does not fill memory.
const maxInput = 16 << 20

// ReadFile reads every object path holds, PEM or DER; - is stdin.
func ReadFile(path string) ([]Object, error) {
	var (
		b   []byte
		err error
	)

	if path == "-" {
		b, err = io.ReadAll(io.LimitReader(os.Stdin, maxInput+1))
	} else {
		var f *os.File
		if f, err = os.Open(path); err == nil {
			b, err = io.ReadAll(io.LimitReader(f, maxInput+1))
			f.Close()
		}
	}

	if err != nil {
		return nil, err
	}

	if len(b) > maxInput {
		return nil, fmt.Errorf("%s is larger than %d MiB, which no certificate, request, list or key is", path, maxInput>>20)
	}

	objs, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name(path), err)
	}

	return objs, nil
}

func name(path string) string {
	if path == "-" {
		return "stdin"
	}

	return path
}

// legacyKeys are the PEM labels of keys in the forms before PKCS#8, read as the key they hold.
var legacyKeys = map[string]func([]byte) (any, error){
	"EC PRIVATE KEY":  func(b []byte) (any, error) { return x509.ParseECPrivateKey(b) },
	"RSA PRIVATE KEY": func(b []byte) (any, error) { return x509.ParsePKCS1PrivateKey(b) },
}

// Parse reads every object in b: each PEM block in it, or b as one DER encoding.
func Parse(b []byte) ([]Object, error) {
	if !bytes.Contains(b, []byte("-----BEGIN ")) {
		o, err := sniff(b)
		if err != nil {
			return nil, err
		}

		return []Object{o}, nil
	}

	var out []Object

	for rest := b; ; {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		o, err := fromPEM(block)
		if err != nil {
			return nil, err
		}

		out = append(out, o)
	}

	if len(out) == 0 {
		return nil, errors.New("holds no PEM block that decodes")
	}

	return out, nil
}

func fromPEM(block *pem.Block) (Object, error) {
	if _, legacy := block.Headers["DEK-Info"]; legacy {
		return Object{}, fmt.Errorf("this %s is encrypted the way OpenSSL's legacy PEM is, with a key MD5 derives, "+
			"which FIPS 140-3 does not approve. To re-encrypt it with OpenSSL:\n  %s", block.Type, reencrypt)
	}

	switch k := Kind(block.Type); k {
	case KindCertificate, KindRequest, KindCRL, KindPrivateKey, KindEncryptedKey, KindPublicKey:
		return Object{k, block.Bytes}, nil
	case "NEW CERTIFICATE REQUEST":
		return Object{KindRequest, block.Bytes}, nil
	}

	if parse, ok := legacyKeys[block.Type]; ok {
		k, err := parse(block.Bytes)
		if err != nil {
			return Object{}, fmt.Errorf("this %s does not parse: %w", block.Type, err)
		}

		p8, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return Object{}, err
		}

		return Object{KindPrivateKey, p8}, nil
	}

	return Object{}, fmt.Errorf("a %q PEM block is nothing this reads", block.Type)
}

// sniff is what one DER encoding holds, told apart by its shape.
func sniff(der []byte) (Object, error) {
	if _, err := x509.ParseCertificate(der); err == nil {
		return Object{KindCertificate, der}, nil
	}

	if _, err := x509.ParseCertificateRequest(der); err == nil {
		return Object{KindRequest, der}, nil
	}

	if _, err := x509.ParseRevocationList(der); err == nil {
		return Object{KindCRL, der}, nil
	}

	// A PKCS#12 bundle begins with an INTEGER too, so it is told apart first.
	if IsPKCS12(der) {
		return Object{}, errors.New("is a PKCS#12 bundle: conflux cert p12 import takes it apart")
	}

	// SEQUENCE { INTEGER, ... } is PKCS#8; SEQUENCE { SEQUENCE, OCTET STRING } an encrypted
	// key; SEQUENCE { SEQUENCE, BIT STRING } a public key.
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &seq); err == nil && len(rest) == 0 && seq.Tag == asn1.TagSequence {
		var first, second asn1.RawValue

		if rest, err := asn1.Unmarshal(seq.Bytes, &first); err == nil {
			_, err = asn1.Unmarshal(rest, &second)

			switch {
			case err != nil:
			case first.Tag == asn1.TagInteger:
				return Object{KindPrivateKey, der}, nil
			case first.Tag == asn1.TagSequence && second.Tag == asn1.TagOctetString:
				return Object{KindEncryptedKey, der}, nil
			case first.Tag == asn1.TagSequence && second.Tag == asn1.TagBitString:
				return Object{KindPublicKey, der}, nil
			}
		}
	}

	return Object{}, errors.New("is neither PEM nor the DER of a certificate, request, revocation list or key")
}

// Write puts objects at path, PEM unless der, replacing what is there; - is stdout. A
// private key in the clear is written 0600, never to a terminal, and never over a file that
// is already there unless force says so: a key overwritten is a key lost.
func Write(path string, objs []Object, der, force bool) error {
	var (
		data   []byte
		secret bool
	)

	if der && len(objs) != 1 {
		return fmt.Errorf("DER holds one object, and this is %d: write PEM, or one at a time", len(objs))
	}

	for _, o := range objs {
		secret = secret || o.Secret()

		if der {
			data = o.DER
		} else {
			data = append(data, o.PEM()...)
		}
	}

	isKey := secret || (len(objs) > 0 && objs[0].Kind == KindEncryptedKey)

	if path == "-" {
		if secret && StdoutIsTerminal() {
			return errors.New("refusing to print a private key in the clear to a terminal: name a file with --out, " +
				"or encrypt it")
		}

		_, err := Stdout.Write(data)

		return err
	}

	perm := fs.FileMode(0o644)
	if secret {
		perm = 0o600
	}

	err := WriteFile(path, data, perm, isKey && !force)
	if errors.Is(err, ErrExists) {
		return fmt.Errorf("%s is already there, and a key overwritten is lost; --force replaces it", path)
	}

	return err
}

// ErrExists is a name WriteFile was asked to keep that is already taken.
var ErrExists = errors.New("already there")

// WriteFile writes path atomically, at perm from before the first byte, and when keep, only
// where nothing is yet: a name already taken is ErrExists, and is left as it was.
func WriteFile(path string, data []byte, perm fs.FileMode, keep bool) (err error) {
	if keep {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s: %w", path, ErrExists)
		}
	}

	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}

	tmpName := tmp.Name()

	defer func() {
		if tmp != nil {
			tmp.Close()
		}

		os.Remove(tmpName)
	}()

	if err := tmp.Chmod(perm); err != nil {
		return err
	}

	// On Windows the mode is nothing, and the file is its writer's alone by its DACL: whoever
	// runs conflux cert, not the machine's administrators alone, as conflux's own files are.
	if perm&0o077 == 0 {
		if err := paths.RestrictToOwner(tmpName, false); err != nil {
			return err
		}
	}

	if _, err := tmp.Write(data); err != nil {
		return err
	}

	if err := tmp.Sync(); err != nil {
		return err
	}

	err = tmp.Close()
	tmp = nil

	if err != nil {
		return err
	}

	defer syncDir(dir)

	if !keep {
		return os.Rename(tmpName, path)
	}

	// A link refuses a name already taken, where a rename would replace it, so a key
	// written between the check above and here is not lost either. A filesystem without
	// links falls back to the rename, the check above its guard.
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s: %w", path, ErrExists)
		}

		return os.Rename(tmpName, path)
	}

	return nil
}

// syncDir makes the new name durable, as far as the platform lets it: best effort, since the
// file is already in place.
func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		_ = f.Sync()
		f.Close()
	}
}

// Stdout is where - writes; the command line points it where its own output goes.
var Stdout io.Writer = os.Stdout

// StdoutIsTerminal reports whether stdout is a terminal. The command line sets it to ui's,
// which asks the line discipline; this default takes any character device for one.
var StdoutIsTerminal = func() bool {
	st, err := os.Stdout.Stat()

	return err == nil && st.Mode()&fs.ModeCharDevice != 0
}
