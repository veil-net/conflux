package cli

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/veil-net/conflux/internal/pki"
	"github.com/veil-net/conflux/internal/ui"
)

// cert p12: PKCS#12 bundles, in the one profile FIPS 140-3 approves throughout. See
// internal/pki/pkcs12.go.

func runCertP12(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		ui.Printf("conflux cert p12 — PKCS#12 bundles, PBES2 and PBMAC1 throughout\n\n" +
			"  export   bundle a key, its certificate and its chain\n" +
			"  import   take a bundle apart into a key, its certificate and its chain\n\n" +
			"conflux cert p12 COMMAND -h says more of each; docs/cert.md, \"PKCS#12\", has which readers open them.\n")

		if len(args) == 0 {
			return ExitUsage
		}

		return ExitOK
	}

	switch args[0] {
	case "export":
		return runP12Export(ctx, args[1:])
	case "import":
		return runP12Import(ctx, args[1:])
	}

	ui.Errf("%q is not a cert p12 command: export or import", args[0])

	return ExitUsage
}

func registerP12Pass(fs *flag.FlagSet, what string) passFlags {
	return passFlags{
		file:   fs.String("p12-passphrase-file", "", "read the bundle's passphrase, "+what+", from the first line of this file"),
		env:    fs.String("p12-passphrase-env", "", "read the bundle's passphrase, "+what+", from this environment variable"),
		prefix: "p12-",
		what:   what,
	}
}

func runP12Export(ctx context.Context, args []string) int {
	fs := certFlagsNamed("p12 export", "bundle a key, its certificate and its chain",
		"p12 export (--key KEY --cert CERT [--chain CHAIN] | --in PEM) --out FILE [--name NAME]")
	keyPath := fs.String("key", "", "the private key")
	certPath := fs.String("cert", "", "its certificate, and after it in the file, its chain")
	chainPath := fs.String("chain", "", "more of the chain, the issuer first")
	in := fs.String("in", "", "a PEM file holding the key and the certificates together, such as `openssl pkcs12 -nodes` writes; - is stdin")
	name := fs.String("name", "", "the friendly name an importer shows; the certificate's CN when empty")
	out := fs.String("out", "", "where to write the bundle")
	force := fs.Bool("force", false, "replace a bundle already at --out")
	pass := registerPass(fs, "", "to open --key")
	p12 := registerP12Pass(fs, "to protect it with")

	if _, code, ok := certParse(fs, args, none); !ok {
		return code
	}

	if err := required(fs, "out"); err != nil {
		return fail(err)
	}

	key, certs, err := exportInputs(ctx, *in, *keyPath, *certPath, *chainPath, pass)
	if err != nil {
		return fail(err)
	}

	// The key's certificate first, wherever it was.
	for i, c := range certs {
		if pki.SamePublicKey(c.PublicKey, key.Public()) {
			certs[0], certs[i] = certs[i], certs[0]

			break
		}
	}

	if *name == "" {
		*name = certs[0].Subject.CommonName
	}

	pw, err := p12.get(ctx, "Passphrase for the bundle: ", true)
	if err != nil {
		return fail(err)
	}

	der, err := pki.EncodePKCS12(key, certs, pw, *name)
	if err != nil {
		return fail(err)
	}

	if err := pki.WriteFile(*out, der, 0o600, !*force); err != nil {
		if errors.Is(err, pki.ErrExists) {
			return fail(fmt.Errorf("%s is already there; --force replaces it", *out))
		}

		return fail(err)
	}

	note("Wrote %s's key (%s) and %d certificate(s) to %s: PBES2 and PBMAC1, AES-256-CBC and HMAC-SHA-256.",
		certs[0].Subject, pki.Describe(key.Public()).Name, len(certs), *out)

	return ExitOK
}

// exportInputs is what export bundles: from --in, or from --key, --cert and --chain.
func exportInputs(ctx context.Context, in, keyPath, certPath, chainPath string, pass passFlags) (crypto.Signer, []*x509.Certificate, error) {
	switch {
	case in != "" && (keyPath != "" || certPath != "" || chainPath != ""):
		return nil, nil, errors.New("--in holds the key and certificates together; it takes no --key, --cert or --chain")
	case in == "" && (keyPath == "" || certPath == ""):
		return nil, nil, errors.New("conflux cert p12 export needs --key and --cert, or --in")
	}

	if in == "" {
		key, err := loadKey(ctx, keyPath, pass)
		if err != nil {
			return nil, nil, err
		}

		certs, err := loadCerts(certPath)
		if err != nil {
			return nil, nil, err
		}

		if chainPath != "" {
			more, err := loadCerts(chainPath)
			if err != nil {
				return nil, nil, err
			}

			certs = append(certs, more...)
		}

		return key, certs, nil
	}

	objs, err := pki.ReadFile(in)
	if err != nil {
		return nil, nil, err
	}

	var (
		key   crypto.Signer
		certs []*x509.Certificate
	)

	for _, o := range objs {
		switch o.Kind {
		case pki.KindPrivateKey, pki.KindEncryptedKey:
			if key != nil {
				return nil, nil, fmt.Errorf("%s holds more than one key, and a bundle holds one", in)
			}

			p8 := o.DER
			if o.Kind == pki.KindEncryptedKey {
				p, err := pass.get(ctx, "Passphrase for the key in "+in+": ", false)
				if err != nil {
					return nil, nil, err
				}

				if p8, err = pki.DecryptPrivateKey(o.DER, p); err != nil {
					return nil, nil, err
				}
			}

			if key, err = pki.ParsePrivateKey(p8); err != nil {
				return nil, nil, err
			}
		case pki.KindCertificate:
			c, err := x509.ParseCertificate(o.DER)
			if err != nil {
				return nil, nil, err
			}

			certs = append(certs, c)
		}
	}

	if key == nil || len(certs) == 0 {
		return nil, nil, fmt.Errorf("%s needs a private key and its certificate", in)
	}

	return key, certs, nil
}

func runP12Import(ctx context.Context, args []string) int {
	fs := certFlagsNamed("p12 import", "take a bundle apart into a key, its certificate and its chain",
		"p12 import BUNDLE --key-out KEY --cert-out CERT [--chain-out CHAIN] [--encrypt]")
	keyOut := fs.String("key-out", "", "where to write the private key")
	certOut := fs.String("cert-out", "", "where to write the key's certificate")
	chainOut := fs.String("chain-out", "", "where to write the rest of the chain; with none, it follows the certificate in --cert-out")
	encrypt := fs.Bool("encrypt", false, "write the key encrypted under the bundle's passphrase, rather than in the clear")
	force := fs.Bool("force", false, "replace a key already at --key-out")
	p12 := registerP12Pass(fs, "to open it")

	pos, code, ok := certParse(fs, args, func(n int) bool { return n == 1 })
	if !ok {
		return code
	}

	if err := required(fs, "key-out", "cert-out"); err != nil {
		return fail(err)
	}

	der, err := readAll(pos[0])
	if err != nil {
		return fail(err)
	}

	if !pki.IsPKCS12(der) {
		return fail(fmt.Errorf("%s is not a PKCS#12 bundle", pos[0]))
	}

	pw, err := p12.get(ctx, "Passphrase for "+pos[0]+": ", false)
	if err != nil {
		return fail(err)
	}

	key, certs, err := pki.DecodePKCS12(der, pw)
	if err != nil {
		return fail(fmt.Errorf("%s: %w", pos[0], err))
	}

	p8, err := pki.MarshalPrivateKey(key)
	if err != nil {
		return fail(err)
	}

	keyObj := pki.Object{Kind: pki.KindPrivateKey, DER: p8}

	if *encrypt {
		enc, err := pki.EncryptPrivateKey(p8, pw)
		if err != nil {
			return fail(err)
		}

		keyObj = pki.Object{Kind: pki.KindEncryptedKey, DER: enc}
	}

	if err := pki.Write(*keyOut, []pki.Object{keyObj}, false, *force); err != nil {
		return fail(err)
	}

	certObjs := []pki.Object{{Kind: pki.KindCertificate, DER: certs[0].Raw}}

	var chainObjs []pki.Object
	for _, c := range certs[1:] {
		chainObjs = append(chainObjs, pki.Object{Kind: pki.KindCertificate, DER: c.Raw})
	}

	if *chainOut == "" {
		certObjs = append(certObjs, chainObjs...)
	} else if len(chainObjs) > 0 {
		if err := pki.Write(*chainOut, chainObjs, false, false); err != nil {
			return fail(err)
		}
	}

	if err := pki.Write(*certOut, certObjs, false, false); err != nil {
		return fail(err)
	}

	how := "in the clear, readable by its owner alone"
	if *encrypt {
		how = "encrypted under the bundle's passphrase"
	}

	note("Wrote %s's %s key to %s, %s, and %d certificate(s).", certs[0].Subject, pki.Describe(key.Public()).Name,
		*keyOut, how, len(certs))

	return ExitOK
}

// readAll reads a whole file, - being stdin, up to 16 MiB: no bundle comes near it.
func readAll(path string) ([]byte, error) {
	r := io.Reader(os.Stdin)

	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}

		defer f.Close()

		r = f
	}

	b, err := io.ReadAll(io.LimitReader(r, 16<<20+1))
	if err == nil && len(b) > 16<<20 {
		return nil, fmt.Errorf("%s is larger than 16 MiB, which no bundle is", path)
	}

	return b, err
}
