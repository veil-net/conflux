package cli

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/pki"
	"github.com/veil-net/conflux/internal/ui"
)

// conflux cert: keys, requests, certificates and revocation lists, made and checked with
// the Go Cryptographic Module in FIPS 140-3 mode, ML-DSA first. See docs/cert.md.

// certCommand is one of cert's subcommands.
type certCommand struct {
	run     func(ctx context.Context, args []string) int
	usage   string // its synopsis
	summary string
}

func certCommands() map[string]certCommand {
	return map[string]certCommand{
		"genkey":      {runCertGenkey, "genkey --out FILE [--alg ALG] [--encrypt] [--pubout FILE]", "make a private key"},
		"req":         {runCertReq, "req --key KEY --subject DN [--san NAME]... [--out FILE]", "make a certificate signing request"},
		"selfsign":    {runCertSelfsign, "selfsign --key KEY --subject DN [--profile ca] [--days N] [--out FILE]", "make a self-signed certificate: a root CA, or a lone server's"},
		"sign":        {runCertSign, "sign --csr REQ --ca CERT --ca-key KEY [--profile server] [--days N] [--out FILE]", "issue a certificate for a request"},
		"verify":      {runCertVerify, "verify CERT [--ca ROOT]... [--untrusted CERT]... [--crl CRL]... [--name HOST]", "check a certificate's chain, names, purpose and revocation"},
		"show":        {runCertShow, "show FILE... [--json]", "describe a certificate, request, revocation list or key"},
		"convert":     {runCertConvert, "convert IN --out FILE [--to pem|der] [--encrypt | --decrypt] [--pubout]", "re-encode, encrypt or decrypt"},
		"match":       {runCertMatch, "match A B", "check two files hold the same key: a key and its certificate, say"},
		"fingerprint": {runCertFingerprint, "fingerprint FILE... [--alg sha256] [--spki] [--json]", "a certificate's, request's, list's or key's digest"},
		"probe":       {runCertProbe, "probe HOST[:PORT] [--ca ROOT]... [--groups pq] [--require-pq] [--json]", "connect, and say what the server negotiates: TLS, group, signature, chain"},
		"serve":       {runCertServe, "serve --cert CHAIN --key KEY [--listen ADDR] [--client-ca ROOT]... [--once]", "answer TLS, and say what each client offers and gets"},
		"ca":          {runCertCA, "ca init|issue|revoke|list|crl DIR ...", "a certificate authority kept in a directory: what it issued, what it revoked, its CRLs"},
		"crl":         {runCertCRL, "crl --ca CERT --ca-key KEY [--revoke SERIAL[:REASON]]... [--from CRL] [--out FILE]", "make a revocation list"},
	}
}

// ExitCheckFailed is a check that ran and did not hold: a certificate that does not verify,
// two keys that do not match, a probe whose chain does not verify or that fell short of what
// it required.
const ExitCheckFailed = 3

func runCert(ctx context.Context, args []string) int {
	cmds := certCommands()

	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" || args[0] == "-help" {
		certUsage(cmds)

		if len(args) == 0 {
			return ExitUsage
		}

		return ExitOK
	}

	c, ok := cmds[args[0]]
	if !ok {
		ui.Errf("%q is not a cert command; conflux cert help lists them", args[0])

		return ExitUsage
	}

	// Before anything is read: every key, signature and digest here is the module's, and an
	// artifact made outside FIPS 140-3 mode would carry a claim that is not true of it.
	if err := pki.CheckFIPS(); err != nil {
		ui.Errf("%v", err)

		return ExitChildFailed
	}

	pki.Stdout = ui.Out
	pki.StdoutIsTerminal = func() bool {
		f, ok := ui.Out.(*os.File)

		return ok && ui.IsTerminalFile(f)
	}

	return c.run(ctx, args[1:])
}

func certUsage(cmds map[string]certCommand) {
	names := make([]string, 0, len(cmds))
	for n := range cmds {
		names = append(names, n)
	}

	sort.Strings(names)

	ui.Printf("conflux cert — keys, requests, certificates and revocation lists, post-quantum first\n\n")

	for _, n := range names {
		ui.Printf("  %-12s %s\n", n, cmds[n].summary)
	}

	ui.Printf("\nconflux cert COMMAND -h says more of each. Everything is made and checked with the Go\n" +
		"Cryptographic Module in FIPS 140-3 mode: ML-DSA-87 by default, and ECDSA, RSA and Ed25519\n" +
		"beside it. Exit 3 is a check that did not hold. docs/cert.md has the whole of it.\n")
}

// certFlags is a cert subcommand's flag set, its usage the synopsis and the flags.
func certFlags(name string) *flag.FlagSet {
	c := certCommands()[name]

	return certFlagsNamed(name, c.summary, c.usage)
}

// certFlagsNamed is a flag set for conflux cert NAME, its usage the synopsis and the flags.
func certFlagsNamed(name, summary, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet("cert "+name, flag.ContinueOnError)
	fs.SetOutput(ui.Errw)

	fs.Usage = func() {
		ui.Printf("conflux cert %s — %s\n\n  conflux cert %s\n\n", name, summary, usage)
		fs.SetOutput(ui.Out)
		fs.PrintDefaults()
		fs.SetOutput(ui.Errw)
	}

	return fs
}

// parseCert parses args, flags and arguments in any order -- `verify CERT --ca ROOT` as
// readily as `verify --ca ROOT CERT` -- and returns the arguments. A lone -- ends the flags.
func parseCert(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string

	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}

		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}

		if args[0] == "--" {
			return append(positional, args[1:]...), nil
		}

		positional = append(positional, args[0])
		args = args[1:]
	}
}

// certParse parses, and answers a usage error with its exit code: 2, or 0 for -h.
func certParse(fs *flag.FlagSet, args []string, want func(n int) bool) ([]string, int, bool) {
	pos, err := parseCert(fs, args)

	switch {
	case errors.Is(err, flag.ErrHelp):
		return nil, ExitOK, false
	case err != nil:
		return nil, ExitUsage, false
	case want != nil && !want(len(pos)):
		fs.Usage()

		return nil, ExitUsage, false
	}

	return pos, 0, true
}

func none(n int) bool { return n == 0 }

func atLeastOne(n int) bool { return n >= 1 }

// required refuses a flag left empty.
func required(fs *flag.FlagSet, names ...string) error {
	for _, n := range names {
		if fs.Lookup(n).Value.String() == "" {
			return fmt.Errorf("conflux cert %s needs --%s", strings.TrimPrefix(fs.Name(), "cert "), n)
		}
	}

	return nil
}

// note says what was done, on stderr: stdout may be what was written.
func note(format string, a ...any) { fmt.Fprintf(ui.Errw, format+"\n", a...) }

// passFlags are where a passphrase comes from: a file, an environment variable, or else the
// terminal. Never a flag's own value, which every process on the machine can read.
type passFlags struct {
	file, env    *string
	prefix, what string
}

func registerPass(fs *flag.FlagSet, prefix, what string) passFlags {
	return passFlags{
		file:   fs.String(prefix+"passphrase-file", "", "read the passphrase "+what+" from the first line of this file"),
		env:    fs.String(prefix+"passphrase-env", "", "read the passphrase "+what+" from this environment variable"),
		prefix: prefix,
		what:   what,
	}
}

// get is the passphrase, asked for at the terminal as prompt when neither flag gives one;
// confirm asks twice, for a passphrase about to protect something.
func (p passFlags) get(ctx context.Context, prompt string, confirm bool) ([]byte, error) {
	switch {
	case *p.file != "" && *p.env != "":
		return nil, errors.New("a passphrase comes from a file or an environment variable, not both")
	case *p.file != "":
		b, err := os.ReadFile(*p.file)
		if err != nil {
			return nil, err
		}

		line, _, _ := strings.Cut(string(b), "\n")
		if line = strings.TrimSuffix(line, "\r"); line == "" {
			return nil, fmt.Errorf("%s begins with an empty line, which is no passphrase", *p.file)
		}

		return []byte(line), nil
	case *p.env != "":
		v := os.Getenv(*p.env)
		if v == "" {
			return nil, fmt.Errorf("$%s is empty or unset, which is no passphrase", *p.env)
		}

		return []byte(v), nil
	}

	pass, err := ui.AskSecret(ctx, prompt)
	if errors.Is(err, ui.ErrNoTerminal) {
		return nil, fmt.Errorf("a passphrase is needed %s and there is no terminal to ask at: "+
			"give one with --%spassphrase-file or --%spassphrase-env", p.what, p.prefix, p.prefix)
	}

	if err != nil {
		return nil, err
	}

	if confirm {
		if len(pass) < pki.MinPassphrase {
			return nil, fmt.Errorf("a passphrase is %d characters or more", pki.MinPassphrase)
		}

		again, err := ui.AskSecret(ctx, "Again, to be sure: ")
		if err != nil {
			return nil, err
		}

		if string(again) != string(pass) {
			return nil, errors.New("the two passphrases differ")
		}
	}

	return pass, nil
}

// loadKey reads the private key at path, decrypting it with a passphrase from pass.
func loadKey(ctx context.Context, path string, pass passFlags) (crypto.Signer, error) {
	objs, err := pki.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for _, o := range objs {
		switch o.Kind {
		case pki.KindPrivateKey:
			return pki.ParsePrivateKey(o.DER)
		case pki.KindEncryptedKey:
			p, err := pass.get(ctx, "Passphrase for "+path+": ", false)
			if err != nil {
				return nil, err
			}

			p8, err := pki.DecryptPrivateKey(o.DER, p)
			if err != nil {
				return nil, err
			}

			return pki.ParsePrivateKey(p8)
		}
	}

	return nil, fmt.Errorf("%s holds no private key", path)
}

// loadCerts reads every certificate at path.
func loadCerts(path string) ([]*x509.Certificate, error) {
	objs, err := pki.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var out []*x509.Certificate

	for _, o := range objs {
		if o.Kind != pki.KindCertificate {
			continue
		}

		c, err := x509.ParseCertificate(o.DER)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}

		out = append(out, c)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("%s holds no certificate", path)
	}

	return out, nil
}

func loadAllCerts(paths []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate

	for _, p := range paths {
		cs, err := loadCerts(p)
		if err != nil {
			return nil, err
		}

		out = append(out, cs...)
	}

	return out, nil
}

// nameFlags are a certificate's or request's subject and alternative names.
type nameFlags struct {
	subject *string
	sans    repeated
}

func registerNames(fs *flag.FlagSet) *nameFlags {
	n := &nameFlags{subject: fs.String("subject", "", `the subject, as "CN=host.example,O=Example" or "/O=Example/CN=host.example"`)}
	fs.Var(&n.sans, "san", "a subject alternative name: DNS:NAME, IP:ADDRESS, EMAIL:ADDRESS or URI:URI, "+
		"or a bare one whose type its shape says; repeat for more")

	return n
}

// names reads the --san flags.
func (n *nameFlags) names() (pki.SANs, error) {
	var s pki.SANs

	for _, v := range n.sans {
		if err := s.AddSAN(v); err != nil {
			return s, err
		}
	}

	return s, nil
}

// parse reads the subject and the names.
func (n *nameFlags) parse() (pkix.Name, pki.SANs, error) {
	name, err := pki.ParseName(*n.subject)
	if err != nil {
		return name, pki.SANs{}, err
	}

	sans, err := n.names()

	return name, sans, err
}

// sansFromCN takes the CN as the one name where there is none and it is a host name or an
// address, as a TLS client would want it, and says so.
func sansFromCN(cn string, sans *pki.SANs) {
	if !sans.Empty() || cn == "" {
		return
	}

	if net.ParseIP(cn) != nil || strings.Contains(cn, ".") {
		if err := sans.AddSAN(cn); err == nil {
			note("No --san given: the certificate names %s, its CN, as its one subject alternative name.", cn)
		}
	}
}

// outFlags are where something is written, and how.
type outFlags struct {
	out   *string
	der   *bool
	force *bool
}

func registerOut(fs *flag.FlagSet, def string) outFlags {
	return outFlags{
		out:   fs.String("out", def, "where to write it; - is stdout"),
		der:   fs.Bool("der", false, "write DER rather than PEM"),
		force: fs.Bool("force", false, "replace a key already at --out, which is otherwise refused"),
	}
}

func (o outFlags) write(objs ...pki.Object) error {
	return pki.Write(*o.out, objs, *o.der, *o.force)
}

func (o outFlags) where() string {
	if *o.out == "-" {
		return "stdout"
	}

	return *o.out
}

func runCertGenkey(ctx context.Context, args []string) int {
	fs := certFlags("genkey")
	alg := fs.String("alg", string(pki.DefaultAlg), "the key's algorithm: "+algNames())
	encrypt := fs.Bool("encrypt", false, "encrypt the key under a passphrase (PBES2: PBKDF2-HMAC-SHA-256, AES-256-CBC)")
	pubout := fs.String("pubout", "", "also write the public key here")
	pass := registerPass(fs, "", "to encrypt with")
	out := registerOut(fs, "")

	if _, code, ok := certParse(fs, args, none); !ok {
		return code
	}

	if err := required(fs, "out"); err != nil {
		return fail(err)
	}

	a, err := pki.ParseAlg(*alg)
	if err != nil {
		return fail(err)
	}

	k, err := a.Generate()
	if err != nil {
		return fail(err)
	}

	p8, err := pki.MarshalPrivateKey(k)
	if err != nil {
		return fail(err)
	}

	obj := pki.Object{Kind: pki.KindPrivateKey, DER: p8}

	if *encrypt {
		p, err := pass.get(ctx, "Passphrase for the new key: ", true)
		if err != nil {
			return fail(err)
		}

		enc, err := pki.EncryptPrivateKey(p8, p)
		if err != nil {
			return fail(err)
		}

		obj = pki.Object{Kind: pki.KindEncryptedKey, DER: enc}
	}

	if err := out.write(obj); err != nil {
		return fail(err)
	}

	info := pki.Describe(k.Public())
	how := "in the clear, readable by its owner alone"

	if *encrypt {
		how = "encrypted"
	}

	note("Wrote a new %s key (%s) to %s, %s.", info.Name, info.Class, out.where(), how)

	if *pubout != "" {
		spki, err := pki.MarshalPublicKey(k.Public())
		if err != nil {
			return fail(err)
		}

		if err := pki.Write(*pubout, []pki.Object{{Kind: pki.KindPublicKey, DER: spki}}, *out.der, false); err != nil {
			return fail(err)
		}

		note("Wrote its public key to %s.", *pubout)
	}

	return ExitOK
}

func algNames() string {
	names := make([]string, len(pki.Algs))
	for i, a := range pki.Algs {
		names[i] = string(a)
	}

	return strings.Join(names, ", ")
}

func runCertReq(ctx context.Context, args []string) int {
	fs := certFlags("req")
	keyPath := fs.String("key", "", "the private key the request is for, and signed with")
	n := registerNames(fs)
	pss := fs.Bool("rsa-pss", false, "with an RSA key, sign with RSASSA-PSS rather than PKCS #1 v1.5")
	pass := registerPass(fs, "", "to open the key")
	out := registerOut(fs, "-")

	if _, code, ok := certParse(fs, args, none); !ok {
		return code
	}

	if err := required(fs, "key", "subject"); err != nil {
		return fail(err)
	}

	subject, sans, err := n.parse()
	if err != nil {
		return fail(err)
	}

	sansFromCN(pki.CommonName(subject), &sans)

	k, err := loadKey(ctx, *keyPath, pass)
	if err != nil {
		return fail(err)
	}

	der, err := pki.Request(subject, sans, k, *pss)
	if err != nil {
		return fail(err)
	}

	if err := out.write(pki.Object{Kind: pki.KindRequest, DER: der}); err != nil {
		return fail(err)
	}

	if *out.out != "-" {
		note("Wrote a request for %s to %s.", subject, out.where())
	}

	return ExitOK
}

// issueFlags are what selfsign and sign both take.
type issueFlags struct {
	profile *string
	days    *int
	pathLen *int
	crlURLs repeated
	pss     *bool
}

func registerIssue(fs *flag.FlagSet, profile string, days int) *issueFlags {
	f := &issueFlags{
		profile: fs.String("profile", profile, "what the certificate is for: server, client, server+client or ca"),
		days:    fs.Int("days", days, "how many days it is valid for"),
		pathLen: fs.Int("path-len", -1, "with --profile ca, how many CAs may be below it; -1 is no bound"),
		pss:     fs.Bool("rsa-pss", false, "with an RSA issuer, sign with RSASSA-PSS rather than PKCS #1 v1.5"),
	}

	fs.Var(&f.crlURLs, "crl-url", "where its issuer's revocation list is published; repeat for more")

	return f
}

func (f *issueFlags) template(fs *flag.FlagSet) (pki.Template, error) {
	p, err := pki.ParseProfile(*f.profile)
	if err != nil {
		return pki.Template{}, err
	}

	if p != pki.ProfileCA && typedFlags(fs)["path-len"] {
		return pki.Template{}, errors.New("--path-len bounds a CA's, and is for --profile ca")
	}

	return pki.Template{Profile: p, Days: *f.days, PathLen: *f.pathLen, CRLURLs: f.crlURLs, RSAPSS: *f.pss}, nil
}

func runCertSelfsign(ctx context.Context, args []string) int {
	fs := certFlags("selfsign")
	keyPath := fs.String("key", "", "the private key it certifies, and is signed with")
	n := registerNames(fs)
	f := registerIssue(fs, string(pki.ProfileCA), 3650)
	pass := registerPass(fs, "", "to open the key")
	out := registerOut(fs, "-")

	if _, code, ok := certParse(fs, args, none); !ok {
		return code
	}

	if err := required(fs, "key", "subject"); err != nil {
		return fail(err)
	}

	t, err := f.template(fs)
	if err != nil {
		return fail(err)
	}

	if t.Profile != pki.ProfileCA && !typedFlags(fs)["days"] {
		t.Days = 365
	}

	t.Subject, t.SANs, err = n.parse()
	if err != nil {
		return fail(err)
	}

	if t.Profile.NeedsName() {
		sansFromCN(pki.CommonName(t.Subject), &t.SANs)
	}

	k, err := loadKey(ctx, *keyPath, pass)
	if err != nil {
		return fail(err)
	}

	der, err := pki.Issue(t, k.Public(), nil, k, time.Now())
	if err != nil {
		return fail(err)
	}

	return wrote(out, der, nil)
}

// wrote writes a certificate, and the issuer's chain after it when given, and says so.
func wrote(out outFlags, der []byte, chain []*x509.Certificate) int {
	objs := []pki.Object{{Kind: pki.KindCertificate, DER: der}}
	for _, c := range chain {
		objs = append(objs, pki.Object{Kind: pki.KindCertificate, DER: c.Raw})
	}

	if err := out.write(objs...); err != nil {
		return fail(err)
	}

	if *out.out != "-" {
		c, _ := x509.ParseCertificate(der)
		note("Wrote %s's certificate, serial %s, valid until %s UTC, to %s.",
			c.Subject, pki.FormatSerial(c.SerialNumber), c.NotAfter.UTC().Format(time.DateTime), out.where())
	}

	return ExitOK
}

func runCertSign(ctx context.Context, args []string) int {
	fs := certFlags("sign")
	csrPath := fs.String("csr", "", "the request to issue a certificate for")
	caPath := fs.String("ca", "", "the issuer's certificate, the first in this file, the rest its chain")
	caKey := fs.String("ca-key", "", "the issuer's private key")
	n := registerNames(fs)
	f := registerIssue(fs, string(pki.ProfileServer), 365)
	bundle := fs.Bool("bundle", false, "write the issuer's certificates after the new one, the chain a server presents")
	pass := registerPass(fs, "", "to open the issuer's key")
	out := registerOut(fs, "-")

	if _, code, ok := certParse(fs, args, none); !ok {
		return code
	}

	if err := required(fs, "csr", "ca", "ca-key"); err != nil {
		return fail(err)
	}

	t, err := f.template(fs)
	if err != nil {
		return fail(err)
	}

	objs, err := pki.ReadFile(*csrPath)
	if err != nil {
		return fail(err)
	}

	if objs[0].Kind != pki.KindRequest {
		return fail(fmt.Errorf("%s is a %s, not a certificate request", *csrPath, objs[0].Kind.Name()))
	}

	csr, err := x509.ParseCertificateRequest(objs[0].DER)
	if err != nil {
		return fail(err)
	}

	if t.RawSubject, t.SANs, err = pki.FromRequest(csr); err != nil {
		return fail(err)
	}

	// The issuer has the last word on the names: --subject and --san replace the request's.
	cn := csr.Subject.CommonName

	if *n.subject != "" {
		if t.Subject, err = pki.ParseName(*n.subject); err != nil {
			return fail(err)
		}

		t.RawSubject, cn = nil, pki.CommonName(t.Subject)
	}

	if len(n.sans) > 0 {
		if t.SANs, err = n.names(); err != nil {
			return fail(err)
		}
	}

	if t.Profile.NeedsName() {
		sansFromCN(cn, &t.SANs)
	}

	issuers, err := loadCerts(*caPath)
	if err != nil {
		return fail(err)
	}

	k, err := loadKey(ctx, *caKey, pass)
	if err != nil {
		return fail(err)
	}

	der, err := pki.Issue(t, csr.PublicKey, issuers[0], k, time.Now())
	if err != nil {
		return fail(err)
	}

	var chain []*x509.Certificate
	if *bundle {
		chain = issuers
	}

	return wrote(out, der, chain)
}

func runCertVerify(_ context.Context, args []string) int {
	fs := certFlags("verify")

	var cas, untrusted, crls repeated

	fs.Var(&cas, "ca", "a trusted root; repeat for more. None trusts the system's roots")
	fs.Var(&untrusted, "untrusted", "certificates a chain may be built through, trusted for nothing; repeat for more")
	fs.Var(&crls, "crl", "a revocation list to check the chain against; repeat for more")
	purpose := fs.String("purpose", string(pki.PurposeAny), "what the certificate must be valid for: server, client or any")
	name := fs.String("name", "", "a host name or address the certificate must be valid for")
	at := fs.String("at", "", "check as of this time (RFC 3339, or a date), rather than now")
	requirePQ := fs.Bool("require-pq", false, "fail unless the chain's authentication is post-quantum: ML-DSA throughout")
	asJSON := fs.Bool("json", false, "answer in JSON")

	pos, code, ok := certParse(fs, args, func(n int) bool { return n == 1 })
	if !ok {
		return code
	}

	chain, err := loadCerts(pos[0])
	if err != nil {
		return fail(err)
	}

	opts := pki.VerifyOptions{Name: *name}

	if opts.Purpose, err = pki.ParsePurpose(*purpose); err != nil {
		return fail(err)
	}

	if opts.At, err = parseAt(*at); err != nil {
		return fail(err)
	}

	if opts.Roots, err = loadAllCerts(cas); err != nil {
		return fail(err)
	}

	more, err := loadAllCerts(untrusted)
	if err != nil {
		return fail(err)
	}

	opts.Intermediates = append(chain[1:], more...)

	for _, p := range crls {
		objs, err := pki.ReadFile(p)
		if err != nil {
			return fail(err)
		}

		for _, o := range objs {
			if o.Kind != pki.KindCRL {
				return fail(fmt.Errorf("%s holds a %s, not a revocation list", p, o.Kind.Name()))
			}

			l, err := x509.ParseRevocationList(o.DER)
			if err != nil {
				return fail(fmt.Errorf("%s: %w", p, err))
			}

			opts.CRLs = append(opts.CRLs, l)
		}
	}

	r := pki.Verify(chain[0], opts)

	if r.Valid && *requirePQ && r.Authentication != pki.ClassPQC {
		r.Valid, r.Problem = false, "the chain's authentication is classical, and --require-pq asks for ML-DSA throughout"
	}

	if *asJSON {
		if err := printJSON(r); err != nil {
			return fail(err)
		}
	} else {
		printVerify(r, len(opts.Roots) == 0)
	}

	if !r.Valid {
		return ExitCheckFailed
	}

	return ExitOK
}

// parseAt reads --at: RFC 3339, or a date, which is its midnight UTC. Empty is now.
func parseAt(s string) (time.Time, error) {
	if s == "" {
		return time.Now(), nil
	}

	for _, layout := range []string{time.RFC3339, time.DateTime, time.DateOnly} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("%q is not a time: give RFC 3339 (2026-11-01T08:00:00Z) or a date (2026-11-01)", s)
}

func printVerify(r pki.Result, system bool) {
	if !r.Valid {
		ui.Printf("Not valid: %s\n", r.Problem)
	} else {
		ui.Printf("Valid\n")
	}

	for i, l := range r.Chain {
		role := "leaf"

		switch {
		case l.Root && system:
			role = "system root"
		case l.Root:
			role = "root"
		case i > 0:
			role = "intermediate"
		}

		ui.Printf("  %-15s %s\n", role, l.Subject)
		ui.Printf("  %-15s %s key (%s), signed %s (%s), until %s UTC\n", "", l.Key.Name, l.Key.Class,
			l.Signature, l.SigClass, l.NotAfter.Format(time.DateTime))
	}

	if r.Authentication != "" {
		ui.Printf("  %-15s %s\n", "authentication", r.Authentication)
	}

	for _, c := range r.Revocation {
		line := c.Status
		if c.CRL != "" {
			line += ", by the list from " + c.CRL
			if c.Number != "" {
				line += " numbered " + c.Number
			}
		}

		ui.Printf("  %-15s %s: %s\n", "revocation", c.Subject, line)
	}

	for _, n := range r.Notes {
		ui.Printf("  %-15s %s\n", "note", n)
	}

	if r.Name != "" {
		ui.Printf("  %-15s %s\n", "name", r.Name)
	}

	ui.Printf("  %-15s %s, at %s UTC\n", "purpose", r.Purpose, r.At.Format(time.DateTime))
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	ui.Printf("%s\n", b)

	return nil
}

func runCertShow(_ context.Context, args []string) int {
	fs := certFlags("show")
	asJSON := fs.Bool("json", false, "answer in JSON: an array, one element per object")

	pos, code, ok := certParse(fs, args, atLeastOne)
	if !ok {
		return code
	}

	var shown []pki.Shown

	for _, p := range pos {
		objs, err := pki.ReadFile(p)
		if err != nil {
			return fail(err)
		}

		for _, o := range objs {
			s, err := pki.Show(o, time.Now())
			if err != nil {
				return fail(fmt.Errorf("%s: %w", p, err))
			}

			shown = append(shown, s)
		}
	}

	if *asJSON {
		if err := printJSON(shown); err != nil {
			return fail(err)
		}

		return ExitOK
	}

	for i, s := range shown {
		if i > 0 {
			ui.Println()
		}

		s.Text(ui.Out)
	}

	return ExitOK
}

func runCertConvert(ctx context.Context, args []string) int {
	fs := certFlags("convert")
	to := fs.String("to", "pem", "the encoding to write: pem or der")
	encrypt := fs.Bool("encrypt", false, "encrypt a private key under a new passphrase")
	decrypt := fs.Bool("decrypt", false, "write an encrypted private key in the clear")
	pubout := fs.String("pubout", "", "write the public key of the key, certificate or request here, instead of converting it")
	pass := registerPass(fs, "", "to open the key")
	newPass := registerPass(fs, "new-", "to encrypt with")
	out := outFlags{out: fs.String("out", "", "where to write it; - is stdout"), der: new(bool),
		force: fs.Bool("force", false, "replace a key already at --out, which is otherwise refused")}

	pos, code, ok := certParse(fs, args, func(n int) bool { return n == 1 })
	if !ok {
		return code
	}

	switch {
	case *to != "pem" && *to != "der":
		return fail(fmt.Errorf("--to is pem or der, not %q", *to))
	case *encrypt && *decrypt:
		return fail(errors.New("--encrypt and --decrypt contradict each other; --encrypt alone re-encrypts under a new passphrase"))
	case *pubout != "" && *out.out != "":
		return fail(errors.New("--pubout names where the public key goes; it takes no --out"))
	case *pubout == "" && *out.out == "":
		return fail(errors.New("conflux cert convert needs --out"))
	}

	*out.der = *to == "der"

	objs, err := pki.ReadFile(pos[0])
	if err != nil {
		return fail(err)
	}

	if *pubout != "" {
		return convertPublic(ctx, objs, pos[0], *pubout, *out.der, pass)
	}

	for i, o := range objs {
		if objs[i], err = convertOne(ctx, o, pos[0], *encrypt, *decrypt, pass, newPass); err != nil {
			return fail(fmt.Errorf("%s: %w", pos[0], err))
		}
	}

	if err := out.write(objs...); err != nil {
		return fail(err)
	}

	if *out.out != "-" {
		note("Wrote %s, %s, to %s.", objs[0].Kind.Name(), strings.ToUpper(*to), out.where())
	}

	return ExitOK
}

// convertOne is one object as convert writes it.
func convertOne(ctx context.Context, o pki.Object, path string, encrypt, decrypt bool, pass, newPass passFlags) (pki.Object, error) {
	isKey := o.Kind == pki.KindPrivateKey || o.Kind == pki.KindEncryptedKey

	if (encrypt || decrypt) && !isKey {
		return o, fmt.Errorf("--encrypt and --decrypt are for private keys, and %s holds a %s", path, o.Kind.Name())
	}

	p8 := o.DER

	if o.Kind == pki.KindEncryptedKey {
		if !encrypt && !decrypt {
			return o, nil // re-encoded as it is
		}

		p, err := pass.get(ctx, "Passphrase for "+path+": ", false)
		if err != nil {
			return o, err
		}

		if p8, err = pki.DecryptPrivateKey(o.DER, p); err != nil {
			return o, err
		}
	} else if decrypt {
		return o, fmt.Errorf("%s is not encrypted", path)
	}

	if !isKey {
		return o, nil
	}

	// Through the parser and back, so an EC or RSA key in its legacy form, or an ML-DSA one
	// with its expanded half, is written as the PKCS#8 this writes.
	k, err := pki.ParsePrivateKey(p8)
	if err != nil {
		return o, err
	}

	if p8, err = pki.MarshalPrivateKey(k); err != nil {
		return o, err
	}

	if !encrypt {
		return pki.Object{Kind: pki.KindPrivateKey, DER: p8}, nil
	}

	np, err := newPass.get(ctx, "New passphrase: ", true)
	if err != nil {
		return o, err
	}

	enc, err := pki.EncryptPrivateKey(p8, np)

	return pki.Object{Kind: pki.KindEncryptedKey, DER: enc}, err
}

func convertPublic(ctx context.Context, objs []pki.Object, path, to string, der bool, pass passFlags) int {
	o := objs[0]

	if o.Kind == pki.KindEncryptedKey {
		k, err := loadKey(ctx, path, pass)
		if err != nil {
			return fail(err)
		}

		p8, _ := pki.MarshalPrivateKey(k)
		o = pki.Object{Kind: pki.KindPrivateKey, DER: p8}
	}

	pub, err := pki.PublicKeyOf(o)
	if err != nil {
		return fail(err)
	}

	spki, err := pki.MarshalPublicKey(pub)
	if err != nil {
		return fail(err)
	}

	if err := pki.Write(to, []pki.Object{{Kind: pki.KindPublicKey, DER: spki}}, der, false); err != nil {
		return fail(err)
	}

	if to != "-" {
		note("Wrote the %s public key to %s.", pki.Describe(pub).Name, to)
	}

	return ExitOK
}

func runCertMatch(ctx context.Context, args []string) int {
	fs := certFlags("match")
	pass := registerPass(fs, "", "to open a key")

	pos, code, ok := certParse(fs, args, func(n int) bool { return n == 2 })
	if !ok {
		return code
	}

	var keys [2]any

	for i, p := range pos {
		pub, err := publicKeyAt(ctx, p, pass)
		if err != nil {
			return fail(err)
		}

		keys[i] = pub
	}

	if !pki.SamePublicKey(keys[0], keys[1]) {
		ui.Printf("No match: the key in %s (%s) is not the one in %s (%s).\n",
			pos[0], pki.Describe(keys[0]).Name, pos[1], pki.Describe(keys[1]).Name)

		return ExitCheckFailed
	}

	ui.Printf("Match: %s and %s hold the same %s key.\n", pos[0], pos[1], pki.Describe(keys[0]).Name)

	return ExitOK
}

// publicKeyAt is the public key of the first thing at path that has one.
func publicKeyAt(ctx context.Context, path string, pass passFlags) (any, error) {
	objs, err := pki.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if objs[0].Kind == pki.KindEncryptedKey {
		k, err := loadKey(ctx, path, pass)
		if err != nil {
			return nil, err
		}

		return k.Public(), nil
	}

	return pki.PublicKeyOf(objs[0])
}

func runCertFingerprint(_ context.Context, args []string) int {
	fs := certFlags("fingerprint")
	alg := fs.String("alg", string(pki.SHA256), "the digest: sha256, sha384, sha512, sha3-256, sha3-384 or sha3-512")
	spki := fs.Bool("spki", false, "take the public key's fingerprint (its SubjectPublicKeyInfo), the form a pin takes")
	asJSON := fs.Bool("json", false, "answer in JSON: an array, one element per object")

	pos, code, ok := certParse(fs, args, atLeastOne)
	if !ok {
		return code
	}

	d, err := pki.ParseDigest(*alg)
	if err != nil {
		return fail(err)
	}

	type entry struct {
		File string `json:"file"`
		pki.Fingerprint
	}

	var all []entry

	for _, p := range pos {
		objs, err := pki.ReadFile(p)
		if err != nil {
			return fail(err)
		}

		for _, o := range objs {
			f, err := pki.FingerprintOf(o, d, *spki)
			if err != nil {
				return fail(fmt.Errorf("%s: %w", p, err))
			}

			all = append(all, entry{p, f})
		}
	}

	if *asJSON {
		if err := printJSON(all); err != nil {
			return fail(err)
		}

		return ExitOK
	}

	for _, e := range all {
		ui.Printf("%s %s  %s (%s)\n", strings.ToUpper(string(e.Digest)), e.Hex, e.File, e.Of)
	}

	return ExitOK
}

func runCertCRL(ctx context.Context, args []string) int {
	fs := certFlags("crl")
	caPath := fs.String("ca", "", "the issuer's certificate")
	caKey := fs.String("ca-key", "", "the issuer's private key")

	var revoke repeated

	fs.Var(&revoke, "revoke", "a serial number to revoke, in hex as show prints it, as SERIAL or SERIAL:REASON; repeat for more")
	from := fs.String("from", "", "carry the entries of this list, the issuer's last, into the new one, numbered after it")
	number := fs.String("number", "", "the list's number; the default is one after --from's, or else the time in seconds")
	days := fs.Int("days", 7, "how many days until the next list is due")
	pss := fs.Bool("rsa-pss", false, "with an RSA issuer, sign with RSASSA-PSS rather than PKCS #1 v1.5")
	pass := registerPass(fs, "", "to open the issuer's key")
	out := registerOut(fs, "-")

	if _, code, ok := certParse(fs, args, none); !ok {
		return code
	}

	if err := required(fs, "ca", "ca-key"); err != nil {
		return fail(err)
	}

	issuers, err := loadCerts(*caPath)
	if err != nil {
		return fail(err)
	}

	issuer, now := issuers[0], time.Now()

	entries, n, err := carried(*from, issuer)
	if err != nil {
		return fail(err)
	}

	for _, r := range revoke {
		serial, reason := revokeEntry(r)

		e := pki.Revoked{At: now}

		if e.Serial, err = pki.ParseSerial(serial); err != nil {
			return fail(err)
		}

		if reason != "" {
			if e.Reason, err = pki.ParseReason(reason); err != nil {
				return fail(err)
			}
		}

		entries = append(entries, e)
	}

	switch {
	case *number != "":
		var ok bool
		if n, ok = new(big.Int).SetString(*number, 10); !ok {
			return fail(fmt.Errorf("--number is a whole number, not %q", *number))
		}
	case n == nil:
		n = big.NewInt(now.Unix())
	}

	k, err := loadKey(ctx, *caKey, pass)
	if err != nil {
		return fail(err)
	}

	der, err := pki.CRL(issuer, k, entries, n, now, *days, *pss)
	if err != nil {
		return fail(err)
	}

	if err := out.write(pki.Object{Kind: pki.KindCRL, DER: der}); err != nil {
		return fail(err)
	}

	if *out.out != "-" {
		note("Wrote %s's revocation list number %s, %d revoked, due again in %d days, to %s.",
			issuer.Subject, n, len(entries), *days, out.where())
	}

	return ExitOK
}

// revokeEntry splits SERIAL[:REASON]. A serial is printed in colon-separated bytes, so the
// reason is what follows the last colon when that is longer than a byte's two digits.
func revokeEntry(s string) (serial, reason string) {
	if i := strings.LastIndex(s, ":"); i >= 0 && len(s)-i-1 > 2 {
		return s[:i], s[i+1:]
	}

	return s, ""
}

// carried is what a list from issuer at path revoked, and the number after its own. A list
// from another issuer, or one whose signature does not verify, is refused.
func carried(path string, issuer *x509.Certificate) ([]pki.Revoked, *big.Int, error) {
	if path == "" {
		return nil, nil, nil
	}

	objs, err := pki.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	if objs[0].Kind != pki.KindCRL {
		return nil, nil, fmt.Errorf("%s holds a %s, not a revocation list", path, objs[0].Kind.Name())
	}

	l, err := x509.ParseRevocationList(objs[0].DER)
	if err != nil {
		return nil, nil, err
	}

	if err := l.CheckSignatureFrom(issuer); err != nil {
		return nil, nil, fmt.Errorf("%s is not %s's revocation list: %w", path, issuer.Subject, err)
	}

	var out []pki.Revoked
	for _, e := range l.RevokedCertificateEntries {
		out = append(out, pki.Revoked{Serial: e.SerialNumber, Reason: e.ReasonCode, At: e.RevocationTime})
	}

	next := big.NewInt(1)
	if l.Number != nil {
		next.Add(l.Number, next)
	}

	return out, next, nil
}
