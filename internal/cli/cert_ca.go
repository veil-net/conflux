package cli

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/pki"
	"github.com/veil-net/conflux/internal/pki/ca"
	"github.com/veil-net/conflux/internal/ui"
)

// cert ca: a certificate authority kept in a directory -- a root, an optional issuing CA,
// what they issued and what they revoked. See internal/pki/ca.

type caCommand struct {
	run            func(ctx context.Context, args []string) int
	usage, summary string
}

func caCommands() map[string]caCommand {
	return map[string]caCommand{
		"init":   {runCAInit, "init DIR --name NAME [--intermediate] [--alg ALG] [--no-encrypt]", "make a CA in a new directory"},
		"issue":  {runCAIssue, "issue DIR --csr REQ [--profile server] [--days N] [--out FILE] [--bundle]", "issue a certificate for a request, and record it"},
		"revoke": {runCARevoke, "revoke DIR SERIAL [--reason REASON]", "revoke a certificate the CA issued, and publish its CRL"},
		"list":   {runCAList, "list DIR [--json]", "every certificate the CA issued, and whether it is valid, expired or revoked"},
		"crl":    {runCACRL, "crl DIR", "publish the CA's revocation lists again, numbered on"},
	}
}

func runCertCA(ctx context.Context, args []string) int {
	cmds := caCommands()

	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		names := make([]string, 0, len(cmds))
		for n := range cmds {
			names = append(names, n)
		}

		sort.Strings(names)
		ui.Printf("conflux cert ca — a certificate authority kept in a directory\n\n")

		for _, n := range names {
			ui.Printf("  %-8s %s\n", n, cmds[n].summary)
		}

		ui.Printf("\nconflux cert ca COMMAND -h says more of each; docs/cert.md, \"A managed CA\", has the directory.\n")

		if len(args) == 0 {
			return ExitUsage
		}

		return ExitOK
	}

	c, ok := cmds[args[0]]
	if !ok {
		ui.Errf("%q is not a cert ca command; conflux cert ca help lists them", args[0])

		return ExitUsage
	}

	return c.run(ctx, args[1:])
}

// caFlags is a cert ca subcommand's flag set.
func caFlags(name string) *flag.FlagSet {
	return certFlagsNamed("ca "+name, caCommands()[name].summary, "ca "+caCommands()[name].usage)
}

// caPass is the passphrase of the CA's keys, asked only where they are encrypted.
func caPass(ctx context.Context, c *ca.CA, p passFlags) ([]byte, error) {
	if !c.Settings.Encrypted {
		return nil, nil
	}

	return p.get(ctx, "Passphrase for the CA in "+c.Dir+": ", false)
}

func runCAInit(ctx context.Context, args []string) int {
	fs := caFlags("init")
	name := fs.String("name", "", "the CA's name: its root is \"NAME Root CA\", its issuing CA \"NAME Issuing CA\"")
	org := fs.String("org", "", "the organisation (O) in both")
	alg := fs.String("alg", string(pki.DefaultAlg), "the root's key algorithm")
	intermediate := fs.Bool("intermediate", false, "issue from an intermediate CA under the root, so the root's key can be kept offline")
	interAlg := fs.String("intermediate-alg", string(pki.MLDSA65), "the intermediate's key algorithm")
	days := fs.Int("days", 3650, "how many days the root is valid for")
	interDays := fs.Int("intermediate-days", 1825, "how many days the intermediate is valid for")
	leafDays := fs.Int("leaf-days", 365, "how many days a certificate the CA issues is valid for, unless issue says otherwise")
	crlDays := fs.Int("crl-days", 7, "how many days each revocation list is valid for")
	pss := fs.Bool("rsa-pss", false, "with RSA keys, sign with RSASSA-PSS rather than PKCS #1 v1.5")
	noEncrypt := fs.Bool("no-encrypt", false, "leave the CA's keys in the clear, readable by this account alone; otherwise they are encrypted under a passphrase")

	var crlURLs repeated

	fs.Var(&crlURLs, "crl-url", "where the issuing CA's revocation list is published, recorded in what it issues; repeat for more")

	pass := registerPass(fs, "", "to encrypt the CA's keys with")

	pos, code, ok := certParse(fs, args, func(n int) bool { return n == 1 })
	if !ok {
		return code
	}

	o := ca.InitOptions{
		Name: *name, Org: *org, Intermediate: *intermediate, RootDays: *days, IntermediateDays: *interDays,
		LeafDays: *leafDays, CRLDays: *crlDays, CRLURLs: crlURLs, RSAPSS: *pss,
	}

	var err error

	if o.RootAlg, err = pki.ParseAlg(*alg); err != nil {
		return fail(err)
	}

	if o.IntermediateAlg, err = pki.ParseAlg(*interAlg); err != nil {
		return fail(err)
	}

	if !*noEncrypt {
		if o.Passphrase, err = pass.get(ctx, "Passphrase for the CA's keys: ", true); err != nil {
			return fail(err)
		}
	}

	c, err := ca.Init(pos[0], o, time.Now())
	if err != nil {
		return fail(err)
	}

	defer c.Close()

	chain, err := c.Chain()
	if err != nil {
		return fail(err)
	}

	note("Made a CA in %s.", pos[0])

	for _, x := range chain {
		info := pki.Describe(x.PublicKey)
		note("  %s: %s (%s), until %s UTC", x.Subject, info.Name, info.Class, x.NotAfter.UTC().Format(time.DateTime))
	}

	note("Trust root.pem; a server presents its certificate with chain.pem (conflux cert ca issue --bundle).")

	return ExitOK
}

func runCAIssue(ctx context.Context, args []string) int {
	fs := caFlags("issue")
	csrPath := fs.String("csr", "", "the request to issue a certificate for")
	profile := fs.String("profile", string(pki.ProfileServer), "what the certificate is for: server, client or server+client")
	days := fs.Int("days", 0, "how many days it is valid for; the CA's --leaf-days when 0")
	bundle := fs.Bool("bundle", false, "write the CA's chain after the certificate, as a server presents it")
	n := registerNames(fs)
	pass := registerPass(fs, "", "to open the CA's keys")
	out := registerOut(fs, "-")

	pos, code, ok := certParse(fs, args, func(n int) bool { return n == 1 })
	if !ok {
		return code
	}

	if err := required(fs, "csr"); err != nil {
		return fail(err)
	}

	p, err := pki.ParseProfile(*profile)
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

	t := pki.Template{Profile: p, Days: *days, PathLen: -1}

	if t.RawSubject, t.SANs, err = pki.FromRequest(csr); err != nil {
		return fail(err)
	}

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

	if p.NeedsName() {
		sansFromCN(cn, &t.SANs)
	}

	c, err := ca.Open(pos[0])
	if err != nil {
		return fail(err)
	}

	defer c.Close()

	pw, err := caPass(ctx, c, pass)
	if err != nil {
		return fail(err)
	}

	x, err := c.Issue(t, csr.PublicKey, pw, time.Now())
	if err != nil {
		return fail(err)
	}

	var chain []*x509.Certificate

	if *bundle {
		if chain, err = c.Chain(); err != nil {
			return fail(err)
		}

		// A server presents its own certificate and the intermediates; the root is the
		// client's to have.
		if len(chain) > 1 {
			chain = chain[:len(chain)-1]
		} else {
			chain = nil
		}
	}

	note("Issued %s, serial %s, recorded in %s.", x.Subject, pki.FormatSerial(x.SerialNumber), c.Dir)

	return wrote(out, x.Raw, chain)
}

func runCARevoke(ctx context.Context, args []string) int {
	fs := caFlags("revoke")
	reason := fs.String("reason", "unspecified", "why: unspecified, keyCompromise, cACompromise, affiliationChanged, superseded, "+
		"cessationOfOperation, privilegeWithdrawn or aACompromise")
	pass := registerPass(fs, "", "to open the CA's keys")

	pos, code, ok := certParse(fs, args, func(n int) bool { return n == 2 })
	if !ok {
		return code
	}

	serial, err := pki.ParseSerial(pos[1])
	if err != nil {
		return fail(err)
	}

	r, err := pki.ParseReason(*reason)
	if err != nil {
		return fail(err)
	}

	c, err := ca.Open(pos[0])
	if err != nil {
		return fail(err)
	}

	defer c.Close()

	pw, err := caPass(ctx, c, pass)
	if err != nil {
		return fail(err)
	}

	if err := c.Revoke(serial, r, pw, time.Now()); err != nil {
		return fail(err)
	}

	note("Revoked %s (%s), and published %s.", pki.FormatSerial(serial), pki.ReasonName(r), c.Dir+"/crl.pem")

	return ExitOK
}

func runCAList(_ context.Context, args []string) int {
	fs := caFlags("list")
	asJSON := fs.Bool("json", false, "answer in JSON")

	pos, code, ok := certParse(fs, args, func(n int) bool { return n == 1 })
	if !ok {
		return code
	}

	c, err := ca.Open(pos[0])
	if err != nil {
		return fail(err)
	}

	defer c.Close()

	list, err := c.List(time.Now())
	if err != nil {
		return fail(err)
	}

	if *asJSON {
		if err := printJSON(list); err != nil {
			return fail(err)
		}

		return ExitOK
	}

	if len(list) == 0 {
		ui.Printf("%s has issued nothing yet.\n", c.Settings.Name)

		return ExitOK
	}

	for _, e := range list {
		status := e.Status
		if e.Reason != "" {
			status += ", " + e.Reason
		}

		ui.Printf("%s  %-28s until %s  %s  %s\n", e.Serial, status, e.NotAfter.Format(time.DateOnly), e.Subject, strings.Join(e.Names, " "))
	}

	return ExitOK
}

func runCACRL(ctx context.Context, args []string) int {
	fs := caFlags("crl")
	pass := registerPass(fs, "", "to open the CA's keys")

	pos, code, ok := certParse(fs, args, func(n int) bool { return n == 1 })
	if !ok {
		return code
	}

	c, err := ca.Open(pos[0])
	if err != nil {
		return fail(err)
	}

	defer c.Close()

	pw, err := caPass(ctx, c, pass)
	if err != nil {
		return fail(err)
	}

	if err := c.CRL(pw, time.Now()); err != nil {
		return fail(err)
	}

	note("Published the revocation lists in %s, valid for %d days.", c.Dir, c.Settings.CRLDays)

	return ExitOK
}
