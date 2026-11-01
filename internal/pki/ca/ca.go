// Package ca is conflux cert's managed certificate authority: a directory holding a root, an
// optional intermediate, everything they issued and what they revoked, kept so that a crash
// at any point leaves nothing issued unrecorded and no CRL number used twice.
//
// The directory:
//
//	ca.json                  the CA's settings
//	root.pem, root.key       the root, its key encrypted unless made with none
//	intermediate.pem, .key   the issuing CA, when there is one
//	chain.pem                the issuing CA and what is above it, as a server presents them
//	issued/SERIAL.pem        one file per certificate issued: the record of what was
//	index.json               what was revoked, and the last CRL numbers used
//	crl.pem                  the issuing CA's latest CRL; root.crl the root's, with an intermediate
//	.lock                    held by whichever command is working in it
//
// No subscriber's key is ever in it: a certificate is issued for a request.
package ca

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pki"
)

const formatVersion = 1

// Settings are ca.json.
type Settings struct {
	FormatVersion int       `json:"formatVersion"`
	Name          string    `json:"name"`
	Created       time.Time `json:"created"`
	Intermediate  bool      `json:"intermediate"`
	Encrypted     bool      `json:"encrypted"`
	LeafDays      int       `json:"leafDays"`
	CRLDays       int       `json:"crlDays"`
	CRLURLs       []string  `json:"crlUrls,omitempty"`
	RSAPSS        bool      `json:"rsaPss,omitempty"`
}

// Index is index.json.
type Index struct {
	FormatVersion int          `json:"formatVersion"`
	CRLNumber     int64        `json:"crlNumber"`               // the issuing CA's last
	RootCRLNumber int64        `json:"rootCrlNumber,omitempty"` // the root's, with an intermediate
	Revoked       []Revocation `json:"revoked"`
}

// Revocation is one certificate the CA revoked.
type Revocation struct {
	Serial string    `json:"serial"` // as show prints it
	Reason string    `json:"reason"`
	At     time.Time `json:"revokedAt"`
}

// CA is an opened CA directory, its lock held until Close.
type CA struct {
	Dir      string
	Settings Settings

	unlock func()
	keys   map[string]crypto.Signer // opened this command, so a passphrase is derived once
}

func (c *CA) path(name ...string) string { return filepath.Join(append([]string{c.Dir}, name...)...) }

// issuerName is the issuing CA's file name, without its extension.
func (c *CA) issuerName() string {
	if c.Settings.Intermediate {
		return "intermediate"
	}

	return "root"
}

// InitOptions are what a CA is made with.
type InitOptions struct {
	Name, Org        string
	RootAlg          pki.Alg
	Intermediate     bool
	IntermediateAlg  pki.Alg
	RootDays         int
	IntermediateDays int
	LeafDays         int
	CRLDays          int
	CRLURLs          []string
	RSAPSS           bool

	// Passphrase encrypts the CA's keys; nil leaves them in the clear.
	Passphrase []byte
}

// ErrBusy is a CA another command is working in.
var ErrBusy = errors.New("another conflux cert ca command is working in this CA; try again when it is done")

// Init makes a CA in dir, which must not exist or be empty, and returns it opened.
func Init(dir string, o InitOptions, now time.Time) (*CA, error) {
	if o.Name == "" {
		return nil, errors.New("a CA needs a name: --name")
	}

	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s is not empty: a CA is made in a directory of its own", dir)
	}

	if err := makeDir(dir); err != nil {
		return nil, err
	}

	c := &CA{Dir: dir, Settings: Settings{
		FormatVersion: formatVersion, Name: o.Name, Created: now.UTC().Truncate(time.Second),
		Intermediate: o.Intermediate, Encrypted: o.Passphrase != nil,
		LeafDays: o.LeafDays, CRLDays: o.CRLDays, CRLURLs: o.CRLURLs, RSAPSS: o.RSAPSS,
	}}

	if err := c.lock(); err != nil {
		return nil, err
	}

	if err := c.init(o, now); err != nil {
		c.Close()

		return nil, err
	}

	return c, nil
}

func (c *CA) init(o InitOptions, now time.Time) error {
	if err := makeDir(c.path("issued")); err != nil {
		return err
	}

	name := func(cn string) string {
		dn := "CN=" + escape(cn)
		if o.Org != "" {
			dn += ",O=" + escape(o.Org)
		}

		return dn
	}

	rootDN := name(o.Name + " Root CA")

	pathLen := 0
	if o.Intermediate {
		pathLen = 1
	}

	root, rootKey, err := c.makeCA("root", o.RootAlg, rootDN, o.RootDays, pathLen, nil, nil, o.Passphrase, now)
	if err != nil {
		return err
	}

	chain := []*x509.Certificate{root}

	if o.Intermediate {
		dn := name(o.Name + " Issuing CA")

		inter, _, err := c.makeCA("intermediate", o.IntermediateAlg, dn, o.IntermediateDays, 0, root, rootKey, o.Passphrase, now)
		if err != nil {
			return err
		}

		chain = []*x509.Certificate{inter, root}
	}

	var pemChain []byte
	for _, x := range chain {
		pemChain = append(pemChain, pki.Object{Kind: pki.KindCertificate, DER: x.Raw}.PEM()...)
	}

	if err := pki.WriteFile(c.path("chain.pem"), pemChain, 0o644, true); err != nil {
		return err
	}

	if err := c.saveSettings(); err != nil {
		return err
	}

	if err := c.saveIndex(&Index{FormatVersion: formatVersion, Revoked: []Revocation{}}); err != nil {
		return err
	}

	return c.CRL(o.Passphrase, now)
}

// makeCA makes one of the CA's own certificates and its key: self-signed for the root, else
// by parent.
func (c *CA) makeCA(file string, alg pki.Alg, dn string, days, pathLen int, parent *x509.Certificate,
	parentKey crypto.Signer, pass []byte, now time.Time,
) (*x509.Certificate, crypto.Signer, error) {
	k, err := alg.Generate()
	if err != nil {
		return nil, nil, err
	}

	subject, err := pki.ParseName(dn)
	if err != nil {
		return nil, nil, err
	}

	signer := k
	if parent != nil {
		signer = parentKey
	}

	der, err := pki.Issue(pki.Template{Subject: subject, Profile: pki.ProfileCA, Days: days, PathLen: pathLen, RSAPSS: c.Settings.RSAPSS},
		k.Public(), parent, signer, now)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	p8, err := pki.MarshalPrivateKey(k)
	if err != nil {
		return nil, nil, err
	}

	key := pki.Object{Kind: pki.KindPrivateKey, DER: p8}

	if pass != nil {
		enc, err := pki.EncryptPrivateKey(p8, pass)
		if err != nil {
			return nil, nil, err
		}

		key = pki.Object{Kind: pki.KindEncryptedKey, DER: enc}
	}

	if err := pki.WriteFile(c.path(file+".key"), key.PEM(), 0o600, true); err != nil {
		return nil, nil, err
	}

	if err := pki.WriteFile(c.path(file+".pem"), pki.Object{Kind: pki.KindCertificate, DER: der}.PEM(), 0o644, true); err != nil {
		return nil, nil, err
	}

	return cert, k, nil
}

// escape makes a name's value safe inside the RFC 4514 subject ParseName reads.
func escape(v string) string {
	return strings.NewReplacer(`\`, `\\`, `,`, `\,`, `=`, `\=`, `+`, `\+`).Replace(v)
}

// Open opens the CA in dir, holding its lock until Close; a CA another command holds is
// ErrBusy.
func Open(dir string) (*CA, error) {
	if err := checkDir(dir); err != nil {
		return nil, err
	}

	c := &CA{Dir: dir}

	b, err := os.ReadFile(c.path("ca.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s is not a CA: it has no ca.json. conflux cert ca init makes one", dir)
	}

	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(b, &c.Settings); err != nil {
		return nil, fmt.Errorf("%s: %w", c.path("ca.json"), err)
	}

	if c.Settings.FormatVersion != formatVersion {
		return nil, fmt.Errorf("%s is format %d, and this conflux reads %d", c.path("ca.json"), c.Settings.FormatVersion, formatVersion)
	}

	return c, c.lock()
}

func (c *CA) lock() error {
	unlock, ok, err := flock.TryAcquire(c.path(".lock"))
	if err != nil {
		return err
	}

	if !ok {
		return ErrBusy
	}

	c.unlock = unlock

	return nil
}

// Close releases the CA's lock.
func (c *CA) Close() {
	if c.unlock != nil {
		c.unlock()
		c.unlock = nil
	}
}

func (c *CA) saveSettings() error {
	b, err := json.MarshalIndent(c.Settings, "", "  ")
	if err != nil {
		return err
	}

	return pki.WriteFile(c.path("ca.json"), append(b, '\n'), 0o644, false)
}

func (c *CA) index() (*Index, error) {
	b, err := os.ReadFile(c.path("index.json"))
	if err != nil {
		return nil, err
	}

	var ix Index
	if err := json.Unmarshal(b, &ix); err != nil {
		return nil, fmt.Errorf("%s: %w", c.path("index.json"), err)
	}

	return &ix, nil
}

func (c *CA) saveIndex(ix *Index) error {
	b, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		return err
	}

	return pki.WriteFile(c.path("index.json"), append(b, '\n'), 0o644, false)
}

// Chain is the issuing CA's certificate and what is above it, the issuer first.
func (c *CA) Chain() ([]*x509.Certificate, error) {
	b, err := os.ReadFile(c.path("chain.pem"))
	if err != nil {
		return nil, err
	}

	objs, err := pki.Parse(b)
	if err != nil {
		return nil, err
	}

	var out []*x509.Certificate

	for _, o := range objs {
		x, err := x509.ParseCertificate(o.DER)
		if err != nil {
			return nil, err
		}

		out = append(out, x)
	}

	return out, nil
}

// key opens one of the CA's keys with pass, once a command.
func (c *CA) key(file string, pass []byte) (crypto.Signer, error) {
	if k, ok := c.keys[file]; ok {
		return k, nil
	}

	objs, err := pki.ReadFile(c.path(file + ".key"))
	if err != nil {
		return nil, err
	}

	der := objs[0].DER

	if objs[0].Kind == pki.KindEncryptedKey {
		if pass == nil {
			return nil, errors.New("the CA's keys are encrypted, and no passphrase was given")
		}

		if der, err = pki.DecryptPrivateKey(der, pass); err != nil {
			return nil, err
		}
	}

	k, err := pki.ParsePrivateKey(der)
	if err != nil {
		return nil, err
	}

	if c.keys == nil {
		c.keys = map[string]crypto.Signer{}
	}

	c.keys[file] = k

	return k, nil
}

// newSerial draws a serial number; a test replaces it to make one collide.
var newSerial = pki.Serial

// serialFile is where a certificate of serial is recorded: its bytes in lower-case hex.
func (c *CA) serialFile(serial *big.Int) string {
	return c.path("issued", hex.EncodeToString(serial.Bytes())+".pem")
}

// Issue issues a certificate from t for pub, with the CA's CRL URLs and validity, and records
// it before returning it. A serial already recorded is drawn again.
func (c *CA) Issue(t pki.Template, pub crypto.PublicKey, pass []byte, now time.Time) (*x509.Certificate, error) {
	chain, err := c.Chain()
	if err != nil {
		return nil, err
	}

	k, err := c.key(c.issuerName(), pass)
	if err != nil {
		return nil, err
	}

	if t.Days == 0 {
		t.Days = c.Settings.LeafDays
	}

	if t.Profile == pki.ProfileCA {
		return nil, errors.New("a managed CA issues end-entity certificates; its own CAs are made by conflux cert ca init")
	}

	t.CRLURLs, t.RSAPSS = c.Settings.CRLURLs, c.Settings.RSAPSS

	for range 8 {
		if t.Serial, err = newSerial(); err != nil {
			return nil, err
		}

		der, err := pki.Issue(t, pub, chain[0], k, now)
		if err != nil {
			return nil, err
		}

		// The record is written first, and only where no certificate of the serial is: what
		// was issued is what issued/ holds, and a serial is never issued twice.
		err = pki.WriteFile(c.serialFile(t.Serial), pki.Object{Kind: pki.KindCertificate, DER: der}.PEM(), 0o644, true)
		if errors.Is(err, pki.ErrExists) {
			continue
		}

		if err != nil {
			return nil, err
		}

		return x509.ParseCertificate(der)
	}

	return nil, errors.New("eight serial numbers in a row were already issued here, which 128 random bits do not do: " +
		"the random number generator is broken")
}

// Revoke revokes the certificate of serial, which this CA must have issued and not revoked,
// and publishes a new CRL.
func (c *CA) Revoke(serial *big.Int, reason int, pass []byte, now time.Time) error {
	if _, err := os.Stat(c.serialFile(serial)); err != nil {
		return fmt.Errorf("this CA issued no certificate with serial %s", pki.FormatSerial(serial))
	}

	ix, err := c.index()
	if err != nil {
		return err
	}

	s := pki.FormatSerial(serial)

	if i := slices.IndexFunc(ix.Revoked, func(r Revocation) bool { return r.Serial == s }); i >= 0 {
		return fmt.Errorf("%s was revoked already, %s", s, ix.Revoked[i].At.Format(time.DateTime))
	}

	// Checked before anything is recorded: a revocation with no list to publish it in would
	// be recorded and not said.
	if _, err := c.key(c.issuerName(), pass); err != nil {
		return err
	}

	ix.Revoked = append(ix.Revoked, Revocation{Serial: s, Reason: pki.ReasonName(reason), At: now.UTC().Truncate(time.Second)})

	if err := c.saveIndex(ix); err != nil {
		return err
	}

	return c.CRL(pass, now)
}

// CRL publishes the issuing CA's revocation list, and with an intermediate the root's,
// each numbered one past the last. The number is recorded before the list is written, so a
// crash between the two skips a number rather than using one twice.
func (c *CA) CRL(pass []byte, now time.Time) error {
	ix, err := c.index()
	if err != nil {
		return err
	}

	chain, err := c.Chain()
	if err != nil {
		return err
	}

	k, err := c.key(c.issuerName(), pass)
	if err != nil {
		return err
	}

	var rootKey crypto.Signer
	if c.Settings.Intermediate {
		if rootKey, err = c.key("root", pass); err != nil {
			return err
		}

		ix.RootCRLNumber++
	}

	ix.CRLNumber++

	if err := c.saveIndex(ix); err != nil {
		return err
	}

	var entries []pki.Revoked

	for _, r := range ix.Revoked {
		serial, err := pki.ParseSerial(r.Serial)
		if err != nil {
			return err
		}

		reason, err := pki.ParseReason(r.Reason)
		if err != nil {
			return err
		}

		entries = append(entries, pki.Revoked{Serial: serial, Reason: reason, At: r.At})
	}

	if err := c.writeCRL("crl.pem", chain[0], k, entries, ix.CRLNumber, now); err != nil {
		return err
	}

	if c.Settings.Intermediate {
		return c.writeCRL("root.crl", chain[len(chain)-1], rootKey, nil, ix.RootCRLNumber, now)
	}

	return nil
}

func (c *CA) writeCRL(file string, issuer *x509.Certificate, k crypto.Signer, entries []pki.Revoked, number int64, now time.Time) error {
	der, err := pki.CRL(issuer, k, entries, big.NewInt(number), now, c.Settings.CRLDays, c.Settings.RSAPSS)
	if err != nil {
		return err
	}

	return pki.WriteFile(c.path(file), pki.Object{Kind: pki.KindCRL, DER: der}.PEM(), 0o644, false)
}

// Entry is one certificate the CA issued, as list reports it.
type Entry struct {
	Serial    string    `json:"serial"`
	Subject   string    `json:"subject"`
	Names     []string  `json:"names,omitempty"`
	NotAfter  time.Time `json:"notAfter"`
	Status    string    `json:"status"` // valid, expired or revoked
	Reason    string    `json:"reason,omitempty"`
	RevokedAt time.Time `json:"revokedAt,omitzero"`
}

// List is every certificate the CA issued, the soonest to expire first.
func (c *CA) List(now time.Time) ([]Entry, error) {
	ix, err := c.index()
	if err != nil {
		return nil, err
	}

	revoked := map[string]Revocation{}
	for _, r := range ix.Revoked {
		revoked[r.Serial] = r
	}

	files, err := filepath.Glob(c.path("issued", "*.pem"))
	if err != nil {
		return nil, err
	}

	out := []Entry{}

	for _, f := range files {
		objs, err := pki.ReadFile(f)
		if err != nil {
			return nil, err
		}

		x, err := x509.ParseCertificate(objs[0].DER)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}

		e := Entry{Serial: pki.FormatSerial(x.SerialNumber), Subject: x.Subject.String(), NotAfter: x.NotAfter.UTC(), Status: "valid"}
		e.Names = append(e.Names, x.DNSNames...)

		for _, ip := range x.IPAddresses {
			e.Names = append(e.Names, ip.String())
		}

		e.Names = append(e.Names, x.EmailAddresses...)

		switch r, ok := revoked[e.Serial]; {
		case ok:
			e.Status, e.Reason, e.RevokedAt = "revoked", r.Reason, r.At
		case now.After(x.NotAfter):
			e.Status = "expired"
		}

		out = append(out, e)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].NotAfter.Before(out[j].NotAfter) })

	return out, nil
}

// makeDir makes a directory of the CA's: 0700, its own account's alone.
func makeDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	// MkdirAll leaves a directory that was there as it found it: an empty one somebody made
	// at 0755 for the CA is narrowed here, before anything is in it.
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}

	if err := paths.RestrictToOwner(dir, true); err != nil {
		return err
	}

	return checkDir(dir)
}
