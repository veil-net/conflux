// Package enrol gets a credential and keeps it current.
//
// One call gets everything: POST /ghosts/alpha takes no body, needs no account,
// and answers with a base64 anchor manifest carrying an identity, a realm root, a
// credential chain, a bootstrap list and where to renew. Nothing is stored on the
// server -- the response is the only copy in existence -- so the single most
// important property of this package is that it enrols exactly once, when there is
// no manifest on disk, and never as a fallback for anything.
//
// The manifest format is anchor's (cmd/anchorctl/manifest.go, anchorManifest). An
// issuer adds where to renew -- renewalUrl, and for a guardian renewalAuth and
// renewalSecret -- which anchor carries and ignores.
package enrol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"time"

	"github.com/veil-net/conflux/internal/config"
)

// ManifestTime is the timestamp layout the envelope uses on both sides of the
// wire: RFC3339 in UTC with the milliseconds always present, which is how anchor and
// the API write one. anchor never reads them back; conflux does, and writes what it
// renews in the same form so the document stays one shape.
const ManifestTime = "2006-01-02T15:04:05.000Z"

// FormatVersion is the only envelope version this build understands. anchor
// compares it for equality rather than negotiating, and so does conflux: a shape
// change is a coordinated release, not something to sniff at.
const FormatVersion = 1

// Manifest is a parsed envelope that has not forgotten anything.
//
// Held as raw JSON rather than a struct, and that is the load-bearing decision. The
// document carries fields conflux has no opinion about -- genesis, telemetrySecret,
// relay, realm, and whatever an issuer adds next -- and anchor reads most of them even
// though conflux does not. Round-tripping through a struct with only the known
// fields would delete the rest on the first renewal, and the anchor would come back
// after the next reboot without them.
type Manifest struct {
	raw map[string]json.RawMessage
}

// Decode parses an envelope and checks it is a document anchor will start from: the
// encoding, the version, the kind and the three fields anchorctl requires, refused
// here with conflux's words rather than a child process's.
func Decode(env config.Envelope) (*Manifest, error) {
	b, err := base64.StdEncoding.DecodeString(string(env))
	if err != nil {
		return nil, fmt.Errorf("the stored credential is not base64: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("the stored credential is not a JSON document: %w", err)
	}

	m := &Manifest{raw: raw}

	version, err := m.int("formatVersion")
	if err != nil {
		return nil, err
	}

	if version != FormatVersion {
		return nil, fmt.Errorf(
			"the credential is format version %d and this conflux understands %d; upgrade conflux",
			version, FormatVersion)
	}

	kind, err := m.string("kind")
	if err != nil {
		return nil, err
	}

	if kind != "anchor" {
		return nil, fmt.Errorf(
			"the credential is a %q manifest, not an anchor one: a realm manifest mints anchors and does not start one",
			kind)
	}

	for _, field := range []string{"identity", "genesis", "chain"} {
		if v, _ := m.string(field); v == "" {
			return nil, fmt.Errorf("the credential carries no %s, so an anchor cannot be built from it", field)
		}
	}

	return m, nil
}

// Encode renders it back to an envelope. Key order is not preserved and does not
// matter: every reader on both sides looks fields up by name.
func (m *Manifest) Encode() (config.Envelope, error) {
	b, err := json.Marshal(m.raw)
	if err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}

	return config.Envelope(base64.StdEncoding.EncodeToString(b)), nil
}

// NotAfter is when the credential stops verifying. Zero if the document does not
// say, which callers treat as "renew now" rather than "never expires".
func (m *Manifest) NotAfter() time.Time { return m.time("notAfter") }

// IssuedAt is when the chain the document holds was issued, as far as conflux
// observed it, and the other end of the window the renewal timer divides.
func (m *Manifest) IssuedAt() time.Time { return m.time("issuedAt") }

// RenewalURL is where to ask for the next chain. Taken from the document rather
// than composed from a constant, so whatever issued a credential is what is asked
// to renew it.
func (m *Manifest) RenewalURL() string {
	s, _ := m.string("renewalUrl")

	return s
}

// Taints are whatever the issuer put in the document. The alpha realm always sends
// an empty list, and anchor's merge skips an empty list, so conflux's own -taints
// flag decides in practice. Read only by `conflux enrol`, which seeds the
// configuration from a guardian's.
func (m *Manifest) Taints() []string {
	var out []string

	if v, ok := m.raw["taints"]; ok {
		_ = json.Unmarshal(v, &out)
	}

	return out
}

// IPv4 is an overlay address the issuer allocated, as a prefix.
//
// **Read once, by the import verb, and never on a start.** Guardian allocates
// addresses out of a range it keeps in a database, so the number has to travel
// somehow, and a field the operator can see in `conflux config` afterwards beats a
// number retyped from a web page.
//
// The reason it is seeded rather than obeyed is the same one that makes conflux
// pass both exit flags explicitly instead of letting the manifest supply them: a
// document must not decide, on every start, what this machine does. The difference
// is what the two settings are. An exit flag makes a machine a route to the public
// internet for everybody else, so inheriting one silently is a change of role. An
// address grants nothing and reaches nobody -- and unlike an exit, an operator who
// disagrees with it can see it in the config file and change it, because conflux
// wrote it there once rather than re-reading it behind them.
//
// Empty when the issuer allocated none, which is every alpha document and is not an
// error: the v6 address is derived from the identity and needs no decision.
func (m *Manifest) IPv4() string {
	s, _ := m.string("ipv4")

	return s
}

// Export is the telemetry configuration the issuer suggested, as raw JSON.
//
// **Seeded at import and never obeyed at run time**, exactly like IPv4, and this
// is the field where that distinction was hardest to settle. The precedent cuts
// both ways and both halves of it are real.
//
// For carrying it: telemetrySecret already travels in this document, so the
// principle that a manifest may configure how a machine is observed is not new.
// And the alternative is worse in practice -- an operator who commissioned fifty
// nodes in a web UI would then have to type the same collector endpoint and a
// different per-node credential into fifty config files by hand, which is a
// procedure with a typo in it.
//
// Against: anchor's own proto calls Observability "the one interface here that
// tells the daemon to dial an arbitrary network address and ship it this realm's
// operational detail", and conflux refuses to inherit the exit flags for a reason
// that rhymes -- an anchor that became an internet exit because a document said so
// is the worst kind of surprise.
//
// What resolves it is *when* rather than *whether*. The exit flags are refused
// because they would be re-read on every start, so a document could keep deciding
// what this machine does for other people, indefinitely, behind an operator who
// never agreed. This is read once, by a person running a command, and written into
// conflux.json where that person can see it in `conflux config` and change it --
// and from then on the document is not consulted again. A suggestion at
// commissioning time is a different thing from a standing instruction, and the
// difference is the whole of why one is refused and this is not.
//
// Raw rather than parsed, because enrol knows nothing about the shape -- config
// owns it, and a second decoder here would be a second schema.
func (m *Manifest) Export() json.RawMessage {
	v, ok := m.raw["export"]
	if !ok {
		return nil
	}

	return v
}

// Bootstrap is the peer list the issuer supplied.
func (m *Manifest) Bootstrap() []string {
	var out []string

	if v, ok := m.raw["bootstrap"]; ok {
		_ = json.Unmarshal(v, &out)
	}

	return out
}

// WithChain splices a renewed credential into the document: the chain, when it
// expires, and when it was received, and nothing else.
//
// This has to happen on every successful renewal, not just the hot install into the
// running anchor. `anchorctl renew` swaps the chain in memory; if the document on
// disk still holds the old one, the next reboot starts from a stale chain -- and if
// the machine was off for longer than the original window, from an expired one, at
// a moment when nobody is watching.
//
// issuedAt moves with the chain because the window is measured from it. Left at the
// enrolment, every renewal would widen the window the next start divides, and the
// credential would read as due ever earlier in its life.
//
// chain is the raw credential bytes. The API sends base64 and this stores base64,
// but the file anchorctl -cred reads wants the raw bytes, so exactly one of the two
// call sites decodes and it is not this one.
//
// The result is a copy, so a caller whose write of it fails still holds the
// document the running anchor was started from.
func (m *Manifest) WithChain(chain []byte, notAfter, issuedAt time.Time) (*Manifest, error) {
	next := &Manifest{raw: maps.Clone(m.raw)}

	for field, v := range map[string]string{
		"chain":    base64.StdEncoding.EncodeToString(chain),
		"notAfter": notAfter.UTC().Format(ManifestTime),
		"issuedAt": issuedAt.UTC().Format(ManifestTime),
	} {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}

		next.raw[field] = b
	}

	return next, nil
}

func (m *Manifest) string(key string) (string, error) {
	v, ok := m.raw[key]
	if !ok {
		return "", fmt.Errorf("the credential has no %q field", key)
	}

	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", fmt.Errorf("the credential's %q is not a string: %w", key, err)
	}

	return s, nil
}

func (m *Manifest) int(key string) (int, error) {
	v, ok := m.raw[key]
	if !ok {
		return 0, fmt.Errorf("the credential has no %q field", key)
	}

	var n int
	if err := json.Unmarshal(v, &n); err != nil {
		return 0, fmt.Errorf("the credential's %q is not a number: %w", key, err)
	}

	return n, nil
}

// time parses one of the document's timestamps: RFC3339, which covers the
// milliseconds anchor writes and an issuer that leaves them out. An unparseable or
// absent value is the zero time.
func (m *Manifest) time(key string) time.Time {
	s, err := m.string(key)
	if err != nil {
		return time.Time{}
	}

	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}

	return t.UTC()
}

// String keeps the identity out of fmt, the way Envelope's does.
func (m *Manifest) String() string { return "<anchor manifest, redacted>" }

// GoString covers %#v, which String does not and which would otherwise print the raw
// document, seed and bearer included.
func (m *Manifest) GoString() string { return "<anchor manifest, redacted>" }
