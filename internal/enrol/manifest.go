// Package enrol gets a credential and keeps it current.
//
// One call gets everything: POST /ghosts/alpha takes no body, needs no account,
// and answers with a base64 anchor manifest carrying an identity, a realm root, a
// credential chain, a bootstrap list and where to renew. Nothing is stored on the
// server -- the response is the only copy in existence -- so the single most
// important property of this package is that it enrols exactly once, when there is
// no manifest on disk, and never as a fallback for anything.
package enrol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/veil-net/conflux/internal/config"
)

// ManifestTime is the timestamp layout the envelope uses on both sides of the
// wire: RFC3339 in UTC with the milliseconds always present. anchor parses with a
// fixed layout, so writing a variable one back would be refused.
const ManifestTime = "2006-01-02T15:04:05.000Z"

// FormatVersion is the only envelope version this build understands. anchor
// compares it for equality rather than negotiating, and so does conflux: a shape
// change is a coordinated release, not something to sniff at.
const FormatVersion = 1

// Manifest is a parsed envelope that has not forgotten anything.
//
// Held as raw JSON rather than a struct, and that is the load-bearing decision. The
// document carries fields conflux has no opinion about -- telemetrySecret,
// bootstrap, genesis, renewalAuth, and whatever the API adds next -- and anchor
// reads them even though conflux does not. Round-tripping through a struct with
// only the known fields would delete the rest on the first renewal, and the anchor
// would come back after the next reboot with no bootstrap list and no telemetry.
type Manifest struct {
	raw map[string]json.RawMessage
}

// Decode parses an envelope and checks it is the kind of document conflux can use.
func Decode(env config.Envelope) (*Manifest, error) {
	b, err := base64.StdEncoding.DecodeString(string(env))
	if err != nil {
		// Tolerate a padding-free encoding rather than fail on a detail.
		b, err = base64.RawStdEncoding.DecodeString(string(env))
		if err != nil {
			return nil, fmt.Errorf("the stored credential is not base64: %w", err)
		}
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

	if id, _ := m.string("identity"); id == "" {
		return nil, fmt.Errorf("the credential carries no identity")
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

// IssuedAt is when it was signed, and the other end of the window the renewal
// timer divides.
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
// flag decides in practice. Read here only so status can say what was shipped.
func (m *Manifest) Taints() []string {
	var out []string

	if v, ok := m.raw["taints"]; ok {
		_ = json.Unmarshal(v, &out)
	}

	return out
}

// Bootstrap is the peer list the issuer supplied.
func (m *Manifest) Bootstrap() []string {
	var out []string

	if v, ok := m.raw["bootstrap"]; ok {
		_ = json.Unmarshal(v, &out)
	}

	return out
}

// SetChain splices a renewed credential into the document, changing those two
// fields and nothing else.
//
// This has to happen on every successful renewal, not just the hot install into the
// running anchor. `anchorctl renew` swaps the chain in memory; if the document on
// disk still holds the old one, the next reboot starts from a stale chain -- and if
// the machine was off for longer than the original window, from an expired one, at
// a moment when nobody is watching.
//
// chain is the raw credential bytes. The API sends base64 and this stores base64,
// but the file anchorctl -cred reads wants the raw bytes, so exactly one of the two
// call sites decodes and it is not this one.
func (m *Manifest) SetChain(chain []byte, notAfter time.Time) error {
	encoded, err := json.Marshal(base64.StdEncoding.EncodeToString(chain))
	if err != nil {
		return err
	}

	when, err := json.Marshal(notAfter.UTC().Format(ManifestTime))
	if err != nil {
		return err
	}

	m.raw["chain"] = encoded
	m.raw["notAfter"] = when

	return nil
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

// time parses one of the document's timestamps, accepting the exact layout anchor
// writes and plain RFC3339 as well, since a second issuer might not add the
// milliseconds. An unparseable or absent value is the zero time.
func (m *Manifest) time(key string) time.Time {
	s, err := m.string(key)
	if err != nil || s == "" {
		return time.Time{}
	}

	if t, err := time.Parse(ManifestTime, s); err == nil {
		return t.UTC()
	}

	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}

	return time.Time{}
}

// LogValue keeps the identity out of structured logs, the way Envelope keeps it out
// of fmt.
func (m *Manifest) LogValue() string { return "<anchor manifest, redacted>" }

// String does the same for fmt.
func (m *Manifest) String() string { return "<anchor manifest, redacted>" }
