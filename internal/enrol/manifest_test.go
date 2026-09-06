package enrol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
)

// alphaDocument is the shape POST /ghosts/alpha actually returns, field for field,
// from traveller's ghost.alpha.service.ts.
const alphaDocument = `{
  "formatVersion": 1,
  "kind": "anchor",
  "realm": "8f3a1c04be77d2e5aa",
  "genesis": "0011223344556677",
  "identity": "aabbccddeeff00112233445566778899",
  "chain": "Y2hhaW4tdmVyc2lvbi1vbmU=",
  "notAfter": "2026-09-13T04:12:00.000Z",
  "taints": [],
  "useExit": false,
  "telemetrySecret": "deadbeefcafe",
  "bootstrap": ["genesis.veilnet.com.au:4700", "203.0.113.9:4700"],
  "renewalUrl": "https://api.veilnet.com.au/ghosts/alpha/renew",
  "renewalAuth": "anchor-id",
  "issuedAt": "2026-09-06T04:12:00.000Z"
}`

func envelope(t *testing.T, doc string) config.Envelope {
	t.Helper()

	return config.Envelope(base64.StdEncoding.EncodeToString([]byte(doc)))
}

func TestDecodeAlpha(t *testing.T) {
	m, err := Decode(envelope(t, alphaDocument))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if got, want := m.NotAfter(), time.Date(2026, 9, 13, 4, 12, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("NotAfter() = %v, want %v", got, want)
	}

	if got, want := m.IssuedAt(), time.Date(2026, 9, 6, 4, 12, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("IssuedAt() = %v, want %v", got, want)
	}

	if got, want := m.RenewalURL(), "https://api.veilnet.com.au/ghosts/alpha/renew"; got != want {
		t.Errorf("RenewalURL() = %q, want %q", got, want)
	}

	if got := m.Taints(); len(got) != 0 {
		t.Errorf("Taints() = %v, want empty -- alpha ships the shared compartment", got)
	}

	if got := m.Bootstrap(); len(got) != 2 {
		t.Errorf("Bootstrap() = %v, want 2 entries", got)
	}
}

// TestSetChainIsLossless is the most important test here.
//
// A renewal rewrites the document on disk. If the rewrite went through a struct
// holding only the fields conflux models, it would silently drop telemetrySecret,
// bootstrap, genesis and renewalAuth -- and the anchor would come back after the
// next reboot with no peers to bootstrap from and no telemetry, days later, with
// nothing pointing at the renewal that caused it.
func TestSetChainIsLossless(t *testing.T) {
	m, err := Decode(envelope(t, alphaDocument))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	newChain := []byte("a freshly signed credential chain")
	newExpiry := time.Date(2026, 9, 20, 4, 12, 0, 0, time.UTC)

	if err := m.SetChain(newChain, newExpiry); err != nil {
		t.Fatalf("SetChain: %v", err)
	}

	env, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	before := decodeToMap(t, envelope(t, alphaDocument))
	after := decodeToMap(t, env)

	if len(before) != len(after) {
		t.Fatalf("the document has %d fields after a renewal and had %d before", len(after), len(before))
	}

	for k, want := range before {
		got, ok := after[k]
		if !ok {
			t.Errorf("field %q was dropped by the renewal", k)

			continue
		}

		if k == "chain" || k == "notAfter" {
			continue // the two that are meant to change
		}

		if string(got) != string(want) {
			t.Errorf("field %q changed from %s to %s and should not have", k, want, got)
		}
	}

	// And the two that were meant to change did.
	again, err := Decode(env)
	if err != nil {
		t.Fatalf("Decode after renewal: %v", err)
	}

	if got := again.NotAfter(); !got.Equal(newExpiry) {
		t.Errorf("NotAfter() = %v after renewal, want %v", got, newExpiry)
	}

	var chain string
	if err := json.Unmarshal(after["chain"], &chain); err != nil {
		t.Fatalf("chain is not a string: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(chain)
	if err != nil {
		t.Fatalf("chain is not base64: %v", err)
	}

	if string(raw) != string(newChain) {
		t.Errorf("chain = %q, want %q", raw, newChain)
	}
}

// TestUnknownFieldsSurvive is the same guarantee stated against a field that does
// not exist yet, which is the case that will actually happen.
func TestUnknownFieldsSurvive(t *testing.T) {
	doc := `{"formatVersion":1,"kind":"anchor","identity":"aa","chain":"YQ==",` +
		`"notAfter":"2026-09-13T04:12:00.000Z","issuedAt":"2026-09-06T04:12:00.000Z",` +
		`"somethingTheAPIAddsNextYear":{"nested":[1,2,3]}}`

	m, err := Decode(envelope(t, doc))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if err := m.SetChain([]byte("new"), time.Now()); err != nil {
		t.Fatalf("SetChain: %v", err)
	}

	env, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	after := decodeToMap(t, env)

	got, ok := after["somethingTheAPIAddsNextYear"]
	if !ok {
		t.Fatal("an unknown field was dropped by a renewal")
	}

	if string(got) != `{"nested":[1,2,3]}` {
		t.Errorf("the unknown field came back as %s", got)
	}
}

func TestDecodeRefusals(t *testing.T) {
	cases := map[string]string{
		"not base64":        "!!!!not base64!!!!",
		"not json":          base64.StdEncoding.EncodeToString([]byte("hello")),
		"a realm manifest":  base64.StdEncoding.EncodeToString([]byte(`{"formatVersion":1,"kind":"realm","key":"aa"}`)),
		"a future version":  base64.StdEncoding.EncodeToString([]byte(`{"formatVersion":2,"kind":"anchor","identity":"aa"}`)),
		"no identity":       base64.StdEncoding.EncodeToString([]byte(`{"formatVersion":1,"kind":"anchor"}`)),
		"an empty identity": base64.StdEncoding.EncodeToString([]byte(`{"formatVersion":1,"kind":"anchor","identity":""}`)),
		"no formatVersion":  base64.StdEncoding.EncodeToString([]byte(`{"kind":"anchor","identity":"aa"}`)),
	}

	for why, env := range cases {
		if _, err := Decode(config.Envelope(env)); err == nil {
			t.Errorf("Decode accepted %s", why)
		}
	}
}

// TestEnvelopeRedacts is a guard on the type, not the logger: as long as Envelope
// has these methods, no %v anywhere can put an identity seed in a log file.
func TestEnvelopeRedacts(t *testing.T) {
	env := envelope(t, alphaDocument)

	if got := env.String(); got != "<anchor manifest, redacted>" {
		t.Errorf("Envelope.String() = %q", got)
	}

	m, err := Decode(env)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if got := m.String(); got != "<anchor manifest, redacted>" {
		t.Errorf("Manifest.String() = %q", got)
	}
}

// decodeToMap returns each field's value in compacted form, so that comparing two
// documents compares what they say rather than how they were spaced -- the API
// pretty-prints and Encode does not, and that difference is not a lost field.
func decodeToMap(t *testing.T, env config.Envelope) map[string]json.RawMessage {
	t.Helper()

	b, err := base64.StdEncoding.DecodeString(string(env))
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	var out map[string]json.RawMessage
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("parse document: %v", err)
	}

	for k, v := range out {
		var buf bytes.Buffer
		if err := json.Compact(&buf, v); err != nil {
			t.Fatalf("compact %q: %v", k, err)
		}

		out[k] = json.RawMessage(buf.Bytes())
	}

	return out
}
