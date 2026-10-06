package enrol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
)

// alphaTaint is the taint alphaDocument was enrolled in.
const alphaTaint = "brhk-2mq9-tzva-6pjs-k4xe-nw7d-qf"

// alphaDocument is the shape POST /ghosts/alpha returns for {"taints": [alphaTaint]},
// field for field and in the order the live API sends them. The key material is made up.
const alphaDocument = `{
  "formatVersion": 1,
  "kind": "anchor",
  "realm": "8f3a1c04be77d2e5aa",
  "genesis": "0011223344556677",
  "identity": "aabbccddeeff00112233445566778899",
  "chain": "Y2hhaW4tdmVyc2lvbi1vbmU=",
  "notAfter": "2026-10-06T04:12:00.000Z",
  "taints": ["brhk-2mq9-tzva-6pjs-k4xe-nw7d-qf"],
  "useExit": false,
  "bootstrap": ["genesis.veilnet.com.au:4700"],
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

	if got, want := m.NotAfter(), time.Date(2026, 10, 6, 4, 12, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("NotAfter() = %v, want %v", got, want)
	}

	if got, want := m.IssuedAt(), time.Date(2026, 9, 6, 4, 12, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("IssuedAt() = %v, want %v", got, want)
	}

	if got, want := m.RenewalURL(), "https://api.veilnet.com.au/ghosts/alpha/renew"; got != want {
		t.Errorf("RenewalURL() = %q, want %q", got, want)
	}

	if got := m.Taints(); len(got) != 1 || got[0] != alphaTaint {
		t.Errorf("Taints() = %v, want the one asked for, %q", got, alphaTaint)
	}

	if !m.Alpha() {
		t.Error("Alpha() = false for the alpha realm's document")
	}

	if got := m.Bootstrap(); len(got) != 1 {
		t.Errorf("Bootstrap() = %v, want the one entry", got)
	}
}

// TestWithRenewalIsLossless is the most important test here.
//
// A renewal rewrites the document on disk. If the rewrite went through a struct
// holding only the fields conflux models, it would silently drop genesis, realm,
// taints and renewalAuth -- and the anchor would come back after the next reboot
// unable to start, days later, with nothing pointing at the renewal that caused it.
func TestWithRenewalIsLossless(t *testing.T) {
	m, err := Decode(envelope(t, alphaDocument))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	r := Renewal{
		Chain:     []byte("a freshly signed credential chain"),
		NotAfter:  time.Date(2026, 10, 26, 4, 12, 0, 0, time.UTC),
		Bootstrap: []string{bootNode, bootAPI},
	}
	received := time.Date(2026, 9, 26, 4, 12, 0, 0, time.UTC)

	next, err := m.WithRenewal(r, received)
	if err != nil {
		t.Fatalf("WithRenewal: %v", err)
	}

	// The original is untouched: a caller whose write fails still holds it.
	if !m.NotAfter().Equal(time.Date(2026, 10, 6, 4, 12, 0, 0, time.UTC)) || len(m.Bootstrap()) != 1 {
		t.Errorf("WithRenewal changed the manifest it was called on: NotAfter() = %v", m.NotAfter())
	}

	env, err := next.Encode()
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

		switch k {
		case "chain", "notAfter", "issuedAt", "bootstrap":
			continue // the four that are meant to change
		}

		if string(got) != string(want) {
			t.Errorf("field %q changed from %s to %s and should not have", k, want, got)
		}
	}

	// And the four that were meant to change did. issuedAt moves with the chain, so
	// the window the next start divides is the renewed credential's own.
	again, err := Decode(env)
	if err != nil {
		t.Fatalf("Decode after renewal: %v", err)
	}

	if got := again.NotAfter(); !got.Equal(r.NotAfter) {
		t.Errorf("NotAfter() = %v after renewal, want %v", got, r.NotAfter)
	}

	if got := again.IssuedAt(); !got.Equal(received) {
		t.Errorf("IssuedAt() = %v after renewal, want %v", got, received)
	}

	if got := again.Bootstrap(); len(got) != 2 || got[0] != bootNode || got[1] != bootAPI {
		t.Errorf("Bootstrap() = %v after renewal, want the issuer's fresh list", got)
	}

	var chain string
	if err := json.Unmarshal(after["chain"], &chain); err != nil {
		t.Fatalf("chain is not a string: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(chain)
	if err != nil {
		t.Fatalf("chain is not base64: %v", err)
	}

	if string(raw) != string(r.Chain) {
		t.Errorf("chain = %q, want %q", raw, r.Chain)
	}
}

// TestWithRenewalKeepsTheBootstrapWhenNoneCame: an answer with no list conflux can use
// leaves the one the document has, rather than a machine with nowhere to start from.
func TestWithRenewalKeepsTheBootstrapWhenNoneCame(t *testing.T) {
	next, err := manifest(t, alphaDocument).WithRenewal(Renewal{Chain: []byte("c"), NotAfter: time.Now()}, time.Now())
	if err != nil {
		t.Fatalf("WithRenewal: %v", err)
	}

	if got := next.Bootstrap(); len(got) != 1 || got[0] != "genesis.veilnet.com.au:4700" {
		t.Errorf("Bootstrap() = %v, want the document's own list kept", got)
	}
}

// TestAlpha is read off the document: a credential that renews with no bearer.
func TestAlpha(t *testing.T) {
	for name, tc := range map[string]struct {
		doc   string
		alpha bool
	}{
		"the alpha realm":          {alphaDocument, true},
		"alpha, no renewalAuth":    {withoutRenewalAuth, true},
		"a guardian":               {guardianDocument, false},
		"a ghost realm node":       {ghostNodeDocument, false},
		"anchor's own, no renewal": {withoutRenewalFields(t, alphaDocument), false},
	} {
		if got := manifest(t, tc.doc).Alpha(); got != tc.alpha {
			t.Errorf("%s: Alpha() = %v, want %v", name, got, tc.alpha)
		}
	}
}

// TestCheckTaints is the rule every start and every `up` holds a machine to: the
// taints it is configured for are the ones its credential grants, or it is refused --
// with a way out that fits who issued the credential.
func TestCheckTaints(t *testing.T) {
	commons := strings.Replace(alphaDocument, `["`+alphaTaint+`"]`, "[]", 1)
	two := strings.Replace(alphaDocument, `["`+alphaTaint+`"]`, `["office","lab"]`, 1)

	for name, tc := range map[string]struct {
		doc  string
		want []string
		ok   bool
		says []string
	}{
		"the granted set":              {alphaDocument, []string{alphaTaint}, true, nil},
		"the granted set, repeated":    {alphaDocument, []string{alphaTaint, alphaTaint}, true, nil},
		"a set in another order":       {two, []string{"lab", "office"}, true, nil},
		"nothing asked: adopt":         {alphaDocument, nil, true, nil},
		"another taint":                {alphaDocument, []string{"other"}, false, []string{`"other"`, "uninstall", "conflux up --taint other"}},
		"one of two":                   {two, []string{"office"}, false, []string{"uninstall"}},
		"alpha granting none":          {commons, []string{"office"}, false, []string{"before the alpha realm granted", "conflux up --taint office"}},
		"alpha granting none, unasked": {commons, nil, false, []string{"shared compartment", "--taint TAINT"}},
		"issued granting none":         {guardianDocument, nil, true, nil},
		"issued, another taint":        {guardianDocument, []string{"office"}, false, []string{"enrol --manifest"}},
		"a ghost node's own":           {ghostNodeDocument, []string{"au"}, true, nil},
	} {
		err := manifest(t, tc.doc).CheckTaints(tc.want)

		if tc.ok {
			if err != nil {
				t.Errorf("%s: refused: %v", name, err)
			}

			continue
		}

		var te *TaintsError
		if !errors.As(err, &te) {
			t.Errorf("%s: got %v, want a *TaintsError", name, err)

			continue
		}

		for _, s := range tc.says {
			if !strings.Contains(err.Error(), s) {
				t.Errorf("%s: the refusal should say %q:\n%v", name, s, err)
			}
		}

		if te.Alpha && strings.Contains(err.Error(), "enrol --manifest") {
			t.Errorf("%s: an alpha machine was told to import a manifest:\n%v", name, err)
		}
	}
}

// TestUnknownFieldsSurvive is the same guarantee stated against a field that does
// not exist yet, which is the case that will actually happen.
func TestUnknownFieldsSurvive(t *testing.T) {
	doc := `{"formatVersion":1,"kind":"anchor","identity":"aa","genesis":"bb","chain":"YQ==",` +
		`"notAfter":"2026-09-13T04:12:00.000Z","issuedAt":"2026-09-06T04:12:00.000Z",` +
		`"somethingTheAPIAddsNextYear":{"nested":[1,2,3]}}`

	m, err := Decode(envelope(t, doc))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	next, err := m.WithRenewal(Renewal{Chain: []byte("new"), NotAfter: time.Now()}, time.Now())
	if err != nil {
		t.Fatalf("WithRenewal: %v", err)
	}

	env, err := next.Encode()
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

// TestDecodeRefusals is anchorctl's own gate (checkEnvelope and loadAnchorManifest):
// standard base64, format version 1, kind anchor, and an identity, genesis and chain.
func TestDecodeRefusals(t *testing.T) {
	b64 := func(doc string) string { return base64.StdEncoding.EncodeToString([]byte(doc)) }
	whole := `{"formatVersion":1,"kind":"anchor","identity":"aa","genesis":"bb","chain":"YQ=="}`

	if _, err := Decode(config.Envelope(b64(whole))); err != nil {
		t.Fatalf("Decode refused a whole document: %v", err)
	}

	cases := map[string]string{
		"not base64":        "!!!!not base64!!!!",
		"unpadded base64":   base64.RawStdEncoding.EncodeToString([]byte(whole + " ")), // a length that pads
		"not json":          b64("hello"),
		"a realm manifest":  b64(`{"formatVersion":1,"kind":"realm","key":"aa"}`),
		"a future version":  b64(`{"formatVersion":2,"kind":"anchor","identity":"aa","genesis":"bb","chain":"YQ=="}`),
		"no identity":       b64(`{"formatVersion":1,"kind":"anchor","genesis":"bb","chain":"YQ=="}`),
		"an empty identity": b64(`{"formatVersion":1,"kind":"anchor","identity":"","genesis":"bb","chain":"YQ=="}`),
		"no genesis":        b64(`{"formatVersion":1,"kind":"anchor","identity":"aa","chain":"YQ=="}`),
		"no chain":          b64(`{"formatVersion":1,"kind":"anchor","identity":"aa","genesis":"bb"}`),
		"no formatVersion":  b64(`{"kind":"anchor","identity":"aa","genesis":"bb","chain":"YQ=="}`),
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
