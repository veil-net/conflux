package enrol

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
)

// guardianDocument is what a self-hosted guardian issues: the same envelope, with
// a renewal endpoint on the operator's own API and a bearer minted for this one
// node. Field for field from guardian's docs/contracts/guardian-node.md.
//
// Note ipv4 and export, which conflux reads once at import and never again, and
// the absence of anything naming the alpha realm. The two documents share a format
// version because they are the same format; what differs is the issuer.
const guardianDocument = `{
  "formatVersion": 1,
  "kind": "anchor",
  "realm": "5c2e9b71aa03d4f6e8",
  "genesis": "0011223344556677",
  "identity": "99887766554433221100ffeeddccbbaa",
  "chain": "Z3VhcmRpYW4tY2hhaW4=",
  "notAfter": "2026-10-13T04:12:00.000Z",
  "taints": [],
  "useExit": false,
  "telemetrySecret": "cafebabe0123",
  "bootstrap": ["genesis-1.example.gov:4700", "genesis-2.example.gov:4700"],
  "renewalUrl": "https://guardian.example.gov/nodes/e3b0c442-98fc-1c14-9afb-f4c8996fb924/credential",
  "renewalAuth": "node-secret",
  "renewalSecret": "e3b0c442-98fc-1c14-9afb-f4c8996fb924.Zm91cnRlZW4tYnl0ZXM",
  "ipv4": "10.20.0.7/24",
  "issuedAt": "2026-09-13T04:12:00.000Z"
}`

const theBearer = "e3b0c442-98fc-1c14-9afb-f4c8996fb924.Zm91cnRlZW4tYnl0ZXM"

func manifest(t *testing.T, doc string) *Manifest {
	t.Helper()

	m, err := Decode(envelope(t, doc))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	return m
}

// TestAuthResolvesTheThreeStates is the whole of the scheme, read off a document.
func TestAuthResolvesTheThreeStates(t *testing.T) {
	for name, tc := range map[string]struct {
		doc    string
		scheme string
		secret string
	}{
		"the alpha realm says anchor-id": {alphaDocument, "", ""},
		"an older document says nothing": {alphaWithoutRenewalAuth, "", ""},
		"a guardian says node-secret":    {guardianDocument, AuthNodeSecret, theBearer},
	} {
		t.Run(name, func(t *testing.T) {
			auth, err := manifest(t, tc.doc).Auth()
			if err != nil {
				t.Fatalf("Auth: %v", err)
			}

			if auth.Scheme != tc.scheme {
				t.Errorf("Scheme = %q, want %q", auth.Scheme, tc.scheme)
			}

			if auth.Secret != tc.secret {
				t.Errorf("Secret = %q, want %q", auth.Secret, tc.secret)
			}
		})
	}
}

// TestNodeSecretSendsABearer checks the header that reaches the server, because
// that is the thing the contract is about.
func TestNodeSecretSendsABearer(t *testing.T) {
	expiry := time.Date(2026, 11, 13, 4, 12, 0, 0, time.UTC)
	c, s, got := record(t, fmt.Sprintf(`{"chain":%q,"notAfter":%q}`,
		base64.StdEncoding.EncodeToString([]byte("fresh")), expiry.Format(ManifestTime)))

	auth, err := manifest(t, guardianDocument).Auth()
	if err != nil {
		t.Fatalf("Auth: %v", err)
	}

	c.Auth = auth

	if _, err := c.Renew(t.Context(), s.URL+"/nodes/x/credential", "anchor1qxy"); err != nil {
		t.Fatalf("Renew: %v", err)
	}

	if want := "Bearer " + theBearer; got.authorization != want {
		t.Errorf("Authorization = %q, want %q", got.authorization, want)
	}

	// The body is unchanged from the alpha exchange. One request shape, two ways
	// of proving who is asking -- a second body would be a second protocol.
	if got.body != `{"anchorId":"anchor1qxy"}` {
		t.Errorf("body = %s", got.body)
	}
}

// TestUnknownRenewalAuthIsRefusedByName is the refusal, and it must name the value.
//
// firebase-id-token is in the list because traveller declares it for a device
// whose session is its credential. conflux has no session, so a conflux holding
// such a document has been handed the wrong one, and answering "unsupported" while
// sending an unauthenticated request would hide that.
func TestUnknownRenewalAuthIsRefusedByName(t *testing.T) {
	for _, scheme := range []string{"firebase-id-token", "mtls", "something-new"} {
		doc := strings.Replace(guardianDocument,
			`"renewalAuth": "node-secret"`, `"renewalAuth": "`+scheme+`"`, 1)

		_, err := manifest(t, doc).Auth()
		if err == nil {
			t.Errorf("Auth accepted renewalAuth %q", scheme)

			continue
		}

		if !strings.Contains(err.Error(), scheme) {
			t.Errorf("the refusal for %q does not name it: %v", scheme, err)
		}
	}
}

// TestNodeSecretWithoutASecretIsRefused covers the document that asks for a bearer
// and carries none. Sending nothing would look like the alpha path and be refused
// by the far end for a reason the message would not mention.
func TestNodeSecretWithoutASecretIsRefused(t *testing.T) {
	doc := strings.Replace(guardianDocument,
		`  "renewalSecret": "`+theBearer+`",`+"\n", "", 1)

	if _, err := manifest(t, doc).Auth(); err == nil {
		t.Fatal("Auth accepted node-secret with no renewalSecret")
	}
}

// TestDecodeAcceptsAnUnknownRenewalAuth pins where the refusal lives.
//
// Refusing at Decode would stop the anchor starting, so a machine handed a
// document naming a future scheme would go from "runs until its credential lapses"
// to "does not come up" -- worse for its operator and for every peer it carries.
func TestDecodeAcceptsAnUnknownRenewalAuth(t *testing.T) {
	doc := strings.Replace(guardianDocument,
		`"renewalAuth": "node-secret"`, `"renewalAuth": "invented-next-year"`, 1)

	if _, err := Decode(envelope(t, doc)); err != nil {
		t.Fatalf("Decode refused a document the anchor could still start from: %v", err)
	}
}

// TestTheSecretIsNotPrinted. The document already redacts itself, and the secret
// arriving inside it is exactly why that has to keep holding.
//
// All four spellings, and the two Sprintf ones are not redundant with String()
// even though fmt reaches String() to satisfy them today. What is being pinned is
// the spelling an operator or a future maintainer actually writes -- `log.Printf("%s", m)`
// -- and that is a different assertion from calling String() by hand: a Format
// method, or a String promoted from a pointer receiver onto a value, would change
// what the verb produces while String() went on being safe.
func TestTheSecretIsNotPrinted(t *testing.T) {
	m := manifest(t, guardianDocument)

	for name, s := range map[string]string{
		"String":   m.String(),
		"LogValue": m.LogValue(),
		"%v":       fmt.Sprintf("%v", m),
		// staticcheck is right that String() would produce this value; it is wrong
		// that this call should be it. The verb is the thing under test.
		//lint:ignore S1025 the %s path is the assertion, not a way to reach String()
		"%s": fmt.Sprintf("%s", m),
	} {
		if strings.Contains(s, theBearer) {
			t.Errorf("%s printed the renewal secret", name)
		}
	}
}

// TestRenewalSecretSurvivesARenewal. SetChain rewrites two fields; everything else
// in the document has to come back, and losing this one would cost the machine
// every renewal after the first.
func TestRenewalSecretSurvivesARenewal(t *testing.T) {
	m := manifest(t, guardianDocument)

	if err := m.SetChain([]byte("fresh"), time.Now()); err != nil {
		t.Fatalf("SetChain: %v", err)
	}

	env, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	auth, err := manifest(t, decoded(t, env)).Auth()
	if err != nil {
		t.Fatalf("Auth after a renewal: %v", err)
	}

	if auth.Secret != theBearer {
		t.Errorf("Secret = %q after a renewal, want %q", auth.Secret, theBearer)
	}
}

func decoded(t *testing.T, env config.Envelope) string {
	t.Helper()

	b, err := base64.StdEncoding.DecodeString(string(env))
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	return string(b)
}
