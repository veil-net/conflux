package enrol

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// This file pins what the public alpha realm already gets, so that adding a second
// issuer cannot quietly change it.
//
// conflux is deployed in the field against one issuer, and every machine out there
// renews unauthenticated because the alpha route is gated on nothing. The tests
// below assert that exchange byte for byte -- the header set, the absence of an
// Authorization header, and the request body -- rather than asserting that a
// renewal "works", which it would go on doing while sending something new.
//
// They were written before any of the guardian work landed, deliberately: a test
// added afterwards pins whatever the change produced, which is not the same thing
// as pinning what the field already runs.

// alphaWithoutRenewalAuth is the older shape, still on machines enrolled before the
// field was added. conflux has never read it, so a document lacking it and a
// document carrying "anchor-id" have to behave identically.
const alphaWithoutRenewalAuth = `{
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
  "bootstrap": ["genesis.veilnet.com.au:4700"],
  "renewalUrl": "https://api.veilnet.com.au/ghosts/alpha/renew",
  "issuedAt": "2026-09-06T04:12:00.000Z"
}`

// seen is what the server actually received, so an assertion can be about the
// request rather than about whether the call returned an error.
type seen struct {
	authorization string
	contentType   string
	accept        string
	userAgent     string
	body          string
}

func record(t *testing.T, reply string) (*Client, *httptest.Server, *seen) {
	t.Helper()

	got := &seen{}
	c, s := server(t, func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read the request body: %v", err)
		}

		got.authorization = r.Header.Get("Authorization")
		got.contentType = r.Header.Get("Content-Type")
		got.accept = r.Header.Get("Accept")
		got.userAgent = r.Header.Get("User-Agent")
		got.body = string(b)

		fmt.Fprint(w, reply)
	})

	return c, s, got
}

// TestAlphaRenewIsUnauthenticated is the one that matters.
//
// Both documents -- the one carrying `renewalAuth: "anchor-id"` and the one
// predating the field -- must produce a request with no Authorization header at
// all. Not an empty one, not a bearer of the AnchorID: absent.
func TestAlphaRenewIsUnauthenticated(t *testing.T) {
	expiry := time.Date(2026, 9, 20, 4, 12, 0, 0, time.UTC)
	reply := fmt.Sprintf(`{"chain":%q,"notAfter":%q}`,
		base64.StdEncoding.EncodeToString([]byte("chain")), expiry.Format(ManifestTime))

	for name, doc := range map[string]string{
		`renewalAuth "anchor-id"`: alphaDocument,
		"no renewalAuth at all":   alphaWithoutRenewalAuth,
	} {
		t.Run(name, func(t *testing.T) {
			// Decoded so the test fails if the document itself stops being one
			// conflux accepts, rather than passing while exercising nothing.
			if _, err := Decode(envelope(t, doc)); err != nil {
				t.Fatalf("Decode: %v", err)
			}

			c, s, got := record(t, reply)

			if _, err := c.Renew(t.Context(), s.URL+renewPath, "anchor1qxy"); err != nil {
				t.Fatalf("Renew: %v", err)
			}

			if got.authorization != "" {
				t.Errorf("Renew sent Authorization: %q -- the alpha route is gated on "+
					"nothing and every deployed machine renews without one",
					got.authorization)
			}

			if got.body != `{"anchorId":"anchor1qxy"}` {
				t.Errorf("body = %s, want {\"anchorId\":\"anchor1qxy\"}", got.body)
			}

			if got.contentType != "application/json" {
				t.Errorf("Content-Type = %q", got.contentType)
			}

			if got.accept != "application/json" {
				t.Errorf("Accept = %q", got.accept)
			}

			if !strings.HasPrefix(got.userAgent, "conflux/") {
				t.Errorf("User-Agent = %q, want a conflux/ prefix", got.userAgent)
			}
		})
	}
}

// TestAlphaEnrolIsUnauthenticated pins the other half. Enrolment cannot carry a
// credential by construction -- it is what draws one -- so a header appearing here
// would mean something was being sent that the caller does not yet have.
func TestAlphaEnrolIsUnauthenticated(t *testing.T) {
	c, _, got := record(t, fmt.Sprintf(`{"credentials":%q}`,
		base64.StdEncoding.EncodeToString([]byte(alphaDocument))))

	if _, err := c.Enrol(t.Context()); err != nil {
		t.Fatalf("Enrol: %v", err)
	}

	if got.authorization != "" {
		t.Errorf("Enrol sent Authorization: %q", got.authorization)
	}

	if got.body != "" {
		t.Errorf("Enrol sent a body: %q -- the route takes none", got.body)
	}
}
