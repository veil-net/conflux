package enrol

import (
	"fmt"
	"net/http"
)

// How a renewal request says who it is: the manifest's renewalAuth.
//
// Two values conflux acts on, and a third answer for everything else:
//
//   - **absent, or "anchor-id"** -- no header. The alpha realm sends "anchor-id",
//     and anchor's own manifest format has no renewal fields at all, so the zero
//     Auth is the one that sends nothing. See alpha_test.go, which pins it.
//   - **"node-secret"** -- a bearer the issuer minted for this one node, carried
//     in the document beside the identity seed. A guardian's.
//   - **anything else** -- refused, naming the value.
//
// The refusal is the part worth arguing. The tempting alternative is to fall back
// to sending nothing, on the grounds that a renewal that might work beats one that
// certainly does not. It is the wrong trade: a node that quietly downgrades sends
// its request unauthenticated to an endpoint expecting proof, gets a 401, and
// reports a renewal failure that names a status code rather than the reason. There
// is no case where the downgrade succeeds, so it buys nothing and costs the
// diagnosis.
const (
	AuthAnchorID   = "anchor-id"
	AuthNodeSecret = "node-secret"
)

// Auth is the resolved scheme, ready to be put on a request.
type Auth struct {
	// Scheme is the manifest's renewalAuth, already checked. Empty means the
	// document did not say, which is the alpha realm and is not an error.
	Scheme string

	// Secret is the complete bearer value for AuthNodeSecret -- the whole
	// `<nodeId>.<secret>` string, sent verbatim.
	//
	// Whole, rather than the two halves for conflux to join with a dot. The
	// issuer composes it and conflux carries it, so there is exactly one place
	// that knows the shape and conflux is not it. The other arrangement means two
	// implementations of one format, and the more permissive of them is the way
	// in.
	Secret string
}

// apply puts the scheme's header on a request, or leaves it alone.
//
// Nothing is set for the alpha path, and the distinction between "no header" and
// "an empty header" matters: an empty Authorization is a header a proxy or a
// server may treat as a failed attempt rather than as no attempt.
func (a Auth) apply(req *http.Request) {
	if a.Scheme == AuthNodeSecret {
		req.Header.Set("Authorization", "Bearer "+a.Secret)
	}
}

// RenewalAuth is how the document says a renewal identifies itself. Empty when it
// does not say.
func (m *Manifest) RenewalAuth() string {
	s, _ := m.string("renewalAuth")

	return s
}

// RenewalSecret is the bearer value for the "node-secret" scheme.
//
// Read from the document and never from anywhere else. It is manifest material in
// exactly the sense the identity seed is: whoever holds it can keep this node's
// credential current indefinitely, which is why it does not get its own file, does
// not reach an argv, and is covered by the same redaction on String and GoString
// that hides the rest of the document.
func (m *Manifest) RenewalSecret() string {
	s, _ := m.string("renewalSecret")

	return s
}

// Auth resolves the document's scheme, or refuses it.
//
// Called at renewal rather than at Decode, and that is not an oversight. Refusing
// at Decode would stop the anchor starting at all, so a machine handed a document
// naming a scheme it does not implement would go from "renews until somebody
// upgrades it" to "does not come up" -- a strictly worse failure for the operator
// and for everything peered with it. The import verb checks it separately, because
// that is the one moment a person is present to read the message.
func (m *Manifest) Auth() (Auth, error) {
	switch scheme := m.RenewalAuth(); scheme {
	case "", AuthAnchorID:
		return Auth{}, nil

	case AuthNodeSecret:
		secret := m.RenewalSecret()
		if secret == "" {
			return Auth{}, fmt.Errorf(
				"the credential says renewalAuth %q and carries no renewalSecret; "+
					"it cannot renew and has to be reissued", scheme)
		}

		return Auth{Scheme: AuthNodeSecret, Secret: secret}, nil

	default:
		return Auth{}, fmt.Errorf(
			"the credential asks for renewalAuth %q and this conflux implements "+
				"%q and %q; upgrade conflux rather than renewing without it",
			scheme, AuthAnchorID, AuthNodeSecret)
	}
}
