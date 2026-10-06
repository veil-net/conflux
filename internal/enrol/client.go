package enrol

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/version"
)

const (
	// maxBody bounds what a compromised or confused server can make conflux hold
	// in memory. A manifest is a few kilobytes; a megabyte is generous.
	maxBody = 1 << 20

	// requestTimeout covers the whole exchange including TLS. Enrolment happens on
	// a path a user is watching, so it fails rather than hangs.
	requestTimeout = 30 * time.Second

	// enrolPath is the alpha realm's enrolment route. Renewal has no constant: the
	// route is whatever the manifest names, so the issuer of a credential is what is
	// asked to renew it.
	enrolPath = "/ghosts/alpha"

	// maxRedirects bounds a chain of same-host redirects.
	maxRedirects = 3
)

// insecureEnv permits a plain-http base URL. Set only by tests, which point the
// client at an httptest server.
const insecureEnv = "CONFLUX_ALLOW_INSECURE_API"

// defaultHTTP is the transport every Client shares unless given its own: Go's
// default, which keeps idle connections for a bounded time and honours a proxy in
// the environment, and redirects that stay on one host and on https.
var defaultHTTP = &http.Client{
	Timeout:   requestTimeout,
	Transport: http.DefaultTransport.(*http.Transport).Clone(),

	// A credential request that follows a redirect to another host is a credential
	// request aimed somewhere conflux did not choose, and one that follows it to
	// plain http hands a renewal bearer to the path. Go keeps an Authorization
	// header across a same-host redirect, so the scheme is checked as well.
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("refusing a redirect from %s to %s", via[0].URL.Host, req.URL.Host)
		}

		if err := checkScheme(req.URL.String()); err != nil {
			return err
		}

		if len(via) >= maxRedirects {
			return errors.New("too many redirects")
		}

		return nil
	},
}

// Client talks to the enrolment API.
type Client struct {
	// BaseURL is where enrolment happens. Empty means the production API.
	BaseURL string

	// HTTP is the transport. Nil means defaultHTTP.
	HTTP *http.Client

	// Now is the clock, injectable so the skew check is testable.
	Now func() time.Time

	// Auth is how a renewal identifies itself, resolved from the stored manifest
	// by Manifest.Auth. The zero value sends nothing, which is the alpha realm.
	// Enrol ignores it: enrolment is what draws a credential, so it cannot hold one.
	Auth Auth

	skew     time.Duration
	measured bool
}

// ErrNoTaints is an enrolment asked to request no compartment at all.
//
// The alpha realm's default compartment is the one every untainted device shares,
// which is what lets any user there reach any other; a machine somebody is joining to
// their own network is never put there, so the request is refused before it is sent.
var ErrNoTaints = errors.New(
	"enrol: no taint to ask for: the alpha realm's default compartment is shared with every untainted device, " +
		"and conflux never asks for it")

// Renewal is what the renew route hands back.
type Renewal struct {
	// Chain is the raw credential bytes, already base64-decoded. The API sends
	// base64 and the file `anchorctl renew -cred` reads wants raw bytes, so the
	// decoding happens here, once, rather than being got backwards at the call
	// site -- where it presents as a credential the daemon refuses, with nothing
	// saying the encoding is why.
	Chain []byte

	// NotAfter is when the new chain stops verifying.
	NotAfter time.Time

	// Bootstrap is the issuer's bootstrap list as of this renewal, or nil when the
	// answer carried none conflux can use -- absent, empty, or with an entry anchor
	// would skip. Nil keeps the manifest's own: a list is worth refreshing, never
	// worth failing a renewal over, and never worth replacing with part of one.
	Bootstrap []string
}

// SkewError means the local clock disagrees with the server's badly enough that
// nothing else will work: anchor refuses a credential that starts in its future, and
// further out the handshake itself fails, as a TLS alert that looks exactly like a
// wrong realm. Worth its own error so the message can say "NTP" rather than leaving
// somebody to work it out from a refused credential or a handshake failure.
type SkewError struct{ By time.Duration }

func (e *SkewError) Error() string {
	return fmt.Sprintf(
		"this machine's clock is %s away from the server's, and the overlay will not start or connect on it.\n"+
			"  fix the clock first (timedatectl set-ntp true, or the equivalent), then try again",
		e.By.Round(time.Second))
}

// CheckSkew refuses a measured skew past the limit.
func CheckSkew(skew, limit time.Duration) error {
	if skew > limit {
		return &SkewError{By: skew}
	}

	return nil
}

// Skew is how far this machine's clock was from the server's on this client's last
// call, and whether that call measured it at all.
func (c *Client) Skew() (time.Duration, bool) { return c.skew, c.measured }

func (c *Client) base() string {
	if c.BaseURL == "" {
		return config.DefaultAPIBaseURL
	}

	return strings.TrimRight(c.BaseURL, "/")
}

func (c *Client) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}

	return c.Now()
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}

	return defaultHTTP
}

// Enrol draws a new identity and the credential that admits it, in the compartments
// taints names.
//
// The credential commits to those taints, and anchor starts the identity under no
// others, so they are asked for here rather than chosen later: the first machine of a
// network asks for one conflux minted, and every machine joining it asks for the same.
// An empty set is ErrNoTaints, refused before anything is sent.
//
// Called in exactly one place, when there is no manifest on disk. It must never be
// a fallback for a failed renewal: a new enrolment is a new identity, a new
// AnchorID and a new overlay address, and every peer that had the old one is
// orphaned with nothing said.
//
// The envelope is returned as it arrived and not decoded here. It is the only copy of
// the identity in existence, so the caller writes it to disk before anything else is
// done with it -- a document this build cannot read is one a later conflux can, and
// discarding it would lose the identity for good.
func (c *Client) Enrol(ctx context.Context, taints []string) (config.Envelope, error) {
	if len(taints) == 0 {
		return nil, ErrNoTaints
	}

	if err := config.ValidateTaints(taints); err != nil {
		return nil, fmt.Errorf("enrol: %w", err)
	}

	u := c.base() + enrolPath

	if err := checkScheme(u); err != nil {
		return nil, err
	}

	body, err := json.Marshal(struct {
		Taints []string `json:"taints"`
	}{taints})
	if err != nil {
		return nil, err
	}

	var out struct {
		Credentials string `json:"credentials"`
	}

	// Auth{}, named rather than omitted. Enrolment is what draws a credential, so
	// there is nothing to present, and a client configured for a renewal must not
	// leak that configuration into the one call that happens before it exists.
	if err := c.do(ctx, http.MethodPost, u, body, Auth{}, &out); err != nil {
		return nil, fmt.Errorf("enrol: %w", err)
	}

	env := config.Envelope(strings.TrimSpace(out.Credentials))
	if len(env) == 0 {
		return nil, errors.New("enrol: the server returned no credentials")
	}

	return env, nil
}

// Renew asks for a fresh chain for an anchor that already exists, in the compartments
// taints names -- the ones its credential grants, read from the stored manifest.
//
// The issuer keeps no record of them to read back, and the running anchor refuses a
// chain granting any other set, so a renewal restates them; changing compartments is
// enrolling again. One body for every issuer: the alpha route reads it as it is, and a
// guardian reads the same with its bearer beside it.
//
// renewalURL comes out of the stored manifest. It is checked against the base URL's
// host: the document is one conflux stores and re-reads, and a POST sent wherever a
// stored field points is a hole worth closing on the way in.
func (c *Client) Renew(ctx context.Context, renewalURL, anchorID string, taints []string) (Renewal, error) {
	if anchorID == "" {
		return Renewal{}, errors.New("renew: no AnchorID; the anchor has to have started at least once")
	}

	if err := config.ValidateAnchorID(anchorID); err != nil {
		return Renewal{}, fmt.Errorf("renew: %w", err)
	}

	if renewalURL == "" {
		return Renewal{}, errors.New("renew: the credential names no renewal URL, so there is nowhere to renew it")
	}

	if err := checkScheme(renewalURL); err != nil {
		return Renewal{}, err
	}

	if err := SameHost(renewalURL, c.base()); err != nil {
		return Renewal{}, err
	}

	// [] rather than null for a credential that grants none: the route defaults a missing
	// list, not a null one.
	if taints == nil {
		taints = []string{}
	}

	body, err := json.Marshal(struct {
		AnchorID string   `json:"anchorId"`
		Taints   []string `json:"taints"`
	}{anchorID, taints})
	if err != nil {
		return Renewal{}, err
	}

	var out struct {
		Chain     string   `json:"chain"`
		NotAfter  string   `json:"notAfter"`
		Bootstrap []string `json:"bootstrap"`
	}

	if err := c.do(ctx, http.MethodPost, renewalURL, body, c.Auth, &out); err != nil {
		return Renewal{}, fmt.Errorf("renew: %w", err)
	}

	chain, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out.Chain))
	if err != nil {
		return Renewal{}, fmt.Errorf("renew: the returned chain is not base64: %w", err)
	}

	if len(chain) == 0 {
		return Renewal{}, errors.New("renew: the returned chain is empty")
	}

	notAfter, err := time.Parse(time.RFC3339, strings.TrimSpace(out.NotAfter))
	if err != nil {
		return Renewal{}, fmt.Errorf("renew: the returned expiry %q is not a timestamp", out.NotAfter)
	}

	return Renewal{Chain: chain, NotAfter: notAfter.UTC(), Bootstrap: usableBootstrap(out.Bootstrap)}, nil
}

// usableBootstrap is the list when every entry is one anchor would dial, and nil
// otherwise. See Renewal.Bootstrap.
func usableBootstrap(list []string) []string {
	if len(list) == 0 || config.ValidatePeers(list) != nil {
		return nil
	}

	return list
}

func (c *Client) do(ctx context.Context, method, u string, body []byte, auth Auth, out any) error {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	auth.apply(req)

	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
	}()

	c.recordSkew(resp)

	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("read the response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &HTTPError{Status: resp.StatusCode, Body: string(b[:min(len(b), 4096)])}
	}

	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("the response is not the JSON expected: %w", err)
	}

	return nil
}

// recordSkew notes how far off the local clock is. It does not fail the call -- the
// call already worked -- but it gives the caller something to refuse on.
func (c *Client) recordSkew(resp *http.Response) {
	served, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return
	}

	c.skew, c.measured = c.now().Sub(served).Abs(), true
}

// HTTPError is a non-2xx, with enough of the body to be diagnosable and not so much
// that a hostile server can fill a terminal.
type HTTPError struct {
	Status int
	Body   string
}

// Error names the status and what the server said. The API answers a refusal as
// {"message": ..., "error": ..., "statusCode": ...} -- the message a string, or a list
// of them when a request fails validation -- so the message is what is shown when there
// is one, and the body as it came otherwise.
func (e *HTTPError) Error() string {
	status := fmt.Sprintf("the server answered %d %s", e.Status, http.StatusText(e.Status))

	var refusal struct {
		Message json.RawMessage `json:"message"`
	}

	if json.Unmarshal([]byte(e.Body), &refusal) == nil {
		var one string
		var many []string

		switch {
		case json.Unmarshal(refusal.Message, &one) == nil && one != "":
			return status + ": " + one
		case json.Unmarshal(refusal.Message, &many) == nil && len(many) > 0:
			return status + ": " + strings.Join(many, "; ")
		}
	}

	if e.Body == "" {
		return status
	}

	return status + ": " + e.Body
}

func checkScheme(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a URL: %w", raw, err)
	}

	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if os.Getenv(insecureEnv) == "1" {
			return nil
		}

		return fmt.Errorf("%s is plain http; credentials are only fetched over https (set %s=1 to override, for tests)",
			raw, insecureEnv)
	default:
		return fmt.Errorf("%s has scheme %q, want https", raw, u.Scheme)
	}
}

// SameHost is the check that a stored field cannot redirect a POST.
//
// Exported because `conflux enrol` asks it too, before anything is written: a
// credential whose renewal URL names a host the configuration does not is one whose
// first renewal would be refused, months later -- so the question is asked while a
// person is present to fix it. One implementation, because two answers to one
// question means the more permissive of them is the way in.
func SameHost(renewalURL, apiBase string) error {
	target, err := url.Parse(renewalURL)
	if err != nil {
		return fmt.Errorf("%q is not a URL: %w", renewalURL, err)
	}

	base, err := url.Parse(apiBase)
	if err != nil {
		return fmt.Errorf("the API base %q is not a URL: %w", apiBase, err)
	}

	if !strings.EqualFold(target.Host, base.Host) {
		return fmt.Errorf(
			"the stored credential names %s for renewal and this conflux is configured for %s; refusing to send it elsewhere",
			target.Host, base.Host)
	}

	return nil
}

// BaseOf is the API base a renewal URL implies: scheme, host and port, nothing
// else.
//
// This is what makes --api an override on `conflux enrol` rather than a requirement.
// A manifest carries an absolute renewalUrl -- a self-hosted API is wherever its
// operator put it -- so the base is already in the document, and asking an operator
// to retype it buys a typo rather than a check. Only the origin is kept: a renewal URL
// is a path on an API, and treating the whole of it as a base would make every later
// request a child of one node's credential route.
func BaseOf(renewalURL string) (string, error) {
	u, err := url.Parse(renewalURL)
	if err != nil {
		return "", fmt.Errorf("%q is not a URL: %w", renewalURL, err)
	}

	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf(
			"%q is not an absolute URL, so the API it renews against cannot be read out of it", renewalURL)
	}

	return u.Scheme + "://" + u.Host, nil
}
