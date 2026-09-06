package enrol

import (
	"bytes"
	"context"
	"crypto/tls"
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

	// enrolPath and the default renewal path. The renewal endpoint is normally read
	// out of the manifest instead; this is the fallback for a document that omits it.
	enrolPath = "/ghosts/alpha"
	renewPath = "/ghosts/alpha/renew"
)

// insecureEnv permits a plain-http base URL. Set only by tests, which point the
// client at an httptest server.
const insecureEnv = "CONFLUX_ALLOW_INSECURE_API"

// Client talks to the enrolment API.
type Client struct {
	// BaseURL is where enrolment happens. Empty means the production API.
	BaseURL string

	// HTTP is the transport. Nil means a sensible default.
	HTTP *http.Client

	// Now is the clock, injectable so the skew check is testable.
	Now func() time.Time
}

// Renewal is what the renew route hands back.
type Renewal struct {
	// Chain is the raw credential bytes, already base64-decoded. The API sends
	// base64 and the file `anchorctl renew -cred` reads wants raw bytes, so the
	// decoding happens here, once, rather than being got backwards at the call
	// site -- where it presents as a credential the daemon silently refuses.
	Chain []byte

	// NotAfter is when the new chain stops verifying.
	NotAfter time.Time
}

// SkewError means the local clock disagrees with the server's badly enough that
// nothing else will work. anchor's ALPN tag rotates hourly and a peer accepts one
// epoch either side, so an hour of skew is a TLS alert that looks exactly like a
// wrong realm -- worth its own error so the message can say "NTP" rather than
// leaving somebody to work it out from a handshake failure.
type SkewError struct{ By time.Duration }

func (e *SkewError) Error() string {
	return fmt.Sprintf(
		"this machine's clock is %s away from the server's; the overlay's handshake rotates hourly and will not connect.\n"+
			"  fix the clock first (timedatectl set-ntp true, or the equivalent), then try again",
		e.By.Round(time.Second))
}

// Skew is how far the clock was off on the last call, or zero.
var Skew time.Duration

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

	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 2,
		},
		// A credential request that follows a redirect to another host is a
		// credential request aimed somewhere conflux did not choose.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("refusing a redirect from %s to %s", via[0].URL.Host, req.URL.Host)
			}

			if len(via) >= 3 {
				return errors.New("too many redirects")
			}

			return nil
		},
	}
}

// Enrol draws a new identity and the credential that admits it.
//
// Called in exactly one place, when there is no manifest on disk. It must never be
// a fallback for a failed renewal: a new enrolment is a new identity, a new
// AnchorID and a new overlay address, and every peer that had the old one is
// orphaned with nothing said. The renewal route needs no fallback anyway -- it is
// checked against nothing and works after expiry.
func (c *Client) Enrol(ctx context.Context) (config.Envelope, error) {
	u := c.base() + enrolPath

	if err := checkScheme(u); err != nil {
		return nil, err
	}

	var out struct {
		Credentials string `json:"credentials"`
	}

	if err := c.do(ctx, http.MethodPost, u, nil, &out); err != nil {
		return nil, fmt.Errorf("enrol: %w", err)
	}

	if strings.TrimSpace(out.Credentials) == "" {
		return nil, errors.New("enrol: the server returned no credentials")
	}

	env := config.Envelope(strings.TrimSpace(out.Credentials))

	// Parse before the caller writes it, so a malformed document fails here rather
	// than at the next boot.
	if _, err := Decode(env); err != nil {
		return nil, fmt.Errorf("enrol: %w", err)
	}

	return env, nil
}

// Renew asks for a fresh chain for an anchor that already exists.
//
// renewalURL comes out of the stored manifest. It is checked against the base URL's
// host: the document is one conflux stores and re-reads, and a POST sent wherever a
// stored field points is a hole worth closing on the way in, even while the only
// thing writing that field is our own API.
func (c *Client) Renew(ctx context.Context, renewalURL, anchorID string) (Renewal, error) {
	if anchorID == "" {
		return Renewal{}, errors.New("renew: no AnchorID; the anchor has to have started at least once")
	}

	if !strings.HasPrefix(anchorID, "anchor") {
		return Renewal{}, fmt.Errorf("renew: %q is not an AnchorID", anchorID)
	}

	u := renewalURL
	if u == "" {
		u = c.base() + renewPath
	}

	if err := checkScheme(u); err != nil {
		return Renewal{}, err
	}

	if err := c.sameHostAsBase(u); err != nil {
		return Renewal{}, err
	}

	body, err := json.Marshal(map[string]string{"anchorId": anchorID})
	if err != nil {
		return Renewal{}, err
	}

	var out struct {
		Chain    string `json:"chain"`
		NotAfter string `json:"notAfter"`
	}

	if err := c.do(ctx, http.MethodPost, u, body, &out); err != nil {
		return Renewal{}, fmt.Errorf("renew: %w", err)
	}

	chain, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out.Chain))
	if err != nil {
		return Renewal{}, fmt.Errorf("renew: the returned chain is not base64: %w", err)
	}

	if len(chain) == 0 {
		return Renewal{}, errors.New("renew: the returned chain is empty")
	}

	notAfter, err := parseTime(out.NotAfter)
	if err != nil {
		return Renewal{}, fmt.Errorf("renew: %w", err)
	}

	return Renewal{Chain: chain, NotAfter: notAfter}, nil
}

func (c *Client) do(ctx context.Context, method, u string, body []byte, out any) error {
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
		return &HTTPError{Status: resp.StatusCode, Body: string(trim(b, 4096)), RetryAfter: retryAfter(resp)}
	}

	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("the response is not the JSON expected: %w", err)
	}

	return nil
}

// recordSkew notes how far off the local clock is. It does not fail the call --
// the call already worked -- but it gives `conflux status` and the up path
// something to refuse on.
func (c *Client) recordSkew(resp *http.Response) {
	served, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return
	}

	d := c.now().Sub(served)
	if d < 0 {
		d = -d
	}

	Skew = d
}

// CheckSkew is what the up path calls before doing anything expensive.
func CheckSkew(limit time.Duration) error {
	if Skew > limit {
		return &SkewError{By: Skew}
	}

	return nil
}

// HTTPError is a non-2xx, with enough of the body to be diagnosable and not so much
// that a hostile server can fill a terminal.
type HTTPError struct {
	Status     int
	Body       string
	RetryAfter time.Duration
}

func (e *HTTPError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("the server answered %d %s", e.Status, http.StatusText(e.Status))
	}

	return fmt.Sprintf("the server answered %d %s: %s", e.Status, http.StatusText(e.Status), e.Body)
}

// Temporary reports whether retrying could plausibly help. A 4xx that is not 408 or
// 429 will answer the same way forever.
func (e *HTTPError) Temporary() bool {
	return e.Status >= 500 || e.Status == http.StatusTooManyRequests || e.Status == http.StatusRequestTimeout
}

func retryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}

	if secs, err := time.ParseDuration(v + "s"); err == nil && secs > 0 {
		return secs
	}

	if when, err := http.ParseTime(v); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}

	return 0
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

func (c *Client) sameHostAsBase(raw string) error {
	target, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a URL: %w", raw, err)
	}

	base, err := url.Parse(c.base())
	if err != nil {
		return fmt.Errorf("the API base %q is not a URL: %w", c.base(), err)
	}

	if !strings.EqualFold(target.Host, base.Host) {
		return fmt.Errorf(
			"the stored credential names %s for renewal and this conflux is configured for %s; refusing to send it elsewhere",
			target.Host, base.Host)
	}

	return nil
}

func parseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, errors.New("the response has no expiry")
	}

	for _, layout := range []string{ManifestTime, time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("%q is not a timestamp this build recognises", s)
}

func trim(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}

	return b[:n]
}

// decodeJSON is a small helper the tests share with nothing; it exists so the test
// file needs no import of encoding/json for one call.
func decodeJSON(r io.Reader, v any) error {
	return json.NewDecoder(io.LimitReader(r, maxBody)).Decode(v)
}
