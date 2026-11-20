// Package httpsonly is the rule every client conflux has holds a URL to: https, or plain
// http only where a test asks for it. The enrolment and renewal client (internal/enrol), the
// GitHub-release client (internal/ghrelease) and wintun's download (internal/wintun) check
// every redirect by it, through Redirects; enrol checks the URLs it is given, and ghrelease's
// callers (internal/update, internal/anchorrelease) the API base they hand it.
package httpsonly

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
)

// InsecureEnv permits a plain-http URL, for a test server.
const InsecureEnv = "CONFLUX_ALLOW_INSECURE_API"

// Check refuses a URL that is not https. Plain http passes where InsecureEnv is 1, for a
// test server; otherwise its refusal gives why, a caller's own reason, when there is one.
func Check(raw, why string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a URL: %w", raw, err)
	}

	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if os.Getenv(InsecureEnv) == "1" {
			return nil
		}

		if why != "" {
			why = "; " + why
		}

		return fmt.Errorf("%s is plain http%s (set %s=1 to override, for tests)", raw, why, InsecureEnv)
	default:
		return fmt.Errorf("%s has scheme %q, want https", raw, u.Scheme)
	}
}

// Redirects is a redirect policy, an http.Client's CheckRedirect: a redirect to the first
// request's host alone where sameHost asks for that, over https by Check, whose refusal
// gives why, and no more than max requests in all. The host is checked first, so a redirect
// to another host is refused as that whatever its scheme. It replaces net/http's own
// policy, that one's limit of ten included, so max is the only limit there is.
func Redirects(max int, sameHost bool, why string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if sameHost && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("refusing a redirect from %s to %s", via[0].URL.Host, req.URL.Host)
		}

		if err := Check(req.URL.String(), why); err != nil {
			return err
		}

		if len(via) >= max {
			return fmt.Errorf("stopped after %d requests", len(via))
		}

		return nil
	}
}
