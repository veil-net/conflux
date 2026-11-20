// Package httpsonly is the rule every client conflux has holds a URL to: https, or plain
// http only where a test asks for it. The enrolment and renewal client (internal/enrol)
// and the GitHub-release client (internal/ghrelease) both check by it.
package httpsonly

import (
	"fmt"
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
