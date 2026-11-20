// Package ghrelease reads one release of one GitHub repository: conflux's own, for
// `conflux update` (internal/update), and anchor's, for a build (internal/anchorrelease).
//
// A leaf, importing nothing of conflux's: cmd/anchor-fetch reaches it through
// internal/anchorrelease, and has to run while anchor/bin is still empty.
package ghrelease

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	// DefaultAPI and DefaultTag are where a release is read from, and which: the tag
	// `latest`, which each caller's repository moves to its newest release.
	DefaultAPI = "https://api.github.com"
	DefaultTag = "latest"

	// InsecureEnv permits a plain-http URL, for a test server. The same override
	// internal/enrol reads.
	InsecureEnv = "CONFLUX_ALLOW_INSECURE_API"
)

// Source is one release: the API it is read from, the owner/name repository holding it,
// and its tag.
type Source struct {
	API  string
	Repo string
	Tag  string
}

// WithDefaults fills what is empty: DefaultAPI, repo and DefaultTag; and drops a trailing
// slash from the API.
func (s Source) WithDefaults(repo string) Source {
	if s.API == "" {
		s.API = DefaultAPI
	}

	if s.Repo == "" {
		s.Repo = repo
	}

	if s.Tag == "" {
		s.Tag = DefaultTag
	}

	s.API = strings.TrimSuffix(s.API, "/")

	return s
}

// Client is every request's. An asset is answered with a redirect to GitHub's storage, on
// another host, so a cross-host hop is expected and cannot be refused outright.
//
// Two things make that safe. Go drops the Authorization header on a redirect to another
// host, so a token never reaches the storage host. And nothing that comes back vouches for
// itself: what arrives is held to a digest that the release document, which the API
// answers directly, gave. What is refused is a downgrade to plain http, which would hand
// the bytes to anyone on the path, and a chain past five requests.
var Client = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if err := CheckScheme(req.URL.String()); err != nil {
			return err
		}

		if len(via) >= 5 {
			return errors.New("too many redirects")
		}

		return nil
	},
}

// CheckScheme refuses a URL that is not https. Plain http passes where InsecureEnv is 1,
// for a test server.
func CheckScheme(raw string) error {
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

		return fmt.Errorf("%s is plain http (set %s=1 to override, for tests)", raw, InsecureEnv)
	default:
		return fmt.Errorf("%s has scheme %q, want https", raw, u.Scheme)
	}
}
