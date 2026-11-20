// Package ghrelease reads one release of one GitHub repository: conflux's own, for
// `conflux update` (internal/update), and anchor's, for a build (internal/anchorrelease).
//
// A leaf, importing nothing of conflux's: cmd/anchor-fetch reaches it through
// internal/anchorrelease, and has to run while anchor/bin is still empty.
package ghrelease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// DefaultAPI and DefaultTag are where a release is read from, and which: the tag
	// `latest`, which each caller's repository moves to its newest release.
	DefaultAPI = "https://api.github.com"
	DefaultTag = "latest"

	// InsecureEnv permits a plain-http URL, for a test server, in every client conflux has
	// (CheckScheme).
	InsecureEnv = "CONFLUX_ALLOW_INSECURE_API"

	// maxDocument bounds the release document, which lists a few dozen assets at most.
	maxDocument = 1 << 20

	documentTimeout = 30 * time.Second
)

// Source is one release, and how its requests are made: the API it is read from, the
// owner/name repository holding it, and its tag.
type Source struct {
	API  string
	Repo string
	Tag  string

	// Header is set on every request, beside Accept and the API version: a caller's token,
	// or its User-Agent.
	Header http.Header

	// Status turns an answer into the caller's sentence for it: nil for 200 OK, and
	// whatever somebody can act on for the codes that caller meets.
	Status func(*http.Response) error
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

// Lookup reads the release document at the tag into doc, which is the caller's own shape
// of it. Plain http is the caller's to refuse first (CheckScheme), in its own order.
//
// By tag rather than by GitHub's "latest", which is a heuristic over publication dates that
// a release cut by hand would win. A tag is exact.
func (s Source) Lookup(ctx context.Context, doc any) error {
	ctx, cancel := context.WithTimeout(ctx, documentTimeout)
	defer cancel()

	u := fmt.Sprintf("%s/repos/%s/releases/tags/%s", s.API, strings.Trim(s.Repo, "/"), url.PathEscape(s.Tag))

	resp, err := s.get(ctx, u, "application/vnd.github+json")
	if err != nil {
		return fmt.Errorf("looking up the %s release of %s: %w", s.Tag, s.Repo, err)
	}
	defer resp.Body.Close()

	if err := s.Status(resp); err != nil {
		return err
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDocument)).Decode(doc); err != nil {
		return fmt.Errorf("the release is not the JSON this expects: %w", err)
	}

	return nil
}

func (s Source) get(ctx context.Context, u, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range s.Header {
		req.Header[k] = v
	}

	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	return Client.Do(req)
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
		if err := CheckScheme(req.URL.String(), ""); err != nil {
			return err
		}

		if len(via) >= 5 {
			return errors.New("too many redirects")
		}

		return nil
	},
}

// CheckScheme refuses a URL that is not https. Plain http passes where InsecureEnv is 1,
// for a test server; otherwise its refusal gives why, a caller's own reason, when there is
// one. internal/enrol's client keeps this rule as well, with its own reason.
func CheckScheme(raw, why string) error {
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
