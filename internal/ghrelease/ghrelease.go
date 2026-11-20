// Package ghrelease reads one release of one GitHub repository: conflux's own, for
// `conflux update` (internal/update), and anchor's, for a build (internal/anchorrelease).
//
// Nothing here reads a URL out of a document. Every request is built from the Source, and
// an asset is asked for by its id in that release's own document. Each caller holds what
// arrives to a digest from something that did not come through GitHub's storage.
//
// Nothing it imports embeds anything (httpsonly is its one import of conflux's, a leaf):
// cmd/anchor-fetch reaches it through internal/anchorrelease, and has to run while
// anchor/bin is still empty.
package ghrelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/httpsonly"
)

const (
	// DefaultAPI and DefaultTag are where a release is read from, and which: the tag
	// `latest`, which each caller's repository moves to its newest release.
	DefaultAPI = "https://api.github.com"
	DefaultTag = "latest"

	// maxDocument bounds the release document, which lists a few dozen assets at most;
	// maxAsset one download, far above any conflux or anchor binary and far below anything
	// that could fill a disk before the write fails.
	maxDocument = 1 << 20
	maxAsset    = 200 << 20

	documentTimeout = 30 * time.Second
	assetTimeout    = 10 * time.Minute
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
// of it. Plain http is the caller's to refuse first (httpsonly.Check), in its own order.
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

// Asset is one file of the release, by its id in the release document, and what vouches
// for it: its size, 0 for unknown, and its SHA-256, hex, from something that did not come
// through GitHub's storage.
type Asset struct {
	ID     int64
	Bytes  int64
	SHA256 string
}

// Download writes the asset into a new temporary file in dir, named by pattern as
// os.CreateTemp names one, and returns its path once it holds the size and SHA-256 given,
// executable. sync puts it on disk before then. The caller renames it into place or
// removes it; a download that fails leaves nothing.
//
// A temporary file, so an interrupted download cannot leave a half-written file that is a
// real binary of nearly the right size: the shape neither the size gate in `make dist` nor
// the header check in anchor.TestPairIsRealExecutables would catch.
func (s Source) Download(ctx context.Context, a Asset, dir, pattern string, sync bool) (path string, err error) {
	ctx, cancel := context.WithTimeout(ctx, assetTimeout)
	defer cancel()

	resp, err := s.get(ctx, s.assetURL(a.ID), "application/octet-stream")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if err := s.Status(resp); err != nil {
		return "", err
	}

	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}

	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()

	sum := sha256.New()

	n, err := io.Copy(io.MultiWriter(tmp, sum), io.LimitReader(resp.Body, maxAsset))
	if err != nil {
		return "", err
	}

	if a.Bytes != 0 && n != a.Bytes {
		return "", fmt.Errorf("got %d bytes, not the %d listed", n, a.Bytes)
	}

	if got := hex.EncodeToString(sum.Sum(nil)); !strings.EqualFold(got, a.SHA256) {
		return "", fmt.Errorf("its SHA-256 is %s, not the %s listed", got, a.SHA256)
	}

	if err := tmp.Chmod(0o755); err != nil {
		return "", err
	}

	if sync {
		if err := tmp.Sync(); err != nil {
			return "", err
		}
	}

	if err := tmp.Close(); err != nil {
		return "", err
	}

	return tmp.Name(), nil
}

// Read answers the bytes of a small asset, at most max of them. What vouches for them is
// the caller's to check.
func (s Source) Read(ctx context.Context, id, max int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, documentTimeout)
	defer cancel()

	resp, err := s.get(ctx, s.assetURL(id), "application/octet-stream")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := s.Status(resp); err != nil {
		return nil, err
	}

	return io.ReadAll(io.LimitReader(resp.Body, max))
}

func (s Source) assetURL(id int64) string {
	return fmt.Sprintf("%s/repos/%s/releases/assets/%d", s.API, strings.Trim(s.Repo, "/"), id)
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

	return client.Do(req)
}

// client is every request's. An asset is answered with a redirect to GitHub's storage, on
// another host, so a cross-host hop is expected and cannot be refused outright.
//
// Two things make that safe. Go drops the Authorization header on a redirect to another
// host, so a token never reaches the storage host. And nothing that comes back vouches for
// itself: what arrives is held to a digest that the release document, which the API
// answers directly, gave. What is refused is a downgrade to plain http, which would hand
// the bytes to anyone on the path, and a chain past five requests.
var client = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if err := httpsonly.Check(req.URL.String(), ""); err != nil {
			return err
		}

		if len(via) >= 5 {
			return errors.New("too many redirects")
		}

		return nil
	},
}
