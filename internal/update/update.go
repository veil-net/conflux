// Package update replaces this conflux with the one conflux's `latest` release holds for
// its platform.
//
// Only when asked: `conflux update` is the one caller, and nothing checks on a schedule.
//
// # What vouches for what arrives
//
// The release document, which the API answers directly over TLS, gives the asset's
// SHA-256. The binary arrives through GitHub's redirect to its storage and is held to that
// digest before it is put anywhere it could run from, so bytes substituted past the API fail
// a compare. Nothing reads a URL out of a document: every request is built from this
// package's own constants, one API host, one repository and one tag, and the asset is
// resolved by name within that one release.
//
// No credential. conflux is a public repository, so its releases are readable by anyone,
// and nothing here sends a token anywhere.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/veil-net/conflux/internal/ghrelease"
	"github.com/veil-net/conflux/internal/httpsonly"
)

const (
	// DefaultRepo is the repository an update comes from, at ghrelease.DefaultTag,
	// `latest`. The tag moves: release.yml moves it to every build of version3. A dev build
	// is the pre-release `dev-latest`, which nothing here asks for, so an update always
	// lands on a release, a dev build's included.
	DefaultRepo = "veil-net/conflux"
)

// Source is where an update comes from. Zero fields take DefaultRepo and ghrelease's
// defaults.
type Source struct {
	API       string
	Repo      string
	Tag       string
	UserAgent string
}

// client is the release s names, as ghrelease reads it: the defaults filled in, this
// conflux's User-Agent on every request, and this package's sentences for a refusal.
func (s Source) client() ghrelease.Source {
	src := ghrelease.Source{API: s.API, Repo: s.Repo, Tag: s.Tag}.WithDefaults(DefaultRepo)

	if s.UserAgent != "" {
		src.Header = http.Header{"User-Agent": {s.UserAgent}}
	}

	src.Status = func(resp *http.Response) error { return statusErr(resp, src) }

	return src
}

// Release is what the release at the tag offers one platform.
type Release struct {
	// Name is the release's title, as release.yml writes it: "latest (1.1.0)".
	Name string

	// Commit is the commit it was built from.
	Commit string

	// Asset is the file for this platform, "conflux-linux-amd64" and so on, and SHA256
	// and Bytes are what the release document says of it.
	Asset  string
	SHA256 string
	Bytes  int64

	src ghrelease.Source
	id  int64
}

// AssetName is the file `make dist` builds for a platform.
func AssetName(goos, goarch string) string {
	name := "conflux-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}

	return name
}

// Latest reads the release at the source's tag and picks the platform's asset from it.
func Latest(ctx context.Context, s Source, goos, goarch string) (*Release, error) {
	src := s.client()

	if err := httpsonly.Check(src.API, ""); err != nil {
		return nil, err
	}

	var doc struct {
		Name            string `json:"name"`
		TargetCommitish string `json:"target_commitish"`
		Assets          []struct {
			ID     int64  `json:"id"`
			Name   string `json:"name"`
			Size   int64  `json:"size"`
			State  string `json:"state"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}

	if err := src.Lookup(ctx, &doc); err != nil {
		return nil, err
	}

	want := AssetName(goos, goarch)

	for _, a := range doc.Assets {
		if a.Name != want {
			continue
		}

		if a.State != "" && a.State != "uploaded" {
			return nil, fmt.Errorf("%s is in state %q on the %s release, so the release is not finished; try again shortly", a.Name, a.State, src.Tag)
		}

		sum, ok := strings.CutPrefix(a.Digest, "sha256:")
		if !ok || len(sum) != sha256.Size*2 {
			return nil, fmt.Errorf("the %s release gives no SHA-256 for %s, so nothing would vouch for what arrives", src.Tag, a.Name)
		}

		return &Release{
			Name:   doc.Name,
			Commit: doc.TargetCommitish,
			Asset:  a.Name,
			SHA256: strings.ToLower(sum),
			Bytes:  a.Size,
			src:    src,
			id:     a.ID,
		}, nil
	}

	return nil, fmt.Errorf("the %s release has no %s, so there is no update for %s/%s", src.Tag, want, goos, goarch)
}

// Is reports whether the file at path is this release's binary, byte for byte.
func (r *Release) Is(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return false, err
	}

	return hex.EncodeToString(sum.Sum(nil)) == r.SHA256, nil
}

// Download writes the release's binary into dir as a temporary file, executable, verified
// and synced to disk, and returns its path. The caller renames it into place or removes it.
//
// In dir because the rename that puts it in place must not cross a filesystem. Named with
// the platform's executable suffix, since Windows will not run a file without one.
func (r *Release) Download(ctx context.Context, dir string) (string, error) {
	a := ghrelease.Asset{ID: r.id, Bytes: r.Bytes, SHA256: r.SHA256}

	tmp, err := r.src.Download(ctx, a, dir, ".conflux-update-*"+filepath.Ext(r.Asset), true)
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", r.Asset, err)
	}

	return tmp, nil
}

// Replace renames the file at src over dst, which is this conflux.
//
// A rename, so a process running dst keeps the file it has. Windows will not replace the
// image of a running process but will rename it, so there dst is moved aside to dst.old
// first, which the next update removes. service.Place replaces the boot service's copy
// with it too.
func Replace(src, dst string) error {
	if err := os.Rename(src, dst); err == nil || runtime.GOOS != "windows" {
		return err
	}

	aside := dst + ".old"
	_ = os.Remove(aside)

	if err := os.Rename(dst, aside); err != nil {
		return err
	}

	if err := os.Rename(src, dst); err != nil {
		// This conflux is put back rather than leaving none at all.
		_ = os.Rename(aside, dst)

		return err
	}

	return nil
}

// statusErr turns the codes this meets into a sentence somebody can act on.
func statusErr(resp *http.Response, src ghrelease.Source) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil

	case http.StatusForbidden, http.StatusTooManyRequests:
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return errors.New("GitHub's limit on unauthenticated requests is reached for this address; try again within the hour")
		}

		return fmt.Errorf("GitHub refused the request (%s)", resp.Status)

	case http.StatusNotFound:
		return fmt.Errorf("%s has no release tagged %q (404)", src.Repo, src.Tag)

	default:
		return fmt.Errorf("GitHub answered %s", resp.Status)
	}
}
