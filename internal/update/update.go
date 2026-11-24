// Package update replaces this conflux with the newest build of its channel for its platform:
// conflux's `latest` release for a release, the pre-release `dev-latest` for a dev build.
//
// Only when asked: `conflux update` is the one caller, and nothing checks on a schedule.
//
// # What vouches for what arrives
//
// The release document, which the API answers directly over TLS, gives the asset's
// SHA-256. The binary arrives through GitHub's redirect to its storage and is held to that
// digest before it is put anywhere it could run from, so bytes substituted past the API fail
// a compare. Nothing reads a URL out of a document: every request is built from this
// package's own constants, one API host, one repository and the channel's tag, and the asset is
// resolved by name within that one release.
//
// No credential. conflux is a public repository, so its releases are readable by anyone,
// and nothing here sends a token anywhere.
package update

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
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/config"
)

const (
	// DefaultAPI and DefaultRepo name where an update comes from.
	DefaultAPI  = "https://api.github.com"
	DefaultRepo = "veil-net/conflux"

	// ReleaseTag and DevTag are the two channels' tags, each of which release.yml moves to
	// the newest build of its branch: `latest` to version3's, the pre-release `dev-latest` to
	// dev's.
	ReleaseTag = "latest"
	DevTag     = "dev-latest"

	// maxRelease bounds the release document; maxBinary one download. A conflux is
	// 45 to 75 MB (the size gate in `make dist`), so 200 MB is far above anything real.
	maxRelease = 1 << 20
	maxBinary  = 200 << 20

	releaseTimeout = 30 * time.Second
	binaryTimeout  = 10 * time.Minute
)

// Source is where an update comes from. Zero fields take the defaults above.
type Source struct {
	API       string
	Repo      string
	UserAgent string
}

func (s Source) withDefaults() Source {
	if s.API == "" {
		s.API = DefaultAPI
	}

	if s.Repo == "" {
		s.Repo = DefaultRepo
	}

	s.API = strings.TrimSuffix(s.API, "/")

	return s
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

	src Source
	tag string
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

// Latest reads the release at tag, ReleaseTag or DevTag, and picks the platform's asset from
// it.
func Latest(ctx context.Context, src Source, tag, goos, goarch string) (*Release, error) {
	src = src.withDefaults()

	if err := config.CheckAPIURL(src.API); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, releaseTimeout)
	defer cancel()

	u := fmt.Sprintf("%s/repos/%s/releases/tags/%s", src.API, strings.Trim(src.Repo, "/"), url.PathEscape(tag))

	resp, err := do(ctx, src, u, "application/vnd.github+json")
	if err != nil {
		return nil, fmt.Errorf("looking up conflux's %s release: %w", tag, err)
	}
	defer resp.Body.Close()

	if err := statusErr(resp, src.Repo, tag); err != nil {
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

	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRelease)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("the release is not the JSON this expects: %w", err)
	}

	want := AssetName(goos, goarch)

	for _, a := range doc.Assets {
		if a.Name != want {
			continue
		}

		if a.State != "" && a.State != "uploaded" {
			return nil, fmt.Errorf("%s is in state %q on the %s release, so the release is not finished; try again shortly", a.Name, a.State, tag)
		}

		sum, ok := strings.CutPrefix(a.Digest, "sha256:")
		if !ok || len(sum) != sha256.Size*2 {
			return nil, fmt.Errorf("the %s release gives no SHA-256 for %s, so nothing would vouch for what arrives", tag, a.Name)
		}

		return &Release{
			Name:   doc.Name,
			Commit: doc.TargetCommitish,
			Asset:  a.Name,
			SHA256: strings.ToLower(sum),
			Bytes:  a.Size,
			src:    src,
			tag:    tag,
			id:     a.ID,
		}, nil
	}

	return nil, fmt.Errorf("the %s release has no %s, so there is no update for %s/%s", tag, want, goos, goarch)
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

// Download writes the release's binary into dir as a temporary file, executable and
// verified, and returns its path. The caller renames it into place or removes it.
//
// In dir because the rename that puts it in place must not cross a filesystem. Named with
// the platform's executable suffix, since Windows will not run a file without one.
func (r *Release) Download(ctx context.Context, dir string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, binaryTimeout)
	defer cancel()

	u := fmt.Sprintf("%s/repos/%s/releases/assets/%d", r.src.API, strings.Trim(r.src.Repo, "/"), r.id)

	resp, err := do(ctx, r.src, u, "application/octet-stream")
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", r.Asset, err)
	}
	defer resp.Body.Close()

	if err := statusErr(resp, r.src.Repo, r.tag); err != nil {
		return "", err
	}

	tmp, err := os.CreateTemp(dir, ".conflux-update-*"+filepath.Ext(r.Asset))
	if err != nil {
		return "", err
	}

	kept := false

	defer func() {
		if !kept {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()

	sum := sha256.New()

	n, err := io.Copy(io.MultiWriter(tmp, sum), io.LimitReader(resp.Body, maxBinary))
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", r.Asset, err)
	}

	if r.Bytes != 0 && n != r.Bytes {
		return "", fmt.Errorf("downloading %s: got %d bytes, the release says %d", r.Asset, n, r.Bytes)
	}

	if got := hex.EncodeToString(sum.Sum(nil)); got != r.SHA256 {
		return "", fmt.Errorf("downloading %s: its SHA-256 is %s, the release says %s", r.Asset, got, r.SHA256)
	}

	if err := tmp.Chmod(0o755); err != nil {
		return "", err
	}

	if err := tmp.Sync(); err != nil {
		return "", err
	}

	if err := tmp.Close(); err != nil {
		return "", err
	}

	kept = true

	return tmp.Name(), nil
}

// Replace renames the file at src over dst, which is this conflux.
//
// A rename, so a process running dst keeps the file it has. Windows will not replace the
// image of a running process but will rename it, so there dst is moved aside to dst.old
// first, which the next update removes. The same way service.Place replaces the boot
// service's copy.
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

func do(ctx context.Context, src Source, u, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	if src.UserAgent != "" {
		req.Header.Set("User-Agent", src.UserAgent)
	}

	return httpClient.Do(req)
}

// statusErr turns the codes this meets into a sentence somebody can act on.
func statusErr(resp *http.Response, repo, tag string) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil

	case http.StatusForbidden, http.StatusTooManyRequests:
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return errors.New("GitHub's limit on unauthenticated requests is reached for this address; try again within the hour")
		}

		return fmt.Errorf("GitHub refused the request (%s)", resp.Status)

	case http.StatusNotFound:
		return fmt.Errorf("%s has no release tagged %q (404)", repo, tag)

	default:
		return fmt.Errorf("GitHub answered %s", resp.Status)
	}
}

// httpClient follows GitHub's redirect from an asset to its storage, which is on another
// host, and refuses only a downgrade to plain http. What comes back is held to the digest
// the release document gave, so the hop is safe.
var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if err := config.CheckAPIURL(req.URL.String()); err != nil {
			return err
		}

		if len(via) >= 5 {
			return errors.New("too many redirects")
		}

		return nil
	},
}
