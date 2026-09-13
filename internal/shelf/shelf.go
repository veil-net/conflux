// Package shelf fetches the anchor binaries from a release of the anchor repository.
//
// The binaries are not in git -- fourteen release builds are about 284 MB -- and without
// a source for them CI ran on placeholders and eight tests skipped on every machine but
// a developer's.
//
// What is fetched is the *pinned* build. An anchor pinned to the genesis realm refuses to
// handshake with any other tree, which is the property worth having and the one a local
// `make dist` cannot give.
//
// # Why this needs a credential
//
// anchor is a private repository, and GitHub has no releases-only read scope: releases
// live under Contents, the same permission that grants the source. So the token conflux
// holds to read two binaries could also clone the repository, and that is the trade being
// made knowingly rather than by accident.
//
// It is acceptable for a reason worth stating rather than re-deriving: GitHub never passes
// secrets to workflows triggered by fork pull requests, and conflux's Linux jobs refuse
// fork pull requests outright, so the token is not reachable by anyone who does not
// already have write access to conflux.
//
// # What replaced the same-host rule
//
// An earlier version of this fetched a manifest that named a download URL per binary, and
// refused any URL whose host differed from the manifest's. That rule existed because a
// document conflux had just downloaded was deciding where conflux would fetch from next.
//
// Nothing here reads a URL out of a document. Every request is built from this package's
// own constants -- one API host, one repository, one tag -- and binaries are resolved by
// *asset name* within that single release. The set of places a fetch can reach is fixed by
// conflux's configuration rather than by anything on the wire, which is the stronger form
// of the same property.
package shelf

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
	"sort"
	"strings"
	"time"
)

const (
	// DefaultAPI, DefaultRepo and DefaultTag are the whole of the contract with anchor.
	// The tag moves: it always names anchor's newest release build, which is the intent
	// -- conflux ships the newest anchor, not a remembered one.
	DefaultAPI  = "https://api.github.com"
	DefaultRepo = "veil-net/anchor"
	DefaultTag  = "shelf"

	// TokenEnv carries the credential. An environment variable and never a flag: a flag
	// is visible in `ps` to every other user on the machine, and lands in any CI log
	// that echoes the command it ran.
	TokenEnv = "ANCHOR_RELEASE_TOKEN"

	// manifestName is the asset that describes the others. Fetched first, and the only
	// asset whose name is known ahead of time.
	manifestName = "manifest.json"

	// insecureEnv permits a plain-http API, for a test server. Named to match
	// internal/enrol's own override rather than inventing a second spelling.
	insecureEnv = "CONFLUX_ALLOW_INSECURE_API"

	// formatVersion is the manifest shape this understands. A future version may mean
	// anything, so an unknown one is refused rather than guessed at -- the same rule
	// internal/enrol applies to a manifest it does not recognise.
	formatVersion = 1

	// maxManifest bounds the JSON; maxBinary bounds one download. An anchord is about
	// 30 MB and anchorctl about 14, so 200 MB is far above anything real and far below
	// anything that could fill a disk before the write fails.
	maxManifest = 1 << 20
	maxBinary   = 200 << 20

	releaseTimeout = 30 * time.Second
	binaryTimeout  = 10 * time.Minute
)

// Source is where the binaries come from. Zero fields take the defaults above, except
// Token, which has none.
type Source struct {
	API   string
	Repo  string
	Tag   string
	Token string
}

func (s Source) withDefaults() Source {
	if s.API == "" {
		s.API = DefaultAPI
	}

	if s.Repo == "" {
		s.Repo = DefaultRepo
	}

	if s.Tag == "" {
		s.Tag = DefaultTag
	}

	s.API = strings.TrimSuffix(s.API, "/")

	return s
}

// Binary is one entry in the manifest.
//
// No URL. The name is what locates the file, as an asset of the release being read --
// see the package comment on what that replaced and why it is the stronger rule.
type Binary struct {
	Name    string `json:"name"`
	Program string `json:"program"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Bytes   int64  `json:"bytes"`
	SHA256  string `json:"sha256"`
}

// Manifest is the asset that describes the rest of them.
type Manifest struct {
	FormatVersion int      `json:"formatVersion"`
	Pin           string   `json:"pin"`
	Binaries      []Binary `json:"binaries"`
}

type asset struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	State string `json:"state"`
}

type release struct {
	ID              int64   `json:"id"`
	TagName         string  `json:"tag_name"`
	TargetCommitish string  `json:"target_commitish"`
	Assets          []asset `json:"assets"`
}

// Fetch downloads every binary named by want into dir, verifying each against the digest
// the manifest gives for it.
//
// want is the set of file names conflux embeds -- "anchord-linux-amd64" and the other
// thirteen. It is passed in rather than derived here so that the list of targets stays in
// one place, scripts/anchor-bins.sh, which is also what prunes the directory.
func Fetch(ctx context.Context, src Source, want []string, dir string, log func(string, ...any)) error {
	src = src.withDefaults()

	if err := checkScheme(src.API); err != nil {
		return err
	}

	if src.Token == "" {
		return fmt.Errorf("no token: set %s to a GitHub token with Contents: read on %s", TokenEnv, src.Repo)
	}

	if !strings.Contains(strings.Trim(src.Repo, "/"), "/") {
		return fmt.Errorf("%q is not an owner/name repository", src.Repo)
	}

	rel, err := lookup(ctx, src)
	if err != nil {
		return err
	}

	assets := map[string]asset{}

	for _, a := range rel.Assets {
		// anchoradmin can mint realm roots. It has no business on the shelf and
		// certainly none in anchor/bin, every file of which is a candidate for being
		// embedded into every conflux a user runs. Refused on sight of it in the
		// release, before anything is downloaded -- if it is being published, that is
		// worth stopping over rather than quietly not selecting.
		if strings.HasPrefix(a.Name, "anchoradmin") {
			return fmt.Errorf("the release carries %q, which mints realm roots and must never be published", a.Name)
		}

		if a.State != "" && a.State != "uploaded" {
			return fmt.Errorf("the asset %q is in state %q, so the release is not finished", a.Name, a.State)
		}

		assets[a.Name] = a
	}

	m, err := manifest(ctx, src, assets)
	if err != nil {
		return err
	}

	if m.FormatVersion != formatVersion {
		return fmt.Errorf("the shelf speaks manifest format %d and this conflux understands %d",
			m.FormatVersion, formatVersion)
	}

	if m.Pin == "" {
		return errors.New("the manifest carries no genesis pin, so nothing says which realm these are for")
	}

	byName := map[string]Binary{}

	for _, b := range m.Binaries {
		if b.Program == "anchoradmin" || strings.HasPrefix(b.Name, "anchoradmin") {
			return fmt.Errorf("the manifest describes %q, which mints realm roots and must never be published", b.Name)
		}

		byName[b.Name] = b
	}

	log("shelf:   %s @ %s", src.Repo, src.Tag)
	log("commit:  %s", rel.TargetCommitish)
	log("realm:   %s", m.Pin)

	var missing []string

	// Both, because they are different failures with the same remedy: a binary the
	// manifest never described, and one it described that was not attached.
	for _, name := range want {
		if _, ok := byName[name]; !ok {
			missing = append(missing, name+" (not in the manifest)")
			continue
		}

		if _, ok := assets[name]; !ok {
			missing = append(missing, name+" (in the manifest, not attached to the release)")
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)

		return fmt.Errorf("the shelf serves %d of the %d binaries conflux embeds; missing:\n  %s",
			len(want)-len(missing), len(want), strings.Join(missing, "\n  "))
	}

	for _, name := range want {
		b := byName[name]

		if err := download(ctx, src, assets[name], b, filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		log("  ok   %-28s %5.1f MB  %s", name, float64(b.Bytes)/(1<<20), b.SHA256[:12])
	}

	return nil
}

// lookup reads the release at the configured tag.
//
// By tag rather than by "latest": latest is a heuristic over publication dates that a
// real product release cut in anchor would win, and conflux would then embed something
// that was never meant for it. A tag is exact.
func lookup(ctx context.Context, src Source) (*release, error) {
	ctx, cancel := context.WithTimeout(ctx, releaseTimeout)
	defer cancel()

	u := fmt.Sprintf("%s/repos/%s/releases/tags/%s", src.API, strings.Trim(src.Repo, "/"), url.PathEscape(src.Tag))

	resp, err := do(ctx, src, u, "application/vnd.github+json")
	if err != nil {
		return nil, fmt.Errorf("looking up the release: %w", err)
	}
	defer resp.Body.Close()

	if err := statusErr(resp, src); err != nil {
		return nil, err
	}

	var rel release
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxManifest)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("the release is not the JSON this expects: %w", err)
	}

	return &rel, nil
}

func manifest(ctx context.Context, src Source, assets map[string]asset) (*Manifest, error) {
	a, ok := assets[manifestName]
	if !ok {
		names := make([]string, 0, len(assets))
		for n := range assets {
			names = append(names, n)
		}

		sort.Strings(names)

		return nil, fmt.Errorf("the release at %s has no %s, so nothing describes its %d asset(s): %s",
			src.Tag, manifestName, len(names), strings.Join(names, ", "))
	}

	ctx, cancel := context.WithTimeout(ctx, releaseTimeout)
	defer cancel()

	resp, err := do(ctx, src, assetURL(src, a), "application/octet-stream")
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", manifestName, err)
	}
	defer resp.Body.Close()

	if err := statusErr(resp, src); err != nil {
		return nil, err
	}

	var m Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxManifest)).Decode(&m); err != nil {
		return nil, fmt.Errorf("the manifest is not the JSON this expects: %w", err)
	}

	return &m, nil
}

// download writes one binary, verifying its digest before it is put in place.
//
// Into a temporary file next to the target and renamed, so an interrupted fetch cannot
// leave a half-written file that is a real binary of nearly the right size -- which is
// exactly the shape neither the size gate in `make dist` nor the header check in
// anchor.TestPairIsRealExecutables would catch.
func download(ctx context.Context, src Source, a asset, b Binary, dest string) error {
	ctx, cancel := context.WithTimeout(ctx, binaryTimeout)
	defer cancel()

	resp, err := do(ctx, src, assetURL(src, a), "application/octet-stream")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := statusErr(resp, src); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".anchor-fetch-*")
	if err != nil {
		return err
	}

	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	sum := sha256.New()

	n, err := io.Copy(io.MultiWriter(tmp, sum), io.LimitReader(resp.Body, maxBinary))
	if err != nil {
		return err
	}

	if b.Bytes != 0 && n != b.Bytes {
		return fmt.Errorf("got %d bytes, the manifest says %d", n, b.Bytes)
	}

	if got := hex.EncodeToString(sum.Sum(nil)); !strings.EqualFold(got, b.SHA256) {
		return fmt.Errorf("sha256 is %s, the manifest says %s", got, b.SHA256)
	}

	if err := tmp.Chmod(0o755); err != nil {
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), dest)
}

func assetURL(src Source, a asset) string {
	return fmt.Sprintf("%s/repos/%s/releases/assets/%d", src.API, strings.Trim(src.Repo, "/"), a.ID)
}

func do(ctx context.Context, src Source, u, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+src.Token)
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	return client().Do(req)
}

// statusErr turns the codes this actually meets into the sentence somebody can act on.
// A bare "404 Not Found" against a private repository is the least informative true
// statement available: it is what GitHub returns both for a tag that does not exist and
// for a token that cannot see the repository at all.
func statusErr(resp *http.Response, src Source) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil

	case http.StatusUnauthorized:
		return fmt.Errorf("GitHub refused the token (401). %s is set but not valid -- most often expired", TokenEnv)

	case http.StatusForbidden:
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return errors.New("GitHub rate limit reached (403)")
		}

		return fmt.Errorf("GitHub refused the token (403). %s needs Contents: read on %s", TokenEnv, src.Repo)

	case http.StatusNotFound:
		return fmt.Errorf(
			"no release tagged %q in %s (404) -- or the token cannot see that repository at all, which GitHub reports the same way.\n"+
				"  Check: anchor's ci.yml has published the %q tag, and %s grants Contents: read on %s",
			src.Tag, src.Repo, src.Tag, TokenEnv, src.Repo)

	default:
		return fmt.Errorf("GitHub answered %s", resp.Status)
	}
}

func client() *http.Client {
	return &http.Client{
		// An asset download answers with a redirect to storage on another host, so
		// unlike the manifest-and-URL scheme this replaced, a cross-host hop is
		// expected and cannot be refused outright.
		//
		// Two things make that safe. Go drops the Authorization header on a redirect
		// to a different host, so the token never reaches the storage host. And the
		// digest is checked against a manifest fetched from the API, so content
		// substituted anywhere along the way fails the compare.
		//
		// What is still refused is a downgrade: a redirect to plain http, which would
		// hand the bytes to anyone on the path.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if err := checkScheme(req.URL.String()); err != nil {
				return err
			}

			if len(via) >= 5 {
				return errors.New("too many redirects")
			}

			return nil
		},
	}
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

		return fmt.Errorf("%s is plain http (set %s=1 to override, for tests)", raw, insecureEnv)
	default:
		return fmt.Errorf("%s has scheme %q, want https", raw, u.Scheme)
	}
}
