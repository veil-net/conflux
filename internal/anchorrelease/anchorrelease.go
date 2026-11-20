// Package anchorrelease fetches the anchor binaries from a release of the anchor repository.
//
// The binaries are not in git -- fourteen release builds are hundreds of megabytes -- so a
// machine with no anchor checkout, which is every CI runner, fetches them from here.
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
// secrets to workflows triggered by fork pull requests, and every conflux job refuses fork
// pull requests outright, so the token is not reachable by anyone who does not already
// have write access to conflux.
//
// # Where a fetch can reach, and what vouches for what arrives
//
// Nothing here reads a URL out of a document. Every request is built from this package's
// own constants -- one API host, one repository, one tag -- and binaries are resolved by
// *asset name* within that single release. An asset download is answered with a redirect
// to GitHub's storage, which is followed; what makes that safe is that nothing fetched
// that way vouches for itself. The release document, which the API answers directly,
// gives each asset's SHA-256: manifest.json is held to it, and each binary to the digest
// manifest.json gives -- so substituted bytes anywhere past the API fail a compare.
package anchorrelease

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
	"sync"

	"github.com/veil-net/conflux/internal/ghrelease"
	"github.com/veil-net/conflux/internal/httpsonly"
)

const (
	// DefaultRepo, at ghrelease.DefaultTag, `latest`, is the whole of the contract with
	// anchor. The tag moves: it always names anchor's newest release build, which is the
	// intent -- conflux ships the newest anchor, not a remembered one. anchor also releases
	// each build at a dated tag, YYYYMMDD-HHMMSS, which stays, and each build of its dev
	// branch as the pre-release `dev-latest`, which conflux's dev embeds; -tag fetches
	// either. A release is asked for by its tag, so a pre-release is as reachable as any
	// other.
	DefaultRepo = "veil-net/anchor"

	// TokenEnv carries the credential. An environment variable and never a flag: a flag
	// is visible in `ps` to every other user on the machine, and lands in any CI log
	// that echoes the command it ran.
	TokenEnv = "ANCHOR_RELEASE_TOKEN"

	// manifestName is the asset that describes the others. Fetched first, and the only
	// asset whose name is known ahead of time.
	manifestName = "manifest.json"

	// formatVersion is the manifest shape this understands. A future version may mean
	// anything, so an unknown one is refused rather than guessed at -- the same rule
	// internal/enrol applies to a manifest it does not recognise.
	formatVersion = 1

	// maxManifest bounds the manifest, which describes fourteen files.
	maxManifest = 1 << 20
)

// Source is where the binaries come from. Zero fields take DefaultRepo and ghrelease's
// defaults, except Token, which has none.
type Source struct {
	API   string
	Repo  string
	Tag   string
	Token string
}

// client is the release s names, as ghrelease reads it: the defaults filled in, the token
// on every request, and this package's sentences for a refusal.
func (s Source) client() ghrelease.Source {
	src := ghrelease.Source{API: s.API, Repo: s.Repo, Tag: s.Tag}.WithDefaults(DefaultRepo)
	src.Header = http.Header{"Authorization": {"Bearer " + s.Token}}
	src.Status = func(resp *http.Response) error { return statusErr(resp, src) }

	return src
}

// Binary is one entry in the manifest.
//
// No URL. The name is what locates the file, as an asset of the release being read; see
// the package comment.
type Binary struct {
	Name    string `json:"name"`
	Program string `json:"program"`
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
	State string `json:"state"`

	// Digest is GitHub's "sha256:<hex>" of the asset, from the release document itself.
	Digest string `json:"digest"`
}

type release struct {
	TargetCommitish string  `json:"target_commitish"`
	Assets          []asset `json:"assets"`
}

// Fetch downloads every binary named by want into dir, verifying each against the digest
// the manifest gives for it.
//
// want is the set of file names conflux embeds -- "anchord-linux-amd64" and the other
// thirteen. It is passed in rather than derived here so that the list of targets stays in
// one place, scripts/anchor-bins.sh, which is also what prunes the directory.
func Fetch(ctx context.Context, s Source, want []string, dir string, log func(string, ...any)) error {
	src := s.client()

	if err := httpsonly.Check(src.API, ""); err != nil {
		return err
	}

	if s.Token == "" {
		return fmt.Errorf("no token: set %s to a GitHub token with Contents: read on %s", TokenEnv, src.Repo)
	}

	if !strings.Contains(strings.Trim(src.Repo, "/"), "/") {
		return fmt.Errorf("%q is not an owner/name repository", src.Repo)
	}

	var rel release
	if err := src.Lookup(ctx, &rel); err != nil {
		return err
	}

	assets := map[string]asset{}

	for _, a := range rel.Assets {
		// anchoradmin can mint realm roots. It has no business in a release and
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
		return fmt.Errorf("the release speaks manifest format %d and this conflux understands %d",
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

	log("release: %s @ %s", src.Repo, src.Tag)
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

		return fmt.Errorf("the release serves %d of the %d binaries conflux embeds; missing:\n  %s",
			len(want)-len(missing), len(want), strings.Join(missing, "\n  "))
	}

	// Every binary at once. Each is its own file, its own download and its own digest,
	// and taken one after another the fetch waits for the slowest part of the path
	// fourteen times over. The first failure stops the rest, and is the one reported.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error

		// staged is each binary downloaded and verified, by where it goes: moved there only
		// once every one has arrived, so a fetch that fails part way leaves the directory as
		// it found it, rather than one build's anchord beside another's anchorctl.
		staged = map[string]string{}
	)

	for _, name := range want {
		wg.Go(func() {
			b := byName[name]
			dest := filepath.Join(dir, name)

			// A file already there with the digest the manifest gives is this binary,
			// and is kept: a directory that survives between fetches -- a persistent
			// runner's cache -- then costs a read rather than a download. Anything
			// else is fetched.
			how := "cached"

			var (
				tmp string
				err error
			)

			if !matches(dest, b) {
				how = "fetched"
				a := ghrelease.Asset{ID: assets[name].ID, Bytes: b.Bytes, SHA256: b.SHA256}
				tmp, err = src.Download(ctx, a, filepath.Dir(dest), ".anchor-fetch-*", false)
			}

			mu.Lock()
			defer mu.Unlock()

			if tmp != "" {
				staged[dest] = tmp
			}

			switch {
			case err != nil && first == nil:
				first = fmt.Errorf("%s: %w", name, err)
				cancel()
			case err == nil:
				log("  ok   %-28s %5.1f MB  %s  %s", name, float64(b.Bytes)/(1<<20), b.SHA256[:12], how)
			}
		})
	}

	wg.Wait()

	for dest, tmp := range staged {
		if first == nil {
			if err := os.Rename(tmp, dest); err != nil {
				first = err
			}
		}

		_ = os.Remove(tmp) // gone once moved; what is left of a failed fetch otherwise
	}

	return first
}

// matches reports whether path already holds exactly the binary b describes.
func matches(path string, b Binary) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	if fi, err := f.Stat(); err != nil || (b.Bytes != 0 && fi.Size() != b.Bytes) {
		return false
	}

	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return false
	}

	return strings.EqualFold(hex.EncodeToString(sum.Sum(nil)), b.SHA256)
}

func manifest(ctx context.Context, src ghrelease.Source, assets map[string]asset) (*Manifest, error) {
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

	body, err := src.Read(ctx, a.ID, maxManifest)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", manifestName, err)
	}

	// The digests every binary is checked against are only as good as this one: it came
	// through the same redirect as the binaries, so it is held to the digest the release
	// document gives, which did not.
	want, ok := strings.CutPrefix(a.Digest, "sha256:")
	if !ok {
		return nil, fmt.Errorf("the release gives no SHA-256 for %s, so nothing vouches for the digests in it", manifestName)
	}

	if sum := sha256.Sum256(body); !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
		return nil, fmt.Errorf("%s is not the file the release lists: its SHA-256 differs from %s", manifestName, want)
	}

	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("the manifest is not the JSON this expects: %w", err)
	}

	return &m, nil
}

// statusErr turns the codes this actually meets into the sentence somebody can act on.
// A bare "404 Not Found" against a private repository is the least informative true
// statement available: it is what GitHub returns both for a tag that does not exist and
// for a token that cannot see the repository at all.
func statusErr(resp *http.Response, src ghrelease.Source) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil

	case http.StatusUnauthorized:
		return fmt.Errorf("GitHub refused the token (401). %s is set but not valid -- most often expired", TokenEnv)

	case http.StatusForbidden:
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return errors.New("GitHub rate limit reached (403)")
		}

		// A binary comes from the storage host the API redirects to, which is sent no token:
		// its 403 is the signed link it was given, most often expired, and nothing the token
		// grants or lacks.
		if api, err := url.Parse(src.API); err == nil && resp.Request != nil && resp.Request.URL.Host != api.Host {
			return fmt.Errorf("%s refused the download (403), which it does to a signed link once that has expired; fetch again",
				resp.Request.URL.Host)
		}

		return fmt.Errorf("GitHub refused the token (403). %s needs Contents: read on %s", TokenEnv, src.Repo)

	case http.StatusNotFound:
		return fmt.Errorf(
			"no release tagged %q in %s (404) -- or the token cannot see that repository at all, which GitHub reports the same way.\n"+
				"  Check: anchor's release.yml has published the %q tag, and %s grants Contents: read on %s",
			src.Tag, src.Repo, src.Tag, TokenEnv, src.Repo)

	default:
		return fmt.Errorf("GitHub answered %s", resp.Status)
	}
}
