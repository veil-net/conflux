// Package shelf fetches the anchor binaries from the published release manifest.
//
// The binaries are not in git -- fourteen release builds are about 284 MB -- and until
// now the only way to get them was a local anchor checkout, which is why CI ran on
// placeholders and eight tests skipped on every machine but a developer's.
//
// The shelf is the answer that needs no credential. What it serves is what conflux
// already ships: `//go:embed` puts these bytes inside every published conflux, so a
// public shelf discloses nothing a release download does not. That is the whole reason
// this can be an unauthenticated GET rather than a token for a private repository --
// conflux needs anchor's *output*, and its output is not the secret. anchor's source
// stays where it is.
//
// What is fetched is the *pinned* build. An anchor pinned to the genesis realm refuses
// to handshake with any other tree, which is the property worth having and the one a
// local `make dist` cannot give.
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
	// DefaultURL is where the manifest lives. Overridable so a dev shelf can be
	// pointed at, and deliberately not a value any *runtime* path reads: this is a
	// build-time source for bytes, not a thing a running conflux ever contacts.
	DefaultURL = "https://api.veilnet.com.au/anchor/release"

	// insecureEnv permits a plain-http shelf, for a test server. Named to match
	// internal/enrol's own override rather than inventing a second spelling.
	insecureEnv = "CONFLUX_ALLOW_INSECURE_API"

	// formatVersion is the manifest shape this understands. A future version may
	// mean anything, so an unknown one is refused rather than guessed at -- the same
	// rule internal/enrol applies to a manifest it does not recognise.
	formatVersion = 1

	// maxManifest bounds the JSON; maxBinary bounds one download. An anchord is
	// about 30 MB and anchorctl about 14, so 200 MB is far above anything real and
	// far below anything that could fill a disk before the write fails.
	maxManifest = 1 << 20
	maxBinary   = 200 << 20

	manifestTimeout = 30 * time.Second
	binaryTimeout   = 10 * time.Minute
)

// Binary is one entry in the manifest.
type Binary struct {
	Name    string `json:"name"`
	Program string `json:"program"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Bytes   int64  `json:"bytes"`
	SHA256  string `json:"sha256"`
	URL     string `json:"url"`
}

// Manifest is what the shelf serves.
type Manifest struct {
	FormatVersion int      `json:"formatVersion"`
	Pin           string   `json:"pin"`
	Binaries      []Binary `json:"binaries"`
}

// Fetch downloads every binary named by want into dir, verifying each against the
// digest the manifest gives for it.
//
// want is the set of file names conflux embeds -- "anchord-linux-amd64" and the other
// thirteen. It is passed in rather than derived here so that the list of targets stays
// in one place, scripts/anchor-bins.sh, which is also what prunes the directory.
func Fetch(ctx context.Context, base string, want []string, dir string, log func(string, ...any)) error {
	if err := checkScheme(base); err != nil {
		return err
	}

	m, err := manifest(ctx, base)
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
		// anchoradmin can mint realm roots. It has no business on a public shelf and
		// certainly none in anchor/bin, every file of which is a candidate for being
		// embedded into every conflux a user runs. Refused here rather than deleted
		// after the fact: if it is being served, that is worth stopping over.
		if b.Program == "anchoradmin" || strings.HasPrefix(b.Name, "anchoradmin") {
			return fmt.Errorf("the shelf is serving %q, which mints realm roots and must never be published", b.Name)
		}

		byName[b.Name] = b
	}

	log("shelf:   %s", base)
	log("realm:   %s", m.Pin)

	var missing []string

	for _, name := range want {
		if _, ok := byName[name]; !ok {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)

		return fmt.Errorf("the shelf serves %d of the %d binaries conflux embeds; missing:\n  %s",
			len(want)-len(missing), len(want), strings.Join(missing, "\n  "))
	}

	for _, name := range want {
		b := byName[name]

		if err := download(ctx, base, b, filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		log("  ok   %-28s %5.1f MB  %s", name, float64(b.Bytes)/(1<<20), b.SHA256[:12])
	}

	return nil
}

func manifest(ctx context.Context, base string) (*Manifest, error) {
	ctx, cancel := context.WithTimeout(ctx, manifestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client(base).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching the manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the shelf answered %s", resp.Status)
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
func download(ctx context.Context, base string, b Binary, dest string) error {
	if err := sameHost(base, b.URL); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, binaryTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.URL, nil)
	if err != nil {
		return err
	}

	resp, err := client(base).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the shelf answered %s", resp.Status)
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

func client(base string) *http.Client {
	u, _ := url.Parse(base)

	return &http.Client{
		// A download that follows a redirect to another host is one this did not
		// agree to. The digest would still have to match, so this is belt and
		// braces -- and cheap enough to keep, because the alternative is trusting
		// that the digest check is never the only thing standing up.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if u != nil && req.URL.Host != u.Host {
				return fmt.Errorf("refusing a redirect from %s to %s", u.Host, req.URL.Host)
			}

			if len(via) >= 5 {
				return errors.New("too many redirects")
			}

			return nil
		},
	}
}

// sameHost refuses a per-binary url that points somewhere other than the manifest.
//
// The manifest names its own download URLs, so a compromised or mistaken shelf could
// point them at a third party. The digest would catch substituted *content*; this
// catches conflux being made to fetch from somewhere it was never told about, which is
// worth refusing on its own.
func sameHost(base, raw string) error {
	b, err := url.Parse(base)
	if err != nil {
		return err
	}

	t, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a URL: %w", raw, err)
	}

	if t.Host != b.Host {
		return fmt.Errorf("the manifest points at %s, which is not the shelf at %s", t.Host, b.Host)
	}

	return checkScheme(raw)
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
