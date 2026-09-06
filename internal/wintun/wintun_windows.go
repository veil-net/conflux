//go:build windows

package wintun

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
)

const (
	downloadTimeout = 90 * time.Second

	// maxZip bounds the download. The real archive is a few hundred kilobytes.
	maxZip = 10 << 20
)

// Ensure places wintun.dll beside the extracted anchord.
//
// Beside the executable specifically, because that is the first path anchor's loader
// searches -- before the system directory, and never on the legacy search path that
// includes the working directory. It lives inside the content-addressed set
// directory, so an upgraded anchor pair fetches it again into its own directory,
// which is correct: the driver belongs next to the binary that loads it.
func Ensure(ctx context.Context, d paths.Dirs) error {
	dir := filepath.Join(d.Libexec(), anchor.SetID())
	target := filepath.Join(dir, DLLName)

	if ok, _ := present(target); ok {
		return nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	ui.Printf("  fetching wintun %s from wintun.net\n", Version)

	zipped, err := download(ctx)
	if err != nil {
		return offline(target, err)
	}

	dll, err := extractDLL(zipped)
	if err != nil {
		return offline(target, err)
	}

	if err := config.WriteFileAtomic(target, dll, 0o600); err != nil {
		return fmt.Errorf("install %s: %w", target, err)
	}

	ui.Printf("  installed %s\n", target)

	return nil
}

func present(path string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	// Only a length check on the hot path: the archive digest is what was verified,
	// and re-hashing the DLL on every start buys nothing once it is in place.
	return len(b) > 0, nil
}

func download(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ZipURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if r.URL.Host != via[0].URL.Host {
				return fmt.Errorf("refusing a redirect from %s to %s", via[0].URL.Host, r.URL.Host)
			}

			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wintun.net answered %s", resp.Status)
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, maxZip))
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != ZipSHA256 {
		return nil, fmt.Errorf(
			"the downloaded archive is not the pinned one.\n  expected sha256 %s\n  got      sha256 %s",
			ZipSHA256, got)
	}

	return b, nil
}

func extractDLL(zipped []byte) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(zipped), int64(len(zipped)))
	if err != nil {
		return nil, err
	}

	want := "wintun/bin/" + runtime.GOARCH + "/" + DLLName

	for _, f := range r.File {
		if f.Name != want {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()

		return io.ReadAll(io.LimitReader(rc, maxZip))
	}

	return nil, fmt.Errorf("the archive has no %s", want)
}

// offline says what to do by hand, and ends with the fallback that needs none of it.
func offline(target string, cause error) error {
	return fmt.Errorf(
		"a network interface on Windows needs wintun.dll, and it could not be fetched: %w\n\n"+
			"  Download wintun-%s.zip from https://www.wintun.net and put\n"+
			"  bin\\%s\\wintun.dll at:\n"+
			"    %s\n\n"+
			"  Or run \"conflux proxy PORT=BACKEND\", which needs no interface at all.",
		cause, Version, runtime.GOARCH, target)
}
