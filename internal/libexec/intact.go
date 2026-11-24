package libexec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths"
)

// verifiedMarker records the two binaries' files as a supervisor last found them holding
// this build's bytes: their sizes, times and identities, so the next start that finds them
// so compares a stat of each and reads neither.
const verifiedMarker = ".verified"

// Intact is Ensure for the supervisor, which runs what it extracts as root: the set it
// returns holds exactly this build's bytes. A binary changed on disk since -- by hand, or by
// anything else -- is found by its digest and the set extracted again. A set whose files are
// as they were when last held to the digests is found so by a stat of each, so a start reads
// fifty-odd megabytes only when something touched them.
//
// The CLI keeps Ensure's three stats: what it runs is anchorctl, as the caller, and status
// and pass-through are paid for on every invocation.
func Intact(d paths.Dirs) (*Tools, error) {
	t, err := Ensure(d)
	if err != nil {
		return nil, err
	}

	if t.verified() {
		return t, nil
	}

	if !t.digestsMatch() {
		if err := t.discard(d); err != nil {
			return nil, err
		}

		if t, err = Ensure(d); err != nil {
			return nil, err
		}

		if !t.digestsMatch() {
			return nil, fmt.Errorf("the anchor binaries extracted to %s do not hold this conflux's bytes", t.Dir)
		}
	}

	// A record that cannot be written costs the next start a read of the pair, nothing more.
	_ = config.WriteFileAtomic(filepath.Join(t.Dir, verifiedMarker), []byte(t.identities()), 0o600)

	return t, nil
}

// verified reports whether the pair's files are the ones last held to the digests.
func (t *Tools) verified() bool {
	b, err := os.ReadFile(filepath.Join(t.Dir, verifiedMarker))

	return err == nil && string(b) == t.identities()
}

// identities is the record of the pair's files as they are now, or "" for one that is gone.
func (t *Tools) identities() string {
	var b strings.Builder

	for _, p := range []string{t.Anchord, t.Anchorctl} {
		fi, err := os.Stat(p)
		if err != nil {
			return ""
		}

		fmt.Fprintf(&b, "%s %d %s\n", filepath.Base(p), fi.Size(), fileIdentity(fi))
	}

	return b.String()
}

// digestsMatch reports whether both binaries hold the bytes this build embeds, read side by
// side.
func (t *Tools) digestsMatch() bool {
	wantD, wantC := anchor.Digests()

	var (
		wg    sync.WaitGroup
		ctlOK bool
	)

	wg.Go(func() { ctlOK = fileDigest(t.Anchorctl) == wantC })

	ok := fileDigest(t.Anchord) == wantD

	wg.Wait()

	return ok && ctlOK
}

// discard removes the set, under the extraction lock, so the next Ensure writes it afresh.
func (t *Tools) discard(d paths.Dirs) error {
	unlock, err := flock.Acquire(filepath.Join(d.Libexec(), ".lock"))
	if err != nil {
		return err
	}
	defer unlock()

	if err := os.RemoveAll(t.Dir); err != nil {
		return fmt.Errorf("remove the changed extraction at %s: %w", t.Dir, err)
	}

	return nil
}

// fileDigest is the hex SHA-256 of the file at path, or "" where it cannot be read.
func fileDigest(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}

	return hex.EncodeToString(h.Sum(nil))
}
