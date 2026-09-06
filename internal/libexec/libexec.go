// Package libexec puts the embedded anchor pair on disk so it can be run.
//
// The directory is content-addressed: <state>/bin/<setID>/, where setID hashes both
// binaries and the platform. That one decision removes four separate problems at
// once. An upgraded conflux writes a new directory instead of over the file a
// running anchord has open, so there is no ETXTBSY on Unix and no sharing violation
// on Windows. Two conflux processes racing produce the same path. A stale set is
// identifiable and sweepable. And "is it already extracted" is a stat rather than a
// hash of forty megabytes on every invocation.
//
// It is emphatically not os.TempDir(). The previous conflux wrote /tmp/anchor, which
// fails four ways for a service: systemd's PrivateTmp= gives the service a different
// /tmp than the CLI, so each extracts a copy the other cannot see; /tmp is noexec on
// hardened hosts; systemd-tmpfiles deletes it under a running daemon; and a
// LocalSystem service's %TEMP% is C:\Windows\Temp.
package libexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/paths"
)

// completeMarker is written last. Its presence is what distinguishes a finished
// directory from one a crash left half-written.
const completeMarker = ".complete"

// smokeTimeout bounds the one-off check that the extracted binary actually runs.
const smokeTimeout = 10 * time.Second

// Tools are the extracted pair.
type Tools struct {
	Dir       string
	Anchord   string
	Anchorctl string
	SetID     string
}

// Ensure extracts this build's pair if it is not already there, and returns the
// paths. Idempotent, atomic, and safe against another conflux doing the same thing.
func Ensure(d paths.Dirs) (*Tools, error) {
	if !anchor.Supported {
		return nil, fmt.Errorf(
			"this conflux was built for %s/%s and carries no anchor binaries for it", runtime.GOOS, runtime.GOARCH)
	}

	setID := anchor.SetID()
	root := d.Libexec()
	target := filepath.Join(root, setID)

	t := &Tools{
		Dir:       target,
		Anchord:   filepath.Join(target, exeName("anchord")),
		Anchorctl: filepath.Join(target, exeName("anchorctl")),
		SetID:     setID,
	}

	// The hot path: every conflux invocation reaches here, including a bare
	// pass-through, so it must not hash 43 MB.
	if t.complete() {
		return t, nil
	}

	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", root, err)
	}

	unlock, err := lock(filepath.Join(root, ".lock"))
	if err != nil {
		return nil, err
	}
	defer unlock()

	// Another process may have finished while we waited for the lock.
	if t.complete() {
		return t, nil
	}

	if err := extract(root, target, t); err != nil {
		return nil, err
	}

	if err := smoke(t); err != nil {
		return nil, err
	}

	go gc(root, setID)

	return t, nil
}

// complete reports whether the directory holds a finished extraction of exactly
// this pair. The sizes are checked as well as the marker, because a truncated write
// that still managed to place the marker is the one failure a marker alone misses.
func (t *Tools) complete() bool {
	if _, err := os.Stat(filepath.Join(t.Dir, completeMarker)); err != nil {
		return false
	}

	for path, want := range map[string]int{
		t.Anchord:   len(anchor.Anchord()),
		t.Anchorctl: len(anchor.Anchorctl()),
	} {
		fi, err := os.Stat(path)
		if err != nil || fi.Size() != int64(want) {
			return false
		}
	}

	return true
}

func extract(root, target string, t *Tools) error {
	staging, err := os.MkdirTemp(root, ".staging-*")
	if err != nil {
		return fmt.Errorf("create a staging directory in %s: %w", root, err)
	}

	defer os.RemoveAll(staging) // no-op once the rename has moved it

	if err := os.Chmod(staging, 0o700); err != nil {
		return fmt.Errorf("chmod %s: %w", staging, err)
	}

	for name, content := range map[string][]byte{
		exeName("anchord"):   anchor.Anchord(),
		exeName("anchorctl"): anchor.Anchorctl(),
	} {
		if err := writeExecutable(filepath.Join(staging, name), content); err != nil {
			return err
		}
	}

	marker := fmt.Sprintf("setID %s\nplatform %s/%s\n", t.SetID, runtime.GOOS, runtime.GOARCH)
	if err := os.WriteFile(filepath.Join(staging, completeMarker), []byte(marker), 0o600); err != nil {
		return fmt.Errorf("write the completion marker: %w", err)
	}

	if err := os.Rename(staging, target); err != nil {
		// Another conflux won the race between our lock check and here, which is
		// possible across a network filesystem where the lock is advisory only.
		if t.complete() {
			return nil
		}

		// Or the target exists and is incomplete -- a power cut mid-write, or a
		// truncated binary. Rename will not replace a non-empty directory, so the
		// debris has to go first. Safe here because we hold the lock, and because
		// an incomplete set is by definition one nothing is running from.
		if _, statErr := os.Stat(target); statErr == nil {
			if rmErr := os.RemoveAll(target); rmErr != nil {
				return fmt.Errorf("replace the incomplete extraction at %s: %w", target, rmErr)
			}

			if err := os.Rename(staging, target); err != nil {
				return fmt.Errorf("install %s: %w", target, err)
			}

			return nil
		}

		return fmt.Errorf("install %s: %w", target, err)
	}

	return nil
}

// writeExecutable writes one binary and closes it before anyone can exec it.
//
// The Close is not tidiness. On Linux, exec of a file that is still open for writing
// anywhere in the system fails with ETXTBSY, and a deferred Close inside a loop is
// exactly how that bug is usually written.
func writeExecutable(path string, content []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}

	if _, err := f.Write(content); err != nil {
		f.Close()

		return fmt.Errorf("write %s: %w", path, err)
	}

	if err := f.Sync(); err != nil {
		f.Close()

		return fmt.Errorf("sync %s: %w", path, err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}

	// macOS marks files written by a quarantined process, and an inherited
	// quarantine on a binary a daemon execs is a dialog nobody will ever see.
	clearQuarantine(path)

	return nil
}

// smoke runs the extracted anchorctl once, so that a filesystem which will not
// execute it says so here rather than at the point a daemon fails to start.
func smoke(t *Tools) error {
	ctx, cancel := context.WithTimeout(context.Background(), smokeTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, t.Anchorctl, "help").CombinedOutput()
	if err == nil {
		return nil
	}

	// A bare "permission denied" on a 0700 file owned by the caller is the most
	// confusing failure in this whole design, so name the two things that cause it.
	if errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "permission denied") {
		return fmt.Errorf("%s\n%s", cannotExecute(t.Dir), strings.TrimSpace(string(out)))
	}

	return fmt.Errorf("the extracted anchorctl in %s did not run: %w\n%s",
		t.Dir, err, strings.TrimSpace(string(out)))
}

// gc removes sets this conflux no longer uses. Best-effort throughout: a directory
// that will not go is a directory that is probably in use.
func gc(root, keep string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}

	cutoff := time.Now().Add(-24 * time.Hour)

	for _, e := range entries {
		if !e.IsDir() || e.Name() == keep {
			continue
		}

		info, err := e.Info()
		if err != nil {
			continue
		}

		// A staging directory older than an hour is the debris of a crash.
		if strings.HasPrefix(e.Name(), ".staging-") {
			if info.ModTime().Before(time.Now().Add(-time.Hour)) {
				os.RemoveAll(filepath.Join(root, e.Name()))
			}

			continue
		}

		if info.ModTime().Before(cutoff) {
			os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}

func exeName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}

	return base
}
