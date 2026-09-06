package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteFileAtomic replaces path with data, or leaves what was there.
//
// A crash, a full disk or a kill between the open and the write must not produce a
// truncated conflux.json or -- far worse -- a truncated manifest.b64, which would
// destroy an identity that has no second copy. So: write a sibling temporary file,
// fsync it, rename over the target, then fsync the directory so the rename itself
// survives a power cut.
//
// The mode is set on the file descriptor before any content reaches it. Writing
// and then chmod'ing leaves a window in which the secret exists at the umask's
// mode, and on a shared machine that window is the whole vulnerability.
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) (err error) {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}

	tmpName := tmp.Name()

	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	// Explicitly, and before the write: CreateTemp is 0600 before umask, which is
	// neither reliably what we want nor reliably narrower.
	if err = tmp.Chmod(perm); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}

	// On Windows the chmod above is a no-op. Restrict by DACL instead, and do it
	// while the file is still empty and unnamed.
	if perm&0o077 == 0 {
		if err = restrictToAdmins(tmpName); err != nil {
			return fmt.Errorf("restrict %s: %w", tmpName, err)
		}
	}

	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", tmpName, err)
	}

	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}

	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}

	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpName, path, err)
	}

	// The rename is atomic but not yet durable. Failing to fsync the directory is
	// not worth losing the write over -- the data is in the page cache and the
	// common case is fine -- so this is best-effort everywhere it is unsupported.
	return syncDir(dir)
}

// syncDir makes a rename durable. Directories cannot be opened for read on
// Windows, and NTFS orders metadata itself, so there it does nothing.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) || errors.Is(err, errUnsupportedDirSync) {
			return nil
		}

		return nil //nolint:nilerr // durability is best-effort; the write succeeded
	}
	defer f.Close()

	if err := f.Sync(); err != nil {
		return nil //nolint:nilerr // EINVAL on some filesystems; harmless
	}

	return nil
}
