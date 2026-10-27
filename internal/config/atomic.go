package config

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/veil-net/conflux/internal/paths"
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
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) error {
	return writeAtomicAs(path, perm, -1, -1, data)
}

// WriteFileAtomicAs is WriteFileAtomic for a file that belongs to uid and gid, given to
// them on the descriptor before any content reaches it, as the mode is: anchord's own
// configuration, which carries credentials and which anchord, running as its own account,
// has to be able to read. -1 leaves either as the creating process's.
func WriteFileAtomicAs(path string, data []byte, perm fs.FileMode, uid, gid int) error {
	return writeAtomicAs(path, perm, uid, gid, data)
}

// writeAtomic is WriteFileAtomic for content in pieces, written one after another, so a
// caller adding a newline need not copy what it was given to add it.
func writeAtomic(path string, perm fs.FileMode, chunks ...[]byte) error {
	return writeAtomicAs(path, perm, -1, -1, chunks...)
}

func writeAtomicAs(path string, perm fs.FileMode, uid, gid int, chunks ...[]byte) (err error) {
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

	if uid >= 0 || gid >= 0 {
		if err = tmp.Chown(uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", tmpName, err)
		}
	}

	// On Windows the chmod above is a no-op. Restrict by ownership and DACL instead,
	// and do it while the file is still empty and unnamed.
	if perm&0o077 == 0 {
		if err = paths.Restrict(tmpName, false); err != nil {
			return fmt.Errorf("restrict %s: %w", tmpName, err)
		}
	}

	for _, c := range chunks {
		if _, err = tmp.Write(c); err != nil {
			return fmt.Errorf("write %s: %w", tmpName, err)
		}
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

	syncDir(dir)

	return nil
}

// syncDir makes the rename durable, as far as the platform lets it. Best effort: the
// rename already happened, and a directory some filesystems refuse to fsync -- and
// NTFS, which orders its metadata itself -- is not worth losing the write over.
func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		_ = f.Sync()
		f.Close()
	}
}
