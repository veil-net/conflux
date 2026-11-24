package config

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/veil-net/conflux/internal/paths"
)

// TempPrefix begins the name of the temporary file every atomic write makes beside its target
// and renames over it: what the supervisor's tidy spares while it is young enough to be a
// write in progress.
const TempPrefix = ".tmp-"

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

// WriteFileIfChanged is WriteFileAtomic, with perm, unless path holds data already, and reports
// whether it wrote. What conflux puts back at every start -- the boot service's registration
// above all -- is written only where it was changed, so an unchanged file keeps its inode and
// its mtime and nothing watching it sees a change. One that holds data with another mode, on
// Unix, is given perm back where it is, which is no write: a registration made group- or
// world-writable since is the service manager running whatever its writer names. One that
// holds data and another account owns, on Unix, is written: its owner can make it writable or
// write it whenever it likes, and the file written in its place is the writer's.
func WriteFileIfChanged(path string, data []byte, perm fs.FileMode) (bool, error) {
	switch same, err := holds(path, data, perm); {
	case err != nil:
		return false, err
	case same:
		return false, nil
	}

	if err := WriteFileAtomic(path, data, perm); err != nil {
		return false, err
	}

	return true, nil
}

// holds reports whether path holds data already, in a file that can stay (keep). A file that
// cannot be opened or read holds nothing, and is written.
func holds(path string, data []byte, perm fs.FileMode) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, nil
	}
	defer f.Close()

	// One byte past data is enough to know a longer file differs.
	cur, err := io.ReadAll(io.LimitReader(f, int64(len(data))+1))
	if err != nil || !bytes.Equal(cur, data) {
		return false, nil
	}

	return keep(f, path, perm)
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

	tmp, err := os.CreateTemp(dir, TempPrefix+"*")
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
