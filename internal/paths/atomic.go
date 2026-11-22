package paths

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteAtomic replaces path with chunks, written one after another, or leaves what was there: the one
// atomic write conflux has, for the configuration, the state, the manifest, and what the daemon and
// the boot services write.
//
// A crash, a full disk or a kill between the open and the write must not produce a truncated
// conflux.json or -- far worse -- a truncated manifest.b64, which would destroy an identity that has
// no second copy. So: write a sibling temporary file (.tmp-), fsync it, rename over the target, then
// fsync the directory so the rename itself survives a power cut.
//
// The mode is set on the file descriptor before any content reaches it, and so are uid and gid where
// either is not -1 -- anchord's own configuration, which carries credentials and which anchord, running
// as its own account, has to be able to read. Writing and then chmod'ing leaves a window in which the
// secret exists at the umask's mode, and on a shared machine that window is the whole vulnerability.
// A mode that lets nobody else in is, on Windows, where a mode is nothing, the ownership and DACL
// Restrict gives, set while the file is still empty and unnamed.
func WriteAtomic(path string, perm fs.FileMode, uid, gid int, chunks ...[]byte) (err error) {
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
		if err = Restrict(tmpName, false); err != nil {
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

	SyncDir(dir)

	return nil
}
