package paths

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// remakeOld is RemakeOld for dir, a root of the installation d's. The root is held open, as itself
// where it is a junction (heldRoot), and held to what secure holds a root to before it changes
// anything in it: its owner, and nobody else let move what is in it, who could put back what is
// removed. Then each thing directly in it that conflux makes again by its name there (remadeIn) is
// opened through the root's handle, never followed, and judged as contents judges it for SYSTEM; one
// that fails is removed, through handles (removeIn). A junction or a link at such a name is not
// conflux's, and is left to the judgement after. Last, what the root holds is judged as secure judges
// an installation's (contents): anything left that fails -- a thing conflux does not make again, the
// configuration, the state and the manifest among them, or one deeper in a folder that passes -- is
// refused, naming it, and left as it is. A root that is not there holds nothing to remove.
func remakeOld(d Dirs, dir string) ([]string, error) {
	root, err := heldRoot(dir, readAccess|windows.FILE_LIST_DIRECTORY|windows.SYNCHRONIZE)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	}
	defer root.close()

	sd, err := security(root.dir)
	if err != nil {
		return nil, fmt.Errorf("read the ownership of %s: %w", dir, err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return nil, fmt.Errorf("read the owner of %s: %w", dir, err)
	}

	if err := ownerRefusal(dir, owner); err != nil {
		return nil, err
	}

	switch who, _, err := changerIn(dir, currentUser(), sd, moves, "move it or what is in it", nil, false); {
	case err != nil:
		return nil, err
	case who != "":
		return nil, fmt.Errorf("%s %s could put back what conflux removes from it to make again, so conflux will "+
			"not.\n  Give it a DACL that grants nobody else that right, then run this again as Administrator", dir, who)
	}

	names, err := listIn(root.dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	anchord, err := ServiceSID()
	if err != nil {
		return nil, fmt.Errorf("judge what %s holds: %w", dir, err)
	}

	var removed []string

	for _, name := range names {
		if !d.remadeIn(dir, name) {
			continue
		}

		p := filepath.Join(dir, name)

		who, err := failsIn(root.dir, name, p, anchord)

		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue // gone since it was listed
		case err != nil:
			return removed, err
		case who == "":
			continue
		}

		if err := removeIn(root.dir, name, p); err != nil {
			return removed, fmt.Errorf("remove %s, which %s could change, for conflux to make again: %w", p, who, err)
		}

		removed = append(removed, p)
	}

	return removed, contents(dir, true)
}

// remadeIn reports whether name, directly in dir, a root of d's, is what conflux makes again by its
// name there, losing nothing of the machine's identity, configuration or state: the lock files, the
// log's folder and the run directory, the extraction, the service's copy of conflux and the image an
// update moved aside, anchord's -config, which the supervisor writes at every spawn, and what an
// atomic write or the service's copy leaves before its rename.
func (d Dirs) remadeIn(dir, name string) bool {
	for _, p := range []string{d.LockFile(), d.ServeLockFile(), d.Log, d.Run, d.Libexec(), d.ServiceExecutable(),
		d.ServiceExecutable() + ".old", d.DaemonConfigFile()} {
		if p != "" && strings.EqualFold(filepath.Dir(p), dir) && strings.EqualFold(filepath.Base(p), name) {
			return true
		}
	}

	lower := strings.ToLower(name)

	return strings.HasPrefix(lower, ".tmp-") || strings.HasPrefix(lower, ".conflux-")
}

// failsIn is who, besides SYSTEM, the Administrators, TrustedInstaller and anchord, may change name,
// in the directory parent holds open, which p names, as contents judges it for SYSTEM, or "": opened
// through parent, looked up there and nowhere else and never followed. A junction or a link is "",
// left to contents, which refuses it.
func failsIn(parent windows.Handle, name, p string, anchord *windows.SID) (string, error) {
	h, err := ntOpen(parent, name, nil, windows.SYNCHRONIZE|readAccess, windows.FILE_OPEN, 0)
	if err != nil {
		return "", &os.PathError{Op: "open", Path: p, Err: err}
	}
	defer windows.CloseHandle(h)

	attributes, tag, err := attributeTag(h)

	switch {
	case err != nil:
		return "", &os.PathError{Op: "read", Path: p, Err: err}
	case attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && tag&reparseTagNameSurrogate != 0:
		return "", nil
	}

	dir := attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0

	what := "write it, move it or make a junction of it"
	if dir {
		what = "write it or what is made in it, move it or make a junction of it"
	}

	who, _, err := changer(p, sidSystem, h, retargets, what, anchord, dir)

	return who, err
}

// removeIn removes name, in the directory parent holds open, which p names, and, where it is a
// folder, all it holds first: each opened through a handle on the one it is in, looked up there and
// nowhere else, never followed (ntOpen), and removed through its own (dispose). A junction or a link
// is removed as itself, and never gone into.
func removeIn(parent windows.Handle, name, p string) error {
	h, err := ntOpen(parent, name, nil,
		windows.SYNCHRONIZE|windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.FILE_LIST_DIRECTORY, windows.FILE_OPEN, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: p, Err: err}
	}
	defer windows.CloseHandle(h)

	attributes, tag, err := attributeTag(h)
	if err != nil {
		return &os.PathError{Op: "read", Path: p, Err: err}
	}

	link := attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && tag&reparseTagNameSurrogate != 0

	if attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 && !link {
		names, err := listIn(h)
		if err != nil {
			return &os.PathError{Op: "read", Path: p, Err: err}
		}

		for _, n := range names {
			if err := removeIn(h, n, filepath.Join(p, n)); err != nil {
				return err
			}
		}
	}

	if err := dispose(h); err != nil {
		return &os.PathError{Op: "remove", Path: p, Err: err}
	}

	return nil
}

// listIn is what the directory h holds open lists, "." and ".." aside: read through h, as
// FILE_FULL_DIR_INFO entries, and not by its name.
func listIn(h windows.Handle) ([]string, error) {
	const nameAt = 68 // FILE_FULL_DIR_INFO's FileName, after its FileNameLength at 60

	var names []string

	b := make([]byte, 64<<10)

	for class := uint32(windows.FileFullDirectoryRestartInfo); ; class = windows.FileFullDirectoryInfo {
		err := windows.GetFileInformationByHandleEx(h, class, &b[0], uint32(len(b)))

		switch {
		case errors.Is(err, windows.ERROR_NO_MORE_FILES):
			return names, nil
		case err != nil:
			return nil, err
		}

		for e := b; ; {
			if len(e) < nameAt {
				return nil, errors.New("a directory entry shorter than its header")
			}

			next, size := binary.LittleEndian.Uint32(e), int(binary.LittleEndian.Uint32(e[60:]))
			if size%2 != 0 || nameAt+size > len(e) {
				return nil, errors.New("a directory entry whose name runs past it")
			}

			u := make([]uint16, size/2)
			for i := range u {
				u[i] = binary.LittleEndian.Uint16(e[nameAt+2*i:])
			}

			if name := string(utf16.Decode(u)); name != "." && name != ".." {
				names = append(names, name)
			}

			if next == 0 {
				break
			}

			if int(next) > len(e) {
				return nil, errors.New("a directory entry whose next runs past the answer")
			}

			e = e[next:]
		}
	}
}
