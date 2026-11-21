package paths

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// removeFrom is RemoveRoot's removal of name, in the directory parent holds open, which p names
// (removeIn), and whether anything was there.
func removeFrom(parent step, name, p string) (bool, error) {
	switch err := removeIn(parent.h, name, p); {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return true, err
	}

	return true, nil
}

// removeEmpty is RemoveWay's removal of name, an empty folder, in the directory parent holds open,
// which p names, and whether it removed it: opened through parent, looked up there and nowhere else
// and never followed, and removed through its own handle (dispose) once it lists nothing. One holding
// anything, not there, or no longer a folder, a junction or a link among them, is left.
func removeEmpty(parent step, name, p string) (bool, error) {
	h, err := ntOpen(parent.h, name, nil,
		windows.SYNCHRONIZE|windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.FILE_LIST_DIRECTORY, windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE)

	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, windows.ERROR_DIRECTORY):
		return false, nil
	case err != nil:
		return false, &os.PathError{Op: "open", Path: p, Err: err}
	}
	defer windows.CloseHandle(h)

	attributes, _, err := attributeTag(h)
	if err != nil {
		return false, &os.PathError{Op: "read", Path: p, Err: err}
	}

	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, nil
	}

	names, err := listIn(h)

	switch {
	case err != nil:
		return false, &os.PathError{Op: "read", Path: p, Err: err}
	case len(names) > 0:
		return false, nil
	}

	if err := dispose(h); err != nil {
		return false, &os.PathError{Op: "remove", Path: p, Err: err}
	}

	return true, nil
}

// removeIn removes name, in the directory parent holds open, which p names, and, where it is a
// folder, all it holds first: each opened through a handle on the one it is in, looked up there and
// nowhere else, never followed (openToRemove), and removed through its own (dispose), with backup
// intent on a thread whose token has the privileges that give it (withBackup), so that a DACL granting
// the Administrators nothing does not keep it. A junction or a link is removed as itself, and never
// gone into. Something gone since its folder was listed is passed over; nothing at name itself is an
// error that is fs.ErrNotExist.
func removeIn(parent windows.Handle, name, p string) error {
	return withBackup(func() error { return removeTree(parent, name, p) })
}

// removeTree is removeIn on a thread withBackup has given its privileges.
func removeTree(parent windows.Handle, name, p string) error {
	h, err := openToRemove(parent, name)
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
			if err := removeTree(h, n, filepath.Join(p, n)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}

	if err := dispose(h); err != nil {
		return &os.PathError{Op: "remove", Path: p, Err: err}
	}

	return nil
}

// openToRemove opens name, in the directory parent holds open, to remove it, with backup intent: a
// folder to list as well, and anything else, which listing would ask to read, not (ERROR_DIRECTORY).
// Looked up in parent and nowhere else, and never followed (ntOpen).
func openToRemove(parent windows.Handle, name string) (windows.Handle, error) {
	h, err := ntOpen(parent, name, nil, removeAccess|windows.FILE_LIST_DIRECTORY, windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_FOR_BACKUP_INTENT)
	if errors.Is(err, windows.ERROR_DIRECTORY) {
		h, err = ntOpen(parent, name, nil, removeAccess, windows.FILE_OPEN,
			windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_FOR_BACKUP_INTENT)
	}

	return h, err
}

// removeAccess is what openToRemove opens a thing to remove for: to delete it and read its attributes,
// and never to read what it holds.
const removeAccess = windows.SYNCHRONIZE | windows.DELETE | windows.FILE_READ_ATTRIBUTES

// withBackup runs f with SeBackupPrivilege and SeRestorePrivilege enabled -- held, disabled, by an
// elevated administrator's token and SYSTEM's -- so that what f opens with backup intent is opened for
// what it asks, to list and to delete, whatever its DACL grants: on this thread alone, which takes a
// copy of the process's token (ImpersonateSelf) to enable them in, and gives it back after
// (RevertToSelf). Where the thread cannot take one, or the token holds neither privilege, f runs as
// it is, and backup intent grants nothing. A thread that could not give its copy back stays locked to
// f's goroutine, which then ends with it.
func withBackup(f func() error) error {
	runtime.LockOSThread()

	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		runtime.UnlockOSThread()

		return f()
	}

	defer func() {
		if windows.RevertToSelf() == nil {
			runtime.UnlockOSThread()
		}
	}()

	var tok windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false,
		&tok); err == nil {
		enable(tok, "SeBackupPrivilege", "SeRestorePrivilege")
		tok.Close()
	}

	return f()
}

// enable enables in tok each privilege of names it holds; one it does not hold, or does not know, is
// passed over.
func enable(tok windows.Token, names ...string) {
	for _, name := range names {
		n, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}

		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		if windows.LookupPrivilegeValue(nil, n, &tp.Privileges[0].Luid) != nil {
			continue
		}

		tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

		_ = windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
	}
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
