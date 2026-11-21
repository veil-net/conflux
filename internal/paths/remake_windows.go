package paths

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// remakeOld is RemakeOld for dir, a root of the installation d's. The root is held open as a reader
// holds it (holdRoot): the way to it walked from the top of its volume, a CONFLUX_DIR's held to parents'
// rule, a junction at its name followed only where conflux would follow it, and its owner SYSTEM, the
// Administrators or the account running conflux (usable). It is held to what secure holds a root to
// before it changes anything in it: nobody else let move what is in it, who could put back what is
// removed. Then each thing directly in it that conflux makes again by its name there (remadeIn) is
// opened through the root's handle, never followed, and judged as contents judges it for SYSTEM; one
// that fails is removed, through handles (removeIn), the log folder once the log files in it that pass
// are moved out into the root (keepLog). A junction or a link at such a name is not
// conflux's, and is left to the judgement after. Last, what the root holds is judged as secure judges
// an installation's (contents): anything left that fails -- a thing conflux does not make again, the
// configuration, the state and the manifest among them, or one deeper in a folder that passes -- is
// refused, naming it, and left as it is. A root that is not there holds nothing to remove.
func remakeOld(d Dirs, dir string) ([]string, error) {
	r, err := holdRoot(dir)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	}
	defer r.close()

	if err := r.usable(dir); err != nil {
		return nil, err
	}

	root := r.dir.h

	sd, err := security(root)
	if err != nil {
		return nil, fmt.Errorf("read the ownership of %s: %w", dir, err)
	}

	switch who, _, err := changerIn(dir, currentUser(), sd, moves, "move it or what is in it", nil, false); {
	case err != nil:
		return nil, err
	case who != "":
		return nil, fmt.Errorf("%s %s could put back what conflux removes from it to make again, so conflux will "+
			"not.\n  Give it a DACL that grants nobody else that right, then run this again as Administrator", dir, who)
	}

	list, err := listing(root)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	defer windows.CloseHandle(list)

	names, err := listIn(list)
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

		who, err := failsIn(root, name, p, anchord)

		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue // gone since it was listed
		case err != nil:
			return removed, err
		case who == "":
			continue
		}

		if d.isLog(dir, name) {
			if err := d.keepLog(root, name, p, anchord); err != nil {
				return removed, err
			}
		}

		if err := removeIn(root, name, p); err != nil {
			return removed, fmt.Errorf("remove %s, which %s could change, for conflux to make again: %w", p, who, err)
		}

		removed = append(removed, p)
	}

	return removed, contents(dir, true)
}

// isLog reports whether name, directly in dir, a root of d's, is d's log folder, logs\.
func (d Dirs) isLog(dir, name string) bool {
	return d.Log != "" && strings.EqualFold(filepath.Dir(d.Log), dir) && strings.EqualFold(filepath.Base(d.Log), name)
}

// logNames are the files the service's log is kept in, in d's log folder: the log, and the one it was
// moved aside to (logfile).
func (d Dirs) logNames() []string {
	name := filepath.Base(d.LogFile())

	return []string{name, name + ".1"}
}

// keptLog is the name a log file of a logs\ RemakeOld removes waits under in the root, for EnsureAll to
// move back once it has made logs\ again (makeInside): a name conflux makes again there (remadeIn).
func keptLog(name string) string { return ".conflux-kept-" + name }

// keepLog moves each log file in name, the log folder directly in the root root holds open, which p
// names, that the service's rule takes into the root, as keptLog names it, before RemakeOld removes the
// folder: the log is the machine's, and what the SYSTEM service wrote there is SYSTEM's, whoever owns
// the folder. Each is opened through a handle on the folder, looked up there and nowhere else and
// never followed, judged as contents judges it for SYSTEM, and renamed through its own handle (moveIn);
// one that fails, or is a junction or a link, goes with the folder, as does one whose kept name is
// taken already. A folder that is a junction or a link is no log folder, and RemakeOld does not remove
// it either.
func (d Dirs) keepLog(root windows.Handle, name, p string, anchord *windows.SID) error {
	logs, err := ntOpen(root, name, nil, windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES, windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE)
	if err != nil {
		return fmt.Errorf("keep the log in %s: %w", p, &os.PathError{Op: "open", Path: p, Err: err})
	}
	defer windows.CloseHandle(logs)

	if link, err := nameSurrogate(logs); err != nil || link {
		return err
	}

	for _, log := range d.logNames() {
		f := filepath.Join(p, log)

		h, err := ntOpen(logs, log, nil, windows.SYNCHRONIZE|windows.DELETE|readAccess, windows.FILE_OPEN,
			windows.FILE_NON_DIRECTORY_FILE)

		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return fmt.Errorf("keep the log %s: %w", f, &os.PathError{Op: "open", Path: f, Err: err})
		}

		err = func() error {
			defer windows.CloseHandle(h)

			switch link, err := nameSurrogate(h); {
			case err != nil:
				return &os.PathError{Op: "read", Path: f, Err: err}
			case link:
				return nil
			}

			switch who, _, err := changer(f, sidSystem, h, retargets, "write it, move it or make a junction of it",
				anchord, false); {
			case err != nil:
				return err
			case who != "":
				return nil
			}

			if err := moveIn(h, root, keptLog(log)); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
				return &os.PathError{Op: "move", Path: f, Err: err}
			}

			return nil
		}()
		if err != nil {
			return fmt.Errorf("keep the log %s: %w", f, err)
		}
	}

	return nil
}

// makeInside makes dir, a root of d's inside another, where it is not there yet; where that is d's log
// folder, made again once RemakeOld removed it, the log files RemakeOld kept in the state root are moved
// back into it (restoreLog).
func (d Dirs) makeInside(dir string) error {
	_, was := os.Lstat(dir)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	if dir != d.Log || d.ephemeral || !errors.Is(was, fs.ErrNotExist) {
		return nil
	}

	return d.restoreLog()
}

// restoreLog moves each log file RemakeOld kept in the state root (keptLog) back into d's log folder,
// under its own name: each opened through a handle on the root, looked up there and nowhere else and
// never followed, and renamed through its own handle into the folder, held open as itself (moveIn). A
// kept name that is a junction or a link is left, for the judgement of what the root holds to refuse.
func (d Dirs) restoreLog() error {
	if !strings.EqualFold(filepath.Dir(d.Log), d.State) {
		return nil
	}

	root, err := heldRoot(d.State, readAccess|windows.SYNCHRONIZE)
	if err != nil {
		return err
	}
	defer root.close()

	var logs windows.Handle

	defer func() {
		if logs != 0 {
			windows.CloseHandle(logs)
		}
	}()

	for _, log := range d.logNames() {
		kept := filepath.Join(d.State, keptLog(log))

		h, err := ntOpen(root.dir, keptLog(log), nil, windows.SYNCHRONIZE|windows.DELETE|windows.FILE_READ_ATTRIBUTES,
			windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)

		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return fmt.Errorf("move the log kept at %s back: %w", kept, &os.PathError{Op: "open", Path: kept, Err: err})
		}

		err = func() error {
			defer windows.CloseHandle(h)

			if link, err := nameSurrogate(h); err != nil || link {
				return err
			}

			if logs == 0 {
				var err error
				if logs, err = ntOpen(root.dir, filepath.Base(d.Log), nil, windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES,
					windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE); err != nil {
					logs = 0

					return &os.PathError{Op: "open", Path: d.Log, Err: err}
				}

				if err := notLink(d.Log, logs, "is a junction or a link"); err != nil {
					return err
				}
			}

			return moveIn(h, logs, log)
		}()
		if err != nil {
			return fmt.Errorf("move the log kept at %s back into %s: %w", kept, d.Log, err)
		}
	}

	return nil
}

// moveIn renames what h holds open, opened with DELETE, to name in the folder dir holds open, through
// h and dir and not by any name (FileRenameInformation, its RootDirectory dir), replacing nothing: a
// name taken already is ERROR_ALREADY_EXISTS.
func moveIn(h, dir windows.Handle, name string) error {
	u, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}

	size := int(unsafe.Offsetof(renameInformation{}.fileName)) + 2*(len(u)-1)

	b := make([]uint64, (size+2+7)/8) // aligned as the struct is, with room for the name's NUL
	info := (*renameInformation)(unsafe.Pointer(&b[0]))
	info.rootDirectory = dir
	info.fileNameLength = uint32(2 * (len(u) - 1))
	copy(unsafe.Slice(&info.fileName[0], len(u)), u)

	var iosb windows.IO_STATUS_BLOCK

	err = windows.NtSetInformationFile(h, &iosb, (*byte)(unsafe.Pointer(&b[0])), uint32(size),
		windows.FileRenameInformation)
	if status, ok := err.(windows.NTStatus); ok {
		return status.Errno()
	}

	return err
}

// renameInformation is FILE_RENAME_INFORMATION, its file name running on past it.
type renameInformation struct {
	replaceIfExists uint32
	rootDirectory   windows.Handle
	fileNameLength  uint32
	fileName        [1]uint16
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

// emptyIn removes all the folder s holds open holds, p naming it: the folder opened again through s, to
// list it (listing), and each name in it removed through that (removeIn), never followed.
func emptyIn(s step, p string) error {
	h, err := listing(s.h)
	if err != nil {
		return &os.PathError{Op: "open", Path: p, Err: err}
	}
	defer windows.CloseHandle(h)

	names, err := listIn(h)
	if err != nil {
		return &os.PathError{Op: "read", Path: p, Err: err}
	}

	for _, n := range names {
		if err := removeIn(h, n, filepath.Join(p, n)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}

	return nil
}

// listing is the folder h holds open, opened again through h, by no name, to be listed (listIn).
func listing(h windows.Handle) (windows.Handle, error) {
	return ntOpen(h, "", nil, windows.SYNCHRONIZE|windows.FILE_LIST_DIRECTORY, windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE)
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
	const access = windows.SYNCHRONIZE | windows.DELETE | windows.FILE_READ_ATTRIBUTES

	h, err := ntOpen(parent, name, nil, access|windows.FILE_LIST_DIRECTORY, windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_FOR_BACKUP_INTENT)
	if errors.Is(err, windows.ERROR_DIRECTORY) {
		h, err = ntOpen(parent, name, nil, access, windows.FILE_OPEN,
			windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_FOR_BACKUP_INTENT)
	}

	return h, err
}

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
