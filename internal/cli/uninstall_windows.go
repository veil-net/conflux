package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/service"
)

// removeInstallation removes what install.ps1 put in place: the directory it installed
// conflux in, and that directory's entry in the machine's PATH. A running image cannot be
// deleted, so where this process is the conflux it installed, the directory goes once it has
// exited, by a cmd.exe it leaves behind to do that and nothing else.
func removeInstallation() error {
	dir := filepath.Dir(paths.InstalledExecutable())

	errs := []error{removePathEntry(dir)}

	if self, err := service.Executable(); err == nil && strings.EqualFold(filepath.Dir(self), dir) {
		return errors.Join(append(errs, removeAfterExit(dir))...)
	}

	if err := os.RemoveAll(dir); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// removeAfterExit starts a cmd.exe, detached and windowless, that waits a few seconds for
// this process to exit and then removes dir.
func removeAfterExit(dir string) error {
	cmd, err := removalCommand(dir)
	if err == nil {
		err = cmd.Start()
	}

	if err != nil {
		return fmt.Errorf("leave %s to be removed once conflux exits: %w", dir, err)
	}

	return cmd.Process.Release()
}

// removalCommand is the cmd.exe removeAfterExit leaves to remove dir, and everything it runs is
// the system's, in the system directory Windows reports: cmd.exe itself, and the ping it waits
// with, named by its full path, with the system directory its current one. Not under
// %SystemRoot%, which is whatever the environment uninstall was started with says, and would
// have an elevated conflux start a cmd.exe from anywhere it pointed; and not ping by name, nor
// in the directory uninstall was typed in, which cmd.exe searches for a command before PATH,
// so that a ping.exe or ping.bat left there would run as Administrator.
func removalCommand(dir string) (*exec.Cmd, error) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, fmt.Errorf("find the system directory: %w", err)
	}

	cmd := exec.Command(filepath.Join(sys, "cmd.exe"))
	cmd.Dir = sys
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine: fmt.Sprintf(`cmd.exe /d /c ""%s" -n 4 127.0.0.1 >nul & rmdir /s /q "%s""`,
			filepath.Join(sys, "PING.EXE"), dir),
		HideWindow:    true,
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}

	return cmd, nil
}

// putOnPath puts the directory of exe, a conflux an update installed where there was none, on
// the machine's PATH, as install.ps1 does.
func putOnPath(exe string) error {
	dir := filepath.Dir(exe)

	if err := editMachinePath(func(path string) string { return withDir(path, dir) }); err != nil {
		return fmt.Errorf("%s is not on the machine's PATH: %w", dir, err)
	}

	return nil
}

// removePathEntry takes dir out of the machine's PATH, as install.ps1 put it there.
func removePathEntry(dir string) error {
	return editMachinePath(func(path string) string { return withoutDir(path, dir) })
}

// editMachinePath rewrites the machine's PATH through edit: read unexpanded and written back
// as its own kind, as install.ps1 writes it, since a value expanded on the way through would
// lose every %SystemRoot% in it; and, where edit changed it, tells every window the
// environment changed.
func editMachinePath(edit func(path string) string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open the machine's environment: %w", err)
	}
	defer k.Close()

	path, kind, err := k.GetStringValue("Path")
	if err != nil {
		return fmt.Errorf("read the machine's PATH: %w", err)
	}

	edited := edit(path)
	if edited == path {
		return nil
	}

	if kind == registry.EXPAND_SZ {
		err = k.SetExpandStringValue("Path", edited)
	} else {
		err = k.SetStringValue("Path", edited)
	}

	if err != nil {
		return fmt.Errorf("write the machine's PATH: %w", err)
	}

	broadcastEnvironment()

	return nil
}

var sendMessageTimeout = windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")

// broadcastEnvironment tells every top-level window, Explorer's above all, that the
// environment changed, so what it starts next has the PATH as it is now.
func broadcastEnvironment() {
	env, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}

	const (
		hwndBroadcast   = 0xffff
		wmSettingChange = 0x1a
		smtoAbortIfHung = 0x2
	)

	var result uintptr

	_, _, _ = sendMessageTimeout.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)),
		smtoAbortIfHung, 5000, uintptr(unsafe.Pointer(&result)))
}
