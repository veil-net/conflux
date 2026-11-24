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
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine:       fmt.Sprintf(`cmd.exe /d /c "ping -n 4 127.0.0.1 >nul & rmdir /s /q "%s""`, dir),
		HideWindow:    true,
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("leave %s to be removed once conflux exits: %w", dir, err)
	}

	return cmd.Process.Release()
}

// removePathEntry takes dir out of the machine's PATH, read unexpanded and written back as
// its own kind, as install.ps1 wrote it, and tells every window the environment changed.
func removePathEntry(dir string) error {
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

	kept := withoutDir(path, dir)
	if kept == path {
		return nil
	}

	if kind == registry.EXPAND_SZ {
		err = k.SetExpandStringValue("Path", kept)
	} else {
		err = k.SetStringValue("Path", kept)
	}

	if err != nil {
		return fmt.Errorf("write the machine's PATH: %w", err)
	}

	broadcastEnvironment()

	return nil
}

var sendMessageTimeout = windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")

// broadcastEnvironment tells every top-level window, Explorer's above all, that the
// environment changed, so what it starts next has the PATH without conflux in it.
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
