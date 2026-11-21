package paths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

// TestMountAllowsExecReadsNothing: Windows mounts nothing noexec, so MountAllowsExec says so of any
// path, and reads nothing at it: Ephemeral asks it where Check found a candidate's way missing,
// and a lookup by name there would follow what any user may make in C:\ meanwhile -- a link to a
// share, which following signs this machine in to -- or find nothing. That nothing is read is pinned
// by a named pipe of the test's own at the name: any look at a pipe's name, an open or a stat of it,
// connects to it, which the test sees, and it sees MountAllowsExec's none. Where a stat of the pipe is
// not seen either, nothing could be, and the test skips. Windows-only, so it runs in CI's platforms job
// alone.
func TestMountAllowsExecReadsNothing(t *testing.T) {
	share := dirSymlink(t, filepath.Join(t.TempDir(), "cfx"), `\\192.0.2.1\conflux`)

	pipe := fmt.Sprintf(`\\.\pipe\conflux-test-%d`, os.Getpid())
	looked := listen(t, pipe)

	for _, p := range []string{filepath.Join(t.TempDir(), "not", "there"), share, filepath.Join(share, ephemeralName),
		pipe} {
		if ok, err := MountAllowsExec(p); !ok || err != nil {
			t.Errorf("MountAllowsExec(%s) = %v, %v, want true, nil, with nothing read", p, ok, err)
		}
	}

	if looked() {
		t.Errorf("MountAllowsExec(%s) looked at what is at the name", pipe)
	}

	_, _ = os.Stat(pipe)

	if !looked() {
		t.Skipf("a stat of %s did not connect to it, so this machine shows no look at a pipe's name", pipe)
	}
}

// listen serves the named pipe name, for as long as t runs, to one client, and is whether one has
// connected to it, by opening its name, since.
func listen(t *testing.T, name string) (looked func() bool) {
	t.Helper()

	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}

	h, err := windows.CreateNamedPipe(n, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_BYTE|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 512, 512, 0, nil)
	if err != nil {
		t.Fatalf("serve %s: %v", name, err)
	}

	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(h)
		t.Fatal(err)
	}

	// The wait's OVERLAPPED, which the system writes to as the wait ends, a close of the pipe
	// cancelling it included, kept alive until then.
	ol := &windows.Overlapped{HEvent: ev}

	t.Cleanup(func() {
		windows.CloseHandle(h)
		runtime.KeepAlive(ol)
		windows.CloseHandle(ev)
	})

	switch err := windows.ConnectNamedPipe(h, ol); {
	case errors.Is(err, windows.ERROR_IO_PENDING):
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		t.Fatalf("%s was connected to before the test looked", name)
	default:
		t.Fatalf("wait for a client of %s: %v", name, err)
	}

	return func() bool {
		e, err := windows.WaitForSingleObject(ev, 0)

		return err == nil && e == windows.WAIT_OBJECT_0
	}
}
