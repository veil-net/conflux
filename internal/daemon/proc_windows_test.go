package daemon

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestClosingTheJobEndsAnchord: anchord is put in a job that ends it when the job's last
// handle closes, which the system does for the supervisor however it ends.
func TestClosingTheJobEndsAnchord(t *testing.T) {
	t.Setenv(fakeAnchordEnv, "serve")

	cmd := exec.Command(os.Args[0], "-socket", "unused")
	cmd.SysProcAttr = procAttr()

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	exited := make(chan struct{})

	go func() {
		_ = cmd.Wait()
		close(exited)
	}()

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
	})

	job, err := newKillJob()
	if err != nil {
		t.Fatal(err)
	}

	if err := assign(job, cmd.Process); err != nil {
		t.Fatal(err)
	}

	select {
	case <-exited:
		t.Fatal("anchord exited before its job was closed")
	case <-time.After(200 * time.Millisecond):
	}

	if err := windows.CloseHandle(job); err != nil {
		t.Fatal(err)
	}

	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("anchord outlived its job")
	}
}
