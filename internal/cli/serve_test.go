package cli

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths/pathstest"
	"github.com/veil-net/conflux/internal/ui"
)

// recordingService is a registered service that records what it was asked to register.
type recordingService struct {
	noService
	reconciled *[]string
}

func (r recordingService) Installed() (bool, error) { return true, nil }

func (r recordingService) Reconcile(exe string, args ...string) error {
	*r.reconciled = append([]string{exe}, args...)

	return nil
}

// TestServePutsTheServiceBack: the service is the supervisor's to keep, as the root is, so a
// start places the copy it runs and puts its registration back to what this conflux writes.
func TestServePutsTheServiceBack(t *testing.T) {
	d := testDirs(t)

	var got []string

	withServices(t, recordingService{reconciled: &got})
	asRoot(t, true)

	reconcileService(d)

	if want := []string{d.ServiceExecutable(), "serve"}; !slices.Equal(got, want) {
		t.Errorf("the registration put back is %q, want %q", got, want)
	}
}

// TestARefusedSupervisorChangesNothing: a second `conflux serve`, refused for the serve.lock
// another holds, puts nothing of the service back -- neither the copy it runs nor its
// registration -- since the one holding the lock is the service, and keeps it.
func TestARefusedSupervisorChangesNothing(t *testing.T) {
	d := pathstest.Root(t)

	unlock, ok, err := flock.TryAcquire(d.ServeLockFile())
	if err != nil || !ok {
		t.Fatalf("hold serve.lock: %v, %v", ok, err)
	}
	t.Cleanup(unlock)

	var got []string

	withServices(t, recordingService{reconciled: &got})
	asRoot(t, true)

	var said bytes.Buffer

	oldErr := ui.Errw
	ui.Errw = &said

	t.Cleanup(func() { ui.Errw = oldErr })

	if code := runServe(t.Context(), []string{"--foreground"}); code != ExitError ||
		!strings.Contains(said.String(), "another conflux supervisor") {
		t.Errorf("a second supervisor exited %d, saying %q; want %d and the refusal", code, said.String(), ExitError)
	}

	if got != nil {
		t.Errorf("a refused supervisor put the registration back: %q", got)
	}

	if _, err := os.Lstat(d.ServiceExecutable()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused supervisor placed %s: %v", d.ServiceExecutable(), err)
	}
}
