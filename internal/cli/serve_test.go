package cli

import (
	"slices"
	"testing"

	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/service"
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

	was, elevated := services, privcheck.Elevated
	services = func() service.Manager { return recordingService{reconciled: &got} }
	privcheck.Elevated = func() bool { return true }

	t.Cleanup(func() { services, privcheck.Elevated = was, elevated })

	reconcileService(d)

	if want := []string{d.ServiceExecutable(), "serve"}; !slices.Equal(got, want) {
		t.Errorf("the registration put back is %q, want %q", got, want)
	}
}
