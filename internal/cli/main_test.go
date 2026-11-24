package cli

import (
	"os"
	"testing"

	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/service"
)

// TestMain roots every conflux path in a directory of the run's own before any test starts,
// and stands in for the boot manager, so a test that does not root its own reaches nothing
// of the machine's: neither its .conflux nor the one service a machine has.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "conflux-test-")
	if err != nil {
		panic(err)
	}

	restore := paths.UseRoot(dir)
	services = func() service.Manager { return noService{} }

	code := m.Run()

	restore()
	_ = os.RemoveAll(dir)

	os.Exit(code)
}

// noService is a machine with no boot service registered, whose every change is refused.
type noService struct{}

var errNoService = os.ErrPermission

func (noService) Install(string, ...string) error   { return errNoService }
func (noService) Remove() error                     { return nil }
func (noService) Stop() error                       { return errNoService }
func (noService) Restart() error                    { return errNoService }
func (noService) Reconcile(string, ...string) error { return errNoService }
func (noService) Installed() (bool, error)          { return false, nil }
func (noService) Describe() string                  { return "not installed (a test's stand-in)" }
func (noService) LogHint() string                   { return "nothing to read: a test's stand-in" }
