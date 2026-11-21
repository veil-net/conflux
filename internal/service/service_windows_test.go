package service

import (
	"testing"

	"golang.org/x/sys/windows/svc"
)

// TestAStoppingServiceRuns: a service the SCM says is starting, running or stopping has its process
// still there, and runs; one stopped does not. tidy asks Running before it stops the service for an
// update, and a service stopping that it took for one not running would leave its supervisor holding
// the serve lock, and be called one run by hand.
func TestAStoppingServiceRuns(t *testing.T) {
	for state, want := range map[svc.State]bool{
		svc.Stopped:      false,
		svc.StartPending: true,
		svc.Running:      true,
		svc.StopPending:  true,
	} {
		if got := runs(state); got != want {
			t.Errorf("runs(%d) = %v, want %v", state, got, want)
		}
	}
}
