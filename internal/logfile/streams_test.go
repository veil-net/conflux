package logfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWhatTheRuntimeWritesLandsInTheLog: the log is placed over the process's own standard
// streams, so what the runtime writes there itself -- a panic, which no logger sees -- is in
// the file, under the Windows service control manager as under launchd and daemon(8).
func TestWhatTheRuntimeWritesLandsInTheLog(t *testing.T) {
	t.Cleanup(keepStandardStreams(t))

	path := filepath.Join(t.TempDir(), "conflux.log")

	w, err := open(path, Max, fixed, true)
	if err != nil {
		t.Fatal(err)
	}

	defer w.Close()

	println("conflux: what the runtime writes itself")

	if got, _ := os.ReadFile(path); !strings.Contains(string(got), "conflux: what the runtime writes itself\n") {
		t.Errorf("the log does not hold what the runtime wrote to stderr; it holds %q", got)
	}
}
