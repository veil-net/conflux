package logfile

import (
	"path/filepath"
	"testing"
	"time"
)

// BenchmarkWrite is one supervisor log line: stamped, and appended to the file.
func BenchmarkWrite(b *testing.B) {
	w, err := open(filepath.Join(b.TempDir(), "conflux.log"), 1<<62, time.Now, false)
	if err != nil {
		b.Fatal(err)
	}

	defer w.Close()

	line := []byte("  anchor is up: 3 peers, 2 routes, renewal in 19d 23h\n")

	b.ReportAllocs()

	for b.Loop() {
		if _, err := w.Write(line); err != nil {
			b.Fatal(err)
		}
	}
}
