// Package logfile is the boot service's log where conflux writes it itself: the file launchd
// and daemon(8) were given on macOS and FreeBSD, and the Windows service's. systemd's journal
// and OpenBSD's syslog stamp and rotate their own, and are left to.
//
// Each line is stamped with when it was written, and once the file passes Max it is moved
// aside to <path>.1, replacing the one before, so the log never holds more than two files.
package logfile

import (
	"bytes"
	"os"
	"sync"
	"time"
)

// Max is how large the file grows before it is moved aside.
const Max = 10 << 20

// stamp is how each line starts: the time, to the millisecond, in UTC.
const stamp = "2006-01-02T15:04:05.000Z "

// File is the log, an io.Writer safe for the supervisor's goroutines to share.
type File struct {
	mu   sync.Mutex
	path string
	max  int64
	now  func() time.Time

	// redirect places the file over the process's stdout and stderr each time it is
	// opened, so what the runtime writes there itself -- a panic -- lands in it too.
	redirect bool

	f    *os.File
	size int64

	// mid is a last write that ended part-way through a line, whose rest is not stamped.
	mid bool
}

// Open appends to the log at path, made 0600 if it is not there, and places it over the
// process's stdout and stderr.
func Open(path string) (*File, error) { return open(path, Max, time.Now, true) }

func open(path string, max int64, now func() time.Time, redirect bool) (*File, error) {
	w := &File{path: path, max: max, now: now, redirect: redirect}
	if err := w.reopen(); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *File) reopen() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()

		return err
	}

	if w.redirect {
		standardStreams(f)
	}

	w.f, w.size = f, fi.Size()

	return nil
}

// Write stamps each line that p starts, and moves the file aside first when it is full: at
// the start of a line, so none is split between the two.
func (w *File) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	written := 0

	for len(p) > 0 {
		line := p
		if i := bytes.IndexByte(p, '\n'); i >= 0 {
			line = p[:i+1]
		}

		var b []byte

		if !w.mid {
			if w.size >= w.max {
				w.rotate()
			}

			b = w.now().UTC().AppendFormat(b, stamp)
		}

		if w.f == nil {
			if err := w.reopen(); err != nil {
				return written, err
			}
		}

		b = append(b, line...)

		n, err := w.f.Write(b)
		w.size += int64(n)

		if err != nil {
			return written, err
		}

		written += len(line)
		p = p[len(line):]
		w.mid = line[len(line)-1] != '\n'
	}

	return written, nil
}

// rotate moves the file aside and starts another. Closed first, since Windows renames no
// file that is open. Best effort: where the move fails -- somebody holds the file open on
// Windows -- the same file is opened again and grows on, and the next line tries again.
func (w *File) rotate() {
	w.f.Close()
	w.f = nil

	_ = os.Rename(w.path, w.path+".1")
	_ = w.reopen() // and where it fails, the next write tries again, and says why
}

// Close closes the file.
func (w *File) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.f == nil {
		return nil
	}

	err := w.f.Close()
	w.f = nil

	return err
}

// Remove deletes the log at path and the one moved aside from it.
func Remove(path string) error {
	for _, p := range []string{path, path + ".1"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	return nil
}
