package daemon

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
)

// The readiness marker, and why a file.
//
// systemd asks for readiness and gets it: Type=notify means `systemctl restart conflux`
// returns when READY=1 arrives, so by the time the CLI looks, the anchor is up. launchd,
// rc and the Windows SCM have no equivalent, so without this `conflux up` would poll
// `anchorctl status` -- a fork -- once a second for news that had already happened.
//
// A file rather than a socket or a pipe: the two processes already share a directory and
// already agree about it, both are root, and a stat is the cheapest question either can
// ask. It is advisory throughout -- every reader falls back to the status call it replaced
// -- so a marker that is missing, stale or unreadable costs a second and never a start.

// MarkReady records that what the configuration runs is up: the anchor, by its AnchorID, or
// "observer" for a machine that only observes, and the pid of the process that says so. What
// goes in says to a human what the marker was about, lets a future reader tell two apart,
// and lets IsLiveReady tell a marker from one whose writer has gone.
func MarkReady(d paths.Dirs, anchorID string) error {
	line := time.Now().UTC().Format(time.RFC3339Nano) + " " + anchorID + " " + strconv.Itoa(os.Getpid()) + "\n"

	return config.WriteFileAtomic(d.ReadyFile(), []byte(line), 0o600)
}

// ClearReady withdraws it. A marker that is already gone is success, which is what every
// caller means: shutdown runs on paths that may never have written one.
func ClearReady(d paths.Dirs) error {
	if err := os.Remove(d.ReadyFile()); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// IsReady reports whether an anchor is up according to the marker: one that names a
// time and an anchor. Every caller treats "no marker" and "a marker it cannot read"
// alike -- fall back to asking anchorctl -- so there is no error to return.
func IsReady(d paths.Dirs) bool {
	b, err := os.ReadFile(d.ReadyFile())

	return err == nil && len(strings.Fields(string(b))) >= 2
}

// IsLiveReady is IsReady for a marker that counts only while the process that wrote it runs:
// an ephemeral run's, which gates whether another conflux may reach into the run's root at
// all. A run that is killed leaves its marker behind, and the next run, once it holds the
// root's lock, takes a moment to clear it; until then the old marker, read beside the new
// run's lock, would say that run is up while it is still emptying the root. A marker naming
// no writer, or one that has gone, is not ready.
func IsLiveReady(d paths.Dirs) bool {
	b, err := os.ReadFile(d.ReadyFile())
	if err != nil {
		return false
	}

	f := strings.Fields(string(b))
	if len(f) < 3 {
		return false
	}

	pid, err := strconv.Atoi(f[2])

	return err == nil && pid > 0 && alive(pid)
}
