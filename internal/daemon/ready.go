package daemon

import (
	"os"
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

// MarkReady records that an anchor is up. The AnchorID goes in so a marker that is read by
// a human says which anchor it was about, and so a future reader can tell two apart.
func MarkReady(d paths.Dirs, anchorID string) error {
	line := time.Now().UTC().Format(time.RFC3339Nano) + " " + anchorID + "\n"

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
