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
// systemd asks for one and gets it: Type=notify means `systemctl restart conflux` returns
// when READY=1 arrives, so by the time the CLI looks, the anchor is up and its first
// status call succeeds. systemd.service(5) is explicit -- "systemd will proceed with
// starting follow-up units after this notification message has been sent".
//
// launchd and the Windows SCM have no equivalent. launchd infers readiness from the
// process staying alive, and the SCM is told by the service handler but tells nobody else.
// So on those two `conflux up` had nothing to wait on and polled `anchorctl status` once a
// second, forking a 43 MB binary each time, on a path where Defender and Gatekeeper both
// have opinions about a freshly written executable.
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

// ReadyAnchor is the AnchorID the marker names, or "" when there is no usable marker.
//
// Deliberately not an error return. Every caller treats "no marker" and "a marker I cannot
// read" the same way -- fall back to asking anchorctl -- so distinguishing them would be a
// distinction none of them could act on.
func ReadyAnchor(d paths.Dirs) string {
	b, err := os.ReadFile(d.ReadyFile())
	if err != nil {
		return ""
	}

	fields := strings.Fields(string(b))
	if len(fields) < 2 {
		return ""
	}

	return fields[1]
}

// IsReady reports whether an anchor is up according to the marker.
func IsReady(d paths.Dirs) bool { return ReadyAnchor(d) != "" }
