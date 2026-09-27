package anchorctl

import (
	"strconv"
	"strings"
	"time"
)

// Parsing anchorctl's human output is not lovely, and it is still the right trade.
//
// The alternative for the one fact conflux genuinely needs -- the AnchorID, which
// the renewal route requires -- is `anchorctl id -identity FILE -root FILE`, and
// that wants the identity as a file on disk. Writing the private key out to learn a
// public name is a worse bargain than reading a line.
//
// What makes it safe is that these parsers are pinned by tests against output in the
// shape the shipped binary prints it. An anchor upgrade that changes the format fails
// a test here rather than a deployment somewhere else.
//
// Every line that matters is a key and a value, the key first: `anchor ID` from
// start, and the tabwriter rows of status, `  overlay  ADDR` and `  works until  TIME`.
// So each is read by its leading fields, and a line of any other shape is skipped.

// Started is what a successful `start` reported.
type Started struct {
	ID string
}

// ParseStarted reads the output of `anchorctl start`.
//
// The ID comes free with the call conflux was making anyway, which is why this is
// the preferred way to learn it.
func ParseStarted(stdout string) Started {
	var s Started

	for line := range strings.Lines(stdout) {
		if id, ok := anchorID(strings.Fields(line)); ok {
			s.ID = id

			break
		}
	}

	return s
}

// Status is what `anchorctl status` reported, as far as conflux reads it.
type Status struct {
	Running    bool
	ID         string
	Overlay    []string
	WorksUntil time.Time
}

// ParseStatus reads the output of `anchorctl status`.
func ParseStatus(stdout string) Status {
	var st Status

	for line := range strings.Lines(stdout) {
		f := strings.Fields(line)

		if id, ok := anchorID(f); ok {
			st.Running, st.ID = true, id

			continue
		}

		switch {
		case len(f) == 2 && f[0] == "overlay":
			st.Overlay = append(st.Overlay, f[1])
		case len(f) == 3 && f[0] == "works" && f[1] == "until":
			st.WorksUntil, _ = time.Parse(time.RFC3339, f[2])
		}
	}

	return st
}

// anchorID reads the `anchor ID` line both commands print first.
func anchorID(f []string) (string, bool) {
	if len(f) == 2 && f[0] == "anchor" && strings.HasPrefix(f[1], "anchor") {
		return f[1], true
	}

	return "", false
}

// MetricConnections is the gauge conflux watches: how many QUIC connections the
// anchor is holding right now.
//
// On an uplink it is the whole story. A link is point-to-point and carries exactly
// one peer, so a sustained zero is a link that has ended rather than a realm that is
// quiet -- and anchor does not reopen a link that ends.
const MetricConnections = "anchor_connections"

// ParseMetric reads one sample from the output of `anchorctl metrics`.
//
// One sample per line, name then value, padded by a tabwriter. A labelled sample
// carries its labels in the name, so asking for a bare name finds only the unlabelled
// series. An observation summary -- "n=3 mean=..." -- has no single value and reads
// as absent rather than half-read.
func ParseMetric(stdout, name string) (float64, bool) {
	for line := range strings.Lines(stdout) {
		f := strings.Fields(line)
		if len(f) != 2 || f[0] != name {
			continue
		}

		v, err := strconv.ParseFloat(f[1], 64)

		return v, err == nil
	}

	return 0, false
}
