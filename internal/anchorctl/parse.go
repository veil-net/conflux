package anchorctl

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Parsing anchorctl's human output is not lovely, and it is still the right trade.
//
// The alternative for the one fact conflux genuinely needs -- the AnchorID, which
// the renewal route requires -- is `anchorctl id -identity FILE -root FILE`, and
// that wants the identity as a file on disk. Writing the private key out to learn a
// public name is a worse bargain than a regexp.
//
// What makes it safe is that these parsers are pinned by tests against literal
// output captured from the shipped binary. An anchor upgrade that changes the
// format fails a test here rather than a deployment somewhere else.

var (
	// anchorLine matches both `anchor <id>` from start and `  anchor  <id>` from
	// status, the latter padded by a tabwriter.
	anchorLine = regexp.MustCompile(`(?m)^\s*anchor\s+(anchor\S+)\s*$`)

	// headline is status's first line.
	headline = regexp.MustCompile(
		`reachability=(\S+)\s+mtu=(\d+)\s+peers=(\d+)\s+up=(\S+)`)

	// fieldLine matches a tabwriter row: two leading spaces, a key of up to three
	// words separated by single spaces, then the two-or-more spaces the tabwriter
	// pads with, then the value. Three words because "cut depth 0" is a key --
	// anchor puts the number in the label so the note beside it reads as prose.
	fieldLine = regexp.MustCompile(`(?m)^\s{2}(\S+(?: \S+){0,2})\s{2,}(.+?)\s*$`)
	proxyLine = regexp.MustCompile(`(?m)^\s{2}proxy\s+(\d+)/(\w+)\s{2,}(.+?)\s*$`)
)

// Started is what a successful `start` reported.
type Started struct {
	ID       string
	Underlay []string
	Overlay  []string
	Hardware string
}

// ParseStarted reads the output of `anchorctl start`.
//
// The ID comes free with the call conflux was making anyway, which is why this is
// the preferred of the three ways to learn it.
func ParseStarted(stdout string) Started {
	var s Started

	if m := anchorLine.FindStringSubmatch(stdout); m != nil {
		s.ID = m[1]
	}

	for line := range strings.Lines(stdout) {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}

		switch f[0] {
		case "underlay":
			s.Underlay = append(s.Underlay, f[1])
		case "overlay":
			s.Overlay = append(s.Overlay, f[1])
		case "hardware":
			s.Hardware = f[1]
		}
	}

	return s
}

// Status is what `anchorctl status` reported.
type Status struct {
	Running      bool
	ID           string
	Reachability string
	MTU          int
	Peers        int
	Up           time.Duration
	Underlay     []string
	Overlay      []string
	Hardware     string
	Realm        string
	CutDepth     int
	RenewBy      time.Time
	WorksUntil   time.Time
	Proxies      []string
}

// ParseStatus reads the output of `anchorctl status`.
func ParseStatus(stdout string) Status {
	var st Status

	if strings.Contains(stdout, "no anchor is running") {
		return st
	}

	if m := anchorLine.FindStringSubmatch(stdout); m != nil {
		st.Running = true
		st.ID = m[1]
	}

	if m := headline.FindStringSubmatch(stdout); m != nil {
		st.Reachability = m[1]
		st.MTU, _ = strconv.Atoi(m[2])
		st.Peers, _ = strconv.Atoi(m[3])
		st.Up, _ = time.ParseDuration(m[4])
	}

	for _, m := range proxyLine.FindAllStringSubmatch(stdout, -1) {
		st.Proxies = append(st.Proxies, m[1]+"/"+m[2]+" "+m[3])
	}

	for _, m := range fieldLine.FindAllStringSubmatch(stdout, -1) {
		key, value := m[1], m[2]

		switch {
		case key == "underlay":
			st.Underlay = append(st.Underlay, value)
		case key == "overlay":
			st.Overlay = append(st.Overlay, value)
		case key == "hardware":
			st.Hardware = value
		case key == "realm":
			st.Realm = value
		case key == "renew by":
			st.RenewBy, _ = time.Parse(time.RFC3339, value)
		case key == "works until":
			st.WorksUntil, _ = time.Parse(time.RFC3339, value)
		case strings.HasPrefix(key, "cut depth"):
			st.CutDepth, _ = strconv.Atoi(strings.TrimPrefix(key, "cut depth "))
		}
	}

	return st
}

// MetricConnections is the gauge conflux watches: how many QUIC connections the
// anchor is holding right now.
//
// On an uplink it is the whole story. A link is point-to-point and carries exactly
// one peer, so a sustained zero is a link that has ended rather than a realm that is
// quiet -- and anchor does not reopen a link that ends.
const MetricConnections = "anchor_connections"

// ParseMetrics reads the output of `anchorctl metrics`.
//
// One sample per line, name then value, padded by a tabwriter. Samples that are
// neither a counter nor a gauge -- the observation summaries, "n=3 mean=..." -- have
// no single value and are skipped rather than half-read. A labelled sample carries
// its labels in the name, which is what keeps them distinct here.
func ParseMetrics(stdout string) map[string]float64 {
	out := map[string]float64{}

	for line := range strings.Lines(stdout) {
		name, value, ok := strings.Cut(strings.TrimSpace(line), "  ")
		if !ok {
			continue
		}

		v, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil {
			continue
		}

		out[strings.TrimSpace(name)] = v
	}

	return out
}

// Cut reports whether this anchor's realm has been severed from the tree above it.
// Its own peers still work; ours stop being reachable.
func (s Status) Cut() bool { return s.CutDepth > 0 }
