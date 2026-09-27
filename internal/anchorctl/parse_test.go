package anchorctl

import (
	"testing"
	"time"
)

// The fixtures below are the exact shapes anchorctl prints: printStarted and the
// status printer in anchor's cmd/anchorctl/lifecycle.go, as a live alpha node printed
// them -- the tabwriter's two-space padding, the extra space Println leaves after
// "overlay ", the prefix length on the overlay address, the three-cell ipv4 row and
// the short realm path. Only the ID and the addresses are made up. If an anchor
// upgrade changes the shape, these fail, which is the entire point of pinning them.

const wantID = "anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq"

const startedOutput = `anchor ` + wantID + `
  underlay 203.0.113.9:41641
  overlay  fd80:c4b9:99ae:c540:9d81:a45c:141a:1ce5/48
  hardware 5a:f0:a9:da:4e:32
`

const statusOutput = `10:40:44  reachability=nat-cone  mtu=65521  peers=3  up=2h14m0s
  anchor       ` + wantID + `
  underlay     203.0.113.9:41641
  overlay      fd80:c4b9:99ae:c540:9d81:a45c:141a:1ce5/48
  ipv4         10.128.0.7/24    sent from and answered at, translated
  hardware     5a:f0:a9:da:4e:32
  realm        tglwuedqqa/snnfpxzuti
  cut depth 0  joined to the whole tree
  renew by     2026-10-04T10:40:39Z
  works until  2026-10-04T10:40:39Z
  proxy 8080/tcp  [fd80:c4b9:99ae:c540:9d81:a45c:141a:1ce5]:8080 → 127.0.0.1:3000
  proxy 53/udp    [fd80:c4b9:99ae:c540:9d81:a45c:141a:1ce5]:53 → 127.0.0.1:53  (1 live, 4 opened)
`

const notRunningOutput = "no anchor is running\n"

func TestParseStarted(t *testing.T) {
	if s := ParseStarted(startedOutput); s.ID != wantID {
		t.Errorf("ID = %q, want %q", s.ID, wantID)
	}
}

func TestParseStatus(t *testing.T) {
	st := ParseStatus(statusOutput)

	if !st.Running {
		t.Fatal("Running = false")
	}

	if st.ID != wantID {
		t.Errorf("ID = %q, want %q", st.ID, wantID)
	}

	if len(st.Overlay) != 1 || st.Overlay[0] != "fd80:c4b9:99ae:c540:9d81:a45c:141a:1ce5/48" {
		t.Errorf("Overlay = %v, want the one IPv6 address with its length", st.Overlay)
	}

	want := time.Date(2026, 10, 4, 10, 40, 39, 0, time.UTC)
	if !st.WorksUntil.Equal(want) {
		t.Errorf("WorksUntil = %v, want %v", st.WorksUntil, want)
	}
}

func TestParseStatusNotRunning(t *testing.T) {
	if st := ParseStatus(notRunningOutput); st.Running || st.ID != "" {
		t.Errorf("ParseStatus(%q) = %+v, want nothing running", notRunningOutput, st)
	}
}

// TestParseStartedIsResilient: garbage must not panic, and must not invent an ID.
func TestParseStartedIsResilient(t *testing.T) {
	for _, in := range []string{"", "\n", "anchor", "some unrelated error text", "anchor \n", "anchor x y\n"} {
		if got := ParseStarted(in).ID; got != "" {
			t.Errorf("ParseStarted(%q).ID = %q, want empty", in, got)
		}

		if got := ParseStatus(in); got.Running {
			t.Errorf("ParseStatus(%q).Running = true", in)
		}
	}
}

// metricsOutput is the head of `anchorctl metrics` from a live node, labelled series
// and an observation summary included.
const metricsOutput = `anchor_connections                                    1
anchor_frames_flooded_total                           0
anchor_gate_dropped_total{reason=not_quic}            0
anchor_lan_peers_found_total{iface=eth0}              2
anchor_overlay_mtu_bytes                              65521
anchor_rtt_seconds                                    n=3 mean=0.0011 min=0.0010 max=0.0012
`

func TestParseMetric(t *testing.T) {
	for name, want := range map[string]float64{
		MetricConnections:                          1,
		"anchor_overlay_mtu_bytes":                 65521,
		"anchor_lan_peers_found_total{iface=eth0}": 2,
	} {
		v, ok := ParseMetric(metricsOutput, name)
		if !ok || v != want {
			t.Errorf("ParseMetric(%s) = %v, %v; want %v", name, v, ok, want)
		}
	}

	// A labelled series is not its bare name, and a summary has no single value.
	for _, name := range []string{"anchor_lan_peers_found_total", "anchor_rtt_seconds", "anchor_absent"} {
		if v, ok := ParseMetric(metricsOutput, name); ok {
			t.Errorf("ParseMetric(%s) = %v, want absent", name, v)
		}
	}
}

// TestParseMetricIsResilient: no anchor, no metrics yet, and junk all read as absent
// rather than a panic. The supervisor reads this on a timer and must not die of it.
func TestParseMetricIsResilient(t *testing.T) {
	for _, in := range []string{"", "no metrics yet\n", "garbage\n", "no anchor is running\n", "anchor_connections\n"} {
		if v, ok := ParseMetric(in, MetricConnections); ok {
			t.Errorf("ParseMetric(%q) = %v, want absent", in, v)
		}
	}
}
