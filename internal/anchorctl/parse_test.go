package anchorctl

import (
	"testing"
)

// The fixtures below are the exact shapes anchorctl prints: printStarted and the
// status printer in anchor's cmd/anchorctl/lifecycle.go, as a live alpha node printed
// them -- the tabwriter padding every row to the widest key, the extra space Println
// leaves after "overlay ", the prefix length on the overlay address, the three-cell
// ipv4 row with a bare address, the short realm path, and proxy rows naming the IPv4
// listener beside the overlay one. Only the ID and the addresses are made up. If an
// anchor upgrade changes the shape, these fail, which is the entire point of pinning
// them.

const wantID = "anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq"

const startedOutput = `anchor ` + wantID + `
  underlay 203.0.113.9:41641
  overlay  fd80:c4b9:99ae:c540:9d81:a45c:141a:1ce5/48
  hardware 5a:f0:a9:da:4e:32
`

const statusOutput = `10:40:44  reachability=nat-cone  mtu=65521  peers=3  up=2h14m0s
  anchor          ` + wantID + `
  underlay        203.0.113.9:41641
  overlay         fd80:c4b9:99ae:c540:9d81:a45c:141a:1ce5/48
  ipv4            10.128.0.7  sent from and answered at, translated
  hardware        5a:f0:a9:da:4e:32
  fips140         on, Go Cryptographic Module v1.26.0
  realm           tglwuedqqa/snnfpxzuti
  cut depth 0     joined to the whole tree
  renew by        2026-10-04T10:40:39Z
  works until     2026-10-04T10:40:39Z
  proxy 53/udp    [fd80:c4b9:99ae:c540:9d81:a45c:141a:1ce5]:53, 10.128.0.7:53 → 127.0.0.1:53  (1 live, 4 opened)
  proxy 8080/tcp  [fd80:c4b9:99ae:c540:9d81:a45c:141a:1ce5]:8080, 10.128.0.7:8080 → 127.0.0.1:3000
  observer        not observing
`

const notRunningOutput = "no anchor is running\n  fips140   on, Go Cryptographic Module v1.26.0\n  observer  not observing\n"

// What status prints of the observer, which anchord always serves: the row comes last, padded
// with the rest of its block, beside an anchor and with none -- observing, under a credential
// whose expiry the row carries, stopped, and stopped by a capture that ended.
const (
	observingAloneOutput = `no anchor is running
  fips140   off, Go Cryptographic Module latest
  observer  af_packet, 2 flows held, 32 packets taken; credential valid until 2026-12-24T05:17:38Z
`
	observerFailedOutput = `no anchor is running
  fips140   off, Go Cryptographic Module latest
  observer  not observing: capture: reading the ring: network is down
`
	observingBesideOutput = `10:40:44  reachability=nat-cone  mtu=65521  peers=3  up=2h14m0s
  anchor          ` + wantID + `
  fips140         on, Go Cryptographic Module v1.26.0
  works until     2026-10-04T10:40:39Z
  observer        af_packet, 12 flows held, 3480 packets taken, 7 copies dropped; credential valid until 2026-10-04T10:40:39Z
`
)

// What anchor prints beside a TUN anchor: the observer's row carrying the overlay's figures
// after its own, and the credential's expiry after those, and the interface row a TUN anchor
// adds after the IPv4 one, named after the anchor, as the status printer in anchor's
// cmd/anchorctl/lifecycle.go places it.
const tunObservingOutput = `04:16:16  reachability=unknown  mtu=65510  peers=0  up=2s
  anchor       anchorqsgwfbu4sk2mkzxmmsydbzcj2cg7rstcjrmsekf2bpaxsdiinmyq
  underlay     192.0.2.2:49055
  overlay      fd71:ff98:76e8:d537:85a5:1bce:c340:f9bb/48
  ipv4         100.127.255.254  sent from, translated; not advertised, so peers cannot reach it
  interface    anchorqsgwfbu4s
  hardware     6a:a7:8f:8b:b1:09
  fips140      on, Go Cryptographic Module v1.26.0
  realm        eocs6meuty
  cut depth 0  joined to the whole tree
  renew by     2026-11-02T04:16:00Z
  works until  2026-11-02T04:16:00Z
  observer     af_packet, 5 flows held, 24 packets taken; overlay of qsgwfbu4sk, 0 flows held, 0 packets taken; credential valid until 2026-11-02T04:16:00Z
`
func TestParseStatusNotRunning(t *testing.T) {
	if st := ParseStatus(notRunningOutput); st.Running || st.ID != "" {
		t.Errorf("ParseStatus(%q) = %+v, want nothing running", notRunningOutput, st)
	}
}

func TestParseStatusReadsTheObserver(t *testing.T) {
	for name, tc := range map[string]struct {
		out          string
		anchor, runs bool
		failed       bool
		note         string
	}{
		"observing, no anchor":   {observingAloneOutput, false, true, false, "af_packet, 2 flows held, 32 packets taken; credential valid until 2026-12-24T05:17:38Z"},
		"stopped, no anchor":     {notRunningOutput, false, false, false, "not observing"},
		"failed, no anchor":      {observerFailedOutput, false, false, true, "not observing: capture: reading the ring: network is down"},
		"beside an anchor":       {observingBesideOutput, true, true, false, "af_packet, 12 flows held, 3480 packets taken, 7 copies dropped; credential valid until 2026-10-04T10:40:39Z"},
		"and its overlay":        {tunObservingOutput, true, true, false, "af_packet, 5 flows held, 24 packets taken; overlay of qsgwfbu4sk, 0 flows held, 0 packets taken; credential valid until 2026-11-02T04:16:00Z"},
		"stopped, beside anchor": {statusOutput, true, false, false, "not observing"},
	} {
		st := ParseStatus(tc.out)

		if st.Running != tc.anchor {
			t.Errorf("%s: Running = %v, want %v", name, st.Running, tc.anchor)
		}

		o := st.Observer
		if o.Running != tc.runs || o.Failed() != tc.failed || o.Note != tc.note {
			t.Errorf("%s: Observer = %+v (failed %v), want running %v, failed %v, note %q",
				name, o, o.Failed(), tc.runs, tc.failed, tc.note)
		}
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
anchor_rtt_seconds                                    n=4 mean=0.00214123575 min=0.001294105 max=0.002989687
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

// TestParseMetricIsResilient: no metrics yet, and junk, read as absent rather than a
// panic. The supervisor reads this on a timer and must not die of it. (No anchor at all
// is not output: anchorctl metrics fails, and the watcher asks status instead.)
func TestParseMetricIsResilient(t *testing.T) {
	for _, in := range []string{"", "no metrics yet\n", "garbage\n", "anchor_connections\n"} {
		if v, ok := ParseMetric(in, MetricConnections); ok {
			t.Errorf("ParseMetric(%q) = %v, want absent", in, v)
		}
	}
}

// TestParseObservingReadsTheIdentity: the AnchorID the observer runs as, from its `as` row as a
// live anchord printed it, which is where a machine that only observes learns the ID its
// credential is renewed by; and nothing from output that names none.
func TestParseObservingReadsTheIdentity(t *testing.T) {
	const live = `observing with  af_packet
  since         0s
  flows         0 held
  packets       0 taken
  overlay       no anchor running
  records       0, in 0 inventory entries
  as            anchork3v7q7rzt2fwxm4hbe6ndl5tsgcaypuvy3iq7jkob2zr45hxwdmq
  realm         4fh2aq7xkd
  credential    valid until 2027-11-17T00:00:00Z
`

	if got := ParseObserving(live); got != "anchork3v7q7rzt2fwxm4hbe6ndl5tsgcaypuvy3iq7jkob2zr45hxwdmq" {
		t.Errorf("ParseObserving = %q", got)
	}

	if got := ParseObserving("not observing\n  packets  0 taken\n"); got != "" {
		t.Errorf("ParseObserving of an observer naming no identity = %q, want none", got)
	}
}
