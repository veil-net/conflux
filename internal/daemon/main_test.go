package daemon

import (
	"fmt"
	"os"
	"testing"

	"github.com/veil-net/conflux/internal/anchorctl"
)

// fakeAnchorctlEnv and fakeAnchordEnv turn this test binary into a stand-in anchorctl
// or anchord, so the paths that fork one are exercised with the fork in them and
// without a real daemon behind it.
const (
	fakeAnchorctlEnv = "CONFLUX_TEST_FAKE_ANCHORCTL"
	fakeAnchordEnv   = "CONFLUX_TEST_FAKE_ANCHORD"
)

func TestMain(m *testing.M) {
	switch {
	case os.Getenv(fakeAnchorctlEnv) == "1":
		os.Exit(fakeAnchorctl(os.Args[1:]))
	case os.Getenv(fakeAnchordEnv) == "1":
		os.Exit(fakeAnchord())
	}

	os.Exit(m.Run())
}

// fakeMetrics is the head of what `anchorctl metrics` printed on a live alpha node.
const fakeMetrics = `anchor_connections                                    1
anchor_frames_flooded_total                           0
anchor_gate_dropped_total{reason=not_quic}            0
anchor_handshakes_total                               1
anchor_lan_groups_joined_total                        1
anchor_lan_probes_refused_total{reason=credential}    0
anchor_overlay_mtu_bytes                              65521
anchor_peers_known                                    1
anchor_resource_held{kind=conns}                      1
anchor_rtt_seconds                                    n=3 mean=0.0011 min=0.0010 max=0.0012
anchor_translated_to_ipv6                             0
`

func fakeAnchorctl(args []string) int {
	if len(args) == 0 {
		return 2
	}

	switch args[0] {
	case "metrics":
		fmt.Print(fakeMetrics)
	case "renew", "stop":
		fmt.Println("ok")
	default:
		return 2
	}

	return 0
}

// fakeAnchordLastWords is what the stand-in anchord says on its way out, with no
// newline after the last of it: the line a failure report most needs is the one most
// easily lost.
const fakeAnchordLastWords = "control: the socket is held by another daemon"

func fakeAnchord() int {
	fmt.Println("anchord starting")
	fmt.Fprint(os.Stderr, fakeAnchordLastWords)

	return 1
}

func fakeCtl(tb testing.TB) *anchorctl.Ctl {
	tb.Helper()
	tb.Setenv(fakeAnchorctlEnv, "1")

	return &anchorctl.Ctl{Bin: os.Args[0], Socket: "unused", Token: "unused"}
}
