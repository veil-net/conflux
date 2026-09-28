package daemon

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"

	"github.com/veil-net/conflux/internal/anchorctl"
)

// fakeAnchorctlEnv and fakeAnchordEnv turn this test binary into a stand-in anchorctl
// or anchord, so the paths that fork one are exercised with the fork in them and
// without a real daemon behind it. fakeAnchordEnv is "1" for a daemon that dies at
// once, and "serve" for one that runs until it is signalled. fakeAnchorctlLogEnv,
// when set, names a file the stand-in anchorctl appends each command it ran to.
const (
	fakeAnchorctlEnv    = "CONFLUX_TEST_FAKE_ANCHORCTL"
	fakeAnchorctlLogEnv = "CONFLUX_TEST_FAKE_ANCHORCTL_LOG"
	fakeAnchordEnv      = "CONFLUX_TEST_FAKE_ANCHORD"
)

func TestMain(m *testing.M) {
	// The two are told apart by argv as well as by the environment, since a stand-in
	// anchord inherits whatever the test set for anchorctl: anchord is always started
	// -socket first, and anchorctl with a command.
	switch daemon := len(os.Args) > 1 && os.Args[1] == "-socket"; {
	case daemon && os.Getenv(fakeAnchordEnv) == "1":
		os.Exit(fakeAnchord())
	case daemon && os.Getenv(fakeAnchordEnv) == "serve":
		os.Exit(fakeServingAnchord())
	case os.Getenv(fakeAnchorctlEnv) == "1":
		os.Exit(fakeAnchorctl(os.Args[1:]))
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

	if log := os.Getenv(fakeAnchorctlLogEnv); log != "" {
		if f, err := os.OpenFile(log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			fmt.Fprintln(f, args[0])
			f.Close()
		}
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

// fakeServingAnchord runs until it is asked to stop, and then stops, as anchord does
// on SIGTERM once it has closed its anchor.
func fakeServingAnchord() int {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	fmt.Println("anchord listening")
	<-stop

	return 0
}

func fakeCtl(tb testing.TB) *anchorctl.Ctl {
	tb.Helper()
	tb.Setenv(fakeAnchorctlEnv, "1")

	return &anchorctl.Ctl{Bin: os.Args[0], Socket: "unused", Token: "unused"}
}
