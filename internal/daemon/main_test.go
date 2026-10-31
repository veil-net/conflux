package daemon

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"testing"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/paths"
)

// fakeAnchorctlEnv and fakeAnchordEnv turn this test binary into a stand-in anchorctl
// or anchord, so the paths that fork one are exercised with the fork in them and
// without a real daemon behind it. fakeAnchordEnv is "1" for a daemon that dies at
// once, and "serve" for one that runs until it is signalled. fakeAnchorctlLogEnv,
// when set, names a file the stand-in anchorctl appends each command it ran to,
// fakeAnchorctlFailEnv a command it refuses, and fakeAnchorctlStatusEnv what its
// status says: "running", or "none" for a daemon holding no anchor. fakeAnchorctlObserverEnv
// is the observer's row in it -- "running", "stopped", "failed", or none at all -- and
// fakeAnchorctlCaptureEnv set makes `observe -start` refuse as a host that will not let the
// daemon capture does.
const (
	fakeAnchorctlEnv         = "CONFLUX_TEST_FAKE_ANCHORCTL"
	fakeAnchorctlLogEnv      = "CONFLUX_TEST_FAKE_ANCHORCTL_LOG"
	fakeAnchorctlFailEnv     = "CONFLUX_TEST_FAKE_ANCHORCTL_FAIL"
	fakeAnchorctlStatusEnv   = "CONFLUX_TEST_FAKE_ANCHORCTL_STATUS"
	fakeAnchorctlObserverEnv = "CONFLUX_TEST_FAKE_ANCHORCTL_OBSERVER"
	fakeAnchorctlCaptureEnv  = "CONFLUX_TEST_FAKE_ANCHORCTL_NO_CAPTURE"
	fakeAnchordEnv           = "CONFLUX_TEST_FAKE_ANCHORD"
	fakeAnchordListenEnv     = "CONFLUX_TEST_FAKE_ANCHORD_LISTEN"
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
anchor_rtt_seconds                                    n=4 mean=0.00214123575 min=0.001294105 max=0.002989687
anchor_translated_to_ipv6                             0
`

// fakeStarted is what `anchorctl start` prints for the anchor it started.
const fakeStarted = `anchor ` + fakeAnchorID + `
  underlay 203.0.113.9:41641
  overlay  fd80:c4b9:99ae:c540:9d81:a45c:141a:1ce5/48
  hardware 5a:f0:a9:da:4e:32
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
	case os.Getenv(fakeAnchorctlFailEnv):
		fmt.Fprintln(os.Stderr, "refused")

		return 1
	case "metrics":
		fmt.Print(fakeMetrics)
	case "start":
		// The manifest arrives on stdin, as it does for the real one, and is read to the end
		// so the writer never meets a closed pipe.
		_, _ = io.Copy(io.Discard, os.Stdin)

		fmt.Print(fakeStarted)
	case "renew", "stop":
		fmt.Println("ok")
	case "observe":
		// What anchorctl says of a host that will not let the daemon capture, on stderr.
		if len(args) > 1 && args[1] == "-start" && os.Getenv(fakeAnchorctlCaptureEnv) != "" {
			fmt.Fprintln(os.Stderr, "anchorctl: capture: not permitted: open a packet socket: operation not permitted (it needs CAP_NET_RAW)\n"+
				"  capturing needs CAP_NET_RAW for the daemon on Linux, read access to /dev/bpf* on macOS, "+
				"Administrators or Performance Log Users on Windows; give the daemon that, then \"anchorctl observe -start\" again")

			return 1
		}

		fmt.Println("observing with  af_packet")
	case "status":
		switch os.Getenv(fakeAnchorctlStatusEnv) {
		case "running":
			fmt.Println("anchor       " + fakeAnchorID)
		case "none":
			fmt.Println("no anchor is running")
		default:
			return 2
		}

		switch os.Getenv(fakeAnchorctlObserverEnv) {
		case "running":
			fmt.Println("  observer  af_packet, 2 flows held, 32 packets taken")
		case "stopped":
			fmt.Println("  observer  not observing")
		case "failed":
			fmt.Println("  observer  not observing: capture: reading the ring: network is down")
		}
	default:
		return 2
	}

	return 0
}

// fakeAnchorID is the anchor the stand-in anchorctl reports running.
const fakeAnchorID = "anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq"

// fakeAnchordLastWords is what the stand-in anchord says on its way out, with no
// newline after the last of it: the line a failure report most needs is the one most
// easily lost.
const fakeAnchordLastWords = "control: /run/conflux/anchord/sock is already served by a running daemon"

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

	// The socket, where a test asks for one, for the supervisor's readiness probe to find
	// something listening on; what it asks after that goes to the stand-in anchorctl.
	if os.Getenv(fakeAnchordListenEnv) == "" {
		fmt.Println("anchord listening")
		<-stop

		return 0
	}

	if l, err := net.Listen("unix", os.Args[2]); err == nil {
		defer l.Close()

		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}

				c.Close()
			}
		}()
	}

	fmt.Println("anchord listening")
	<-stop

	return 0
}

func fakeCtl(tb testing.TB) *anchorctl.Ctl {
	tb.Helper()
	tb.Setenv(fakeAnchorctlEnv, "1")

	// A race-built binary waits a second at exit for other goroutines to report, and
	// every stand-in is this binary: a second a fork, for a process with one goroutine.
	tb.Setenv("GORACE", "atexit_sleep_ms=0")

	return &anchorctl.Ctl{Bin: os.Args[0], Socket: "unused", Token: "unused"}
}

// dirs roots a test's every path in a directory of its own, and makes the roots.
//
// Under /tmp on macOS rather than the test's own directory: a Unix socket's path is 104 bytes
// at most there, and TMPDIR is long enough that a stand-in anchord could not listen on the
// socket the supervisor probes.
func dirs(tb testing.TB) paths.Dirs {
	tb.Helper()

	root := tb.TempDir()
	if runtime.GOOS == "darwin" {
		short, err := os.MkdirTemp("/tmp", "cfx")
		if err != nil {
			tb.Fatal(err)
		}

		tb.Cleanup(func() { _ = os.RemoveAll(short) })
		root = short
	}

	tb.Setenv("CONFLUX_DIR", root)

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		tb.Fatalf("EnsureAll: %v", err)
	}

	// anchord's own, which the supervisor makes afresh before each start and a test that
	// stands in for a daemon writes its socket into.
	if err := os.MkdirAll(d.DaemonRun(), 0o700); err != nil {
		tb.Fatal(err)
	}

	return d
}
