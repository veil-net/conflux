package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
)

// fakeAnchorctlEnv turns this test binary into a stand-in anchorctl, so the paths that
// fork one are measured with the fork in them and without a daemon behind it.
const fakeAnchorctlEnv = "CONFLUX_TEST_FAKE_ANCHORCTL"

func TestMain(m *testing.M) {
	if os.Getenv(fakeAnchorctlEnv) == "1" {
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

func fakeCtl(b *testing.B) *anchorctl.Ctl {
	b.Helper()
	b.Setenv(fakeAnchorctlEnv, "1")

	return &anchorctl.Ctl{Bin: os.Args[0], Socket: "unused", Token: "unused"}
}

// settledGoroutines waits out whatever setup left running -- libexec sweeps old sets in
// the background -- so the count a loop is measured against is a floor.
func settledGoroutines() int {
	n := runtime.NumGoroutine()

	for range 50 {
		time.Sleep(10 * time.Millisecond)

		m := runtime.NumGoroutine()
		if m == n {
			return n
		}

		n = m
	}

	return n
}

// reportGoroutines records how many goroutines outlived the loop. Zero is the answer
// every path here must give: anything else is a leak per iteration or per run.
func reportGoroutines(b *testing.B, before int) {
	b.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	b.ReportMetric(float64(runtime.NumGoroutine()-before), "goroutines-left")
}

// BenchmarkLinkCheck is one tick of the uplink watcher: an anchorctl metrics round trip
// and the parse that decides whether the link still carries anything.
func BenchmarkLinkCheck(b *testing.B) {
	s := &Supervisor{ctl: fakeCtl(b)}
	ctx := context.Background()

	var zeroSince time.Time

	before := settledGoroutines()

	b.ReportAllocs()

	for b.Loop() {
		if dead, _ := s.linkIsDead(ctx, "", &zeroSince); dead {
			b.Fatal("a link carrying a connection read as dead")
		}
	}

	reportGoroutines(b, before)
}

// BenchmarkRenewal is the whole of a timer renewal against a stand-in API: the lock, the
// stored files, the POST, the splice, the writes and the hot install.
func BenchmarkRenewal(b *testing.B) {
	b.Setenv("CONFLUX_DIR", b.TempDir())
	b.Setenv("CONFLUX_ALLOW_INSECURE_API", "1")

	chain := base64.StdEncoding.EncodeToString(make([]byte, 6<<10))

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"chain":    chain,
			"notAfter": time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	b.Cleanup(api.Close)

	d := benchDirs(b)
	cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"bench"}, APIBaseURL: api.URL}

	if err := config.Save(d, cfg); err != nil {
		b.Fatal(err)
	}

	if err := config.SaveState(d, &config.State{AnchorID: "anchorbench"}); err != nil {
		b.Fatal(err)
	}

	doc, _ := json.Marshal(map[string]any{
		"formatVersion": 1, "kind": "anchor", "identity": "00", "genesis": "00", "chain": chain,
		"issuedAt": time.Now().UTC().Format(time.RFC3339), "notAfter": time.Now().UTC().Format(time.RFC3339),
		"renewalUrl": api.URL + "/ghosts/alpha/renew", "renewalAuth": "anchor-id",
	})

	if err := config.SaveManifest(d, config.Envelope(base64.StdEncoding.EncodeToString(doc))); err != nil {
		b.Fatal(err)
	}

	ctl := fakeCtl(b)
	ctx := context.Background()
	before := settledGoroutines()

	b.ReportAllocs()

	for b.Loop() {
		if err := RenewNow(ctx, d, ctl, nil); err != nil {
			b.Fatal(err)
		}
	}

	api.CloseClientConnections()
	reportGoroutines(b, before)
}

// BenchmarkDaemonLifecycle is one supervised anchord lifetime without an anchor in it:
// spawn, the readiness probe, and the shutdown that closes and reaps it.
func BenchmarkDaemonLifecycle(b *testing.B) {
	if !anchor.Supported {
		b.Skip("no anchor pair for this platform")
	}

	b.Setenv("CONFLUX_DIR", b.TempDir())

	d := benchDirs(b)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"bench"}}); err != nil {
		b.Fatal(err)
	}

	tools, err := libexec.Ensure(d)
	if err != nil {
		b.Fatal(err)
	}

	s := &Supervisor{Dirs: d, tools: tools, tail: newRing(tailLines)}

	token, err := s.freshToken()
	if err != nil {
		b.Fatal(err)
	}

	s.ctl = &anchorctl.Ctl{Bin: tools.Anchorctl, Socket: d.Socket(), Token: token, SetID: tools.SetID}

	ctx := context.Background()
	before := settledGoroutines()

	b.ReportAllocs()

	for b.Loop() {
		cmd, done, err := s.spawn(ctx)
		if err != nil {
			b.Fatal(err)
		}

		if err := s.waitReady(ctx, done); err != nil {
			b.Fatal(err)
		}

		s.shutdown(cmd, done)
	}

	reportGoroutines(b, before)
}

func benchDirs(b *testing.B) paths.Dirs {
	b.Helper()

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		b.Fatal(err)
	}

	return d
}
