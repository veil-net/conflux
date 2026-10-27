package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
)

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
		if dead, _, _ := s.linkIsDead(ctx, "", &zeroSince); dead {
			b.Fatal("a link carrying a connection read as dead")
		}
	}

	reportGoroutines(b, before)
}

// BenchmarkLinkCheckWithDevice is the same tick on a device uplink, which looks for the
// device on the filesystem before it asks the daemon.
func BenchmarkLinkCheckWithDevice(b *testing.B) {
	device := filepath.Join(b.TempDir(), "ttyUSB0")
	if err := os.WriteFile(device, nil, 0o600); err != nil {
		b.Fatal(err)
	}

	s := &Supervisor{ctl: fakeCtl(b)}
	ctx := context.Background()

	var zeroSince time.Time

	before := settledGoroutines()

	b.ReportAllocs()

	for b.Loop() {
		if dead, _, _ := s.linkIsDead(ctx, device, &zeroSince); dead {
			b.Fatal("a device that is present, carrying a connection, read as dead")
		}
	}

	reportGoroutines(b, before)
}

// BenchmarkAnchordOutput is anchord's output on its way to the tail and the reporter: what
// every line the daemon writes costs the supervisor.
func BenchmarkAnchordOutput(b *testing.B) {
	s := &Supervisor{tail: newRing(tailLines)}
	w := s.lines()

	line := []byte(`time=2026-10-13T16:22:15.338Z level=INFO msg="anchor listening" component=anchor ` +
		`id=anchorpecpoflwfnftrb6mc2nbp356zmrmx5uogmvtuomfdxigkxzq647a addr=0.0.0.0:33759` + "\n")

	b.ReportAllocs()
	b.SetBytes(int64(len(line)))

	for b.Loop() {
		_, _ = w.Write(line)
	}
}

// BenchmarkBringUp is the start every boot and every `conflux up` makes with a credential
// in hand: the lock, the stored files, the taints check, anchorctl start and the state
// written back.
func BenchmarkBringUp(b *testing.B) {
	d := benchSite(b)

	ctl := fakeCtl(b)
	ctx := context.Background()
	before := settledGoroutines()

	b.ReportAllocs()

	for b.Loop() {
		if _, err := bringUp(ctx, d, ctl, nopReporter{}, d.RootAnchorDir(), false); err != nil {
			b.Fatal(err)
		}
	}

	reportGoroutines(b, before)
}

// BenchmarkAnchorCheck is one tick of the watcher on the host's network: an anchorctl
// status round trip and the parse that decides whether the daemon still holds an anchor.
func BenchmarkAnchorCheck(b *testing.B) {
	b.Setenv(fakeAnchorctlStatusEnv, "running")

	s := &Supervisor{ctl: fakeCtl(b)}
	ctx := context.Background()

	var zeroSince time.Time

	before := settledGoroutines()

	b.ReportAllocs()

	for b.Loop() {
		if why, _ := s.lost(ctx, "", "", &zeroSince); why != "" {
			b.Fatalf("an anchor that is running read as lost: %s", why)
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
		_ = json.NewEncoder(w).Encode(map[string]any{
			"chain":     chain,
			"notAfter":  time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
			"bootstrap": []string{"anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq@genesis.veilnet.com.au:4700", "api.veilnet.com.au:4700"},
		})
	}))
	b.Cleanup(api.Close)

	d := dirs(b)
	cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"bench"}, APIBaseURL: api.URL}

	if err := config.Save(d, cfg); err != nil {
		b.Fatal(err)
	}

	if err := config.SaveState(d, &config.State{AnchorID: "anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq"}); err != nil {
		b.Fatal(err)
	}

	doc, _ := json.Marshal(map[string]any{
		"formatVersion": 1, "kind": "anchor", "identity": "00", "genesis": "00", "chain": chain,
		"issuedAt": time.Now().UTC().Format(time.RFC3339), "notAfter": time.Now().UTC().Format(time.RFC3339),
		"taints": []string{"bench"}, "bootstrap": []string{"genesis.veilnet.com.au:4700"},
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
	anchortest.Require(b)

	b.Setenv("CONFLUX_DIR", b.TempDir())

	d := dirs(b)

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
		_, c, err := s.spawn(ctx)
		if err != nil {
			b.Fatal(err)
		}

		if err := s.waitReady(ctx, c); err != nil {
			b.Fatal(err)
		}

		s.shutdown(c)
	}

	reportGoroutines(b, before)
}

// benchSite is a machine with a configuration, a state that names its anchor and a
// credential nowhere near due: what a start with a credential in hand reads.
func benchSite(tb testing.TB) paths.Dirs {
	tb.Helper()

	d := dirs(tb)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"bench"}}); err != nil {
		tb.Fatal(err)
	}

	if err := config.SaveState(d, &config.State{AnchorID: fakeAnchorID}); err != nil {
		tb.Fatal(err)
	}

	now := time.Now().UTC()

	doc, _ := json.Marshal(map[string]any{
		"formatVersion": 1, "kind": "anchor", "identity": "00", "genesis": "00",
		"chain":    base64.StdEncoding.EncodeToString(make([]byte, 6<<10)),
		"issuedAt": now.Format(time.RFC3339), "notAfter": now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
		"taints": []string{"bench"}, "bootstrap": []string{"genesis.veilnet.com.au:4700"},
		"renewalUrl": "https://api.veilnet.com.au/ghosts/alpha/renew", "renewalAuth": "anchor-id",
	})

	if err := config.SaveManifest(d, config.Envelope(base64.StdEncoding.EncodeToString(doc))); err != nil {
		tb.Fatal(err)
	}

	return d
}
