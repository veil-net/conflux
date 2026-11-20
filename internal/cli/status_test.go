package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
)

// runningStandIn makes d's daemon look running to status -- its socket and token there -- and
// puts a stand-in anchorctl where d's extracted pair is found whole: a script that writes each
// command it is run with to a line of log, says an anchor runs, and says the export was set by
// a call to anchorctl export. Its anchord never runs. Each is padded to its embedded binary's
// size, which is what finding a pair whole checks.
func runningStandIn(t *testing.T, d paths.Dirs, log string) {
	t.Helper()

	dir := filepath.Join(d.Libexec(), anchor.SetID())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	script := "#!/bin/sh\necho \"$1\" >>'" + log + "'\n" +
		"case $1 in\n" +
		"status) echo 'anchor running' ;;\n" +
		"export) echo '  set by anchorctl export' ;;\n" +
		"esac\nexit 0\n"

	for path, f := range map[string]struct {
		content string
		size    int
	}{
		filepath.Join(dir, "anchorctl"): {script, len(anchor.Anchorctl())},
		filepath.Join(dir, "anchord"):   {"", len(anchor.Anchord())},
	} {
		if err := os.WriteFile(path, []byte(f.content), 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.Truncate(path, int64(f.size)); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.MkdirAll(d.DaemonRun(), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.Socket(), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.TokenFile(), []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestStatusAsksWhatItReports: status asks the machine's daemon for its export, which it
// reports, and an ephemeral run's daemon only for its status, since nothing of that run's
// export is reported; and it reads the last anchord's privilege record for both things it
// says of it -- who anchord runs as, and the anchor directory a member's Subnets order is
// kept in.
func TestStatusAsksWhatItReports(t *testing.T) {
	anchortest.Require(t)

	if runtime.GOOS == "windows" {
		t.Skip("the stand-in anchorctl is a shell script")
	}

	logs := t.TempDir()
	machineLog, ephemeralLog := filepath.Join(logs, "machine"), filepath.Join(logs, "ephemeral")

	// A live ephemeral run beside the machine's own anchor: its lock held, and marked up by a
	// process that runs -- this one.
	e := startingEphemeral(t)
	if err := daemon.MarkReady(e, "anchorephemeral"); err != nil {
		t.Fatal(err)
	}

	runningStandIn(t, e, ephemeralLog)

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	runningStandIn(t, d, machineLog)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"}, Taints: []string{"t"},
		Export: &config.Export{Enabled: true, Endpoint: "collector.example:4317", Flows: true}}); err != nil {
		t.Fatal(err)
	}

	// anchord was last given root's anchor directory, though the account's is there too, and
	// the order is in root's.
	for _, dir := range []string{d.AnchorDir(), d.RootAnchorDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	order := `{"subnets": ["10.9.0.0/24"], "by": "anchormember", "at": "2026-11-20T00:00:00Z"}`
	if err := os.WriteFile(paths.SubnetsOrderFile(d.RootAnchorDir()), []byte(order), 0o600); err != nil {
		t.Fatal(err)
	}

	priv, err := json.Marshal(daemon.Privilege{As: "root", Why: "a firewall only root may change", Dir: d.RootAnchorDir()})
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.PrivilegeFile(), priv, 0o600); err != nil {
		t.Fatal(err)
	}

	out, errOut, code := capture(t, "status")
	if code != ExitOK {
		t.Fatalf("status exited %d:\n%s%s", code, out, errOut)
	}

	for log, want := range map[string][]string{machineLog: {"export", "status"}, ephemeralLog: {"status"}} {
		b, _ := os.ReadFile(log)

		// Asked side by side, so in either order.
		asked := strings.Fields(string(b))
		slices.Sort(asked)

		if !slices.Equal(asked, want) {
			t.Errorf("the %s daemon was asked %q, want %q", filepath.Base(log), asked, want)
		}
	}

	for _, want := range []string{
		"set by anchorctl export — an override",
		"10.9.0.0/24 — set by an order from anchormember",
		"root — a firewall only root may change",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status should say %q; it said:\n%s", want, out)
		}
	}
}
