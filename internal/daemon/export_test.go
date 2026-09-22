package daemon

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
)

func dirs(t *testing.T) paths.Dirs {
	t.Helper()
	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	return d
}

// TestAnchordIsStartedWithAConfig is the one-line regression this whole file is
// about. Without -config an export configured anywhere but over the live socket is
// never applied, and one configured over the socket dies with the daemon.
func TestAnchordIsStartedWithAConfig(t *testing.T) {
	d := dirs(t)

	args := anchordArgs(d)

	i := slices.Index(args, "-config")
	if i < 0 {
		t.Fatalf("anchord is started with %v and no -config", args)
	}

	if got := args[i+1]; got != d.DaemonConfigFile() {
		t.Errorf("-config %s, want %s", got, d.DaemonConfigFile())
	}
}

// TestTheConfigIsWrittenEvenWithNothingToExport pins the precedence decision.
//
// An absent export block is written as an explicit `enabled: false` rather than
// left out, so that a restart lands on what conflux.json says in both directions.
// Leaving it out would let a daemon restarting after an `anchorctl export` keep
// exporting to an endpoint no file on this machine records.
func TestTheConfigIsWrittenEvenWithNothingToExport(t *testing.T) {
	d := dirs(t)

	if err := writeDaemonConfig(d, &config.Config{}); err != nil {
		t.Fatalf("writeDaemonConfig: %v", err)
	}

	var got daemonConfig
	if err := json.Unmarshal(read(t, d), &got); err != nil {
		t.Fatalf("the rendered config is not JSON: %v", err)
	}

	if got.Export == nil {
		t.Fatal("the export block was left out; anchord would then apply nothing")
	}

	if got.Export.Enabled {
		t.Error("enabled is true for a machine configured to export nothing")
	}
}

// TestTheConfigCarriesWhatWasConfigured, including the headers, which are the
// credentials the collector authenticates on.
func TestTheConfigCarriesWhatWasConfigured(t *testing.T) {
	d := dirs(t)

	cfg := &config.Config{Export: &config.Export{
		Enabled:  true,
		Endpoint: "otlp.example.gov:4317",
		Metrics:  true,
		Headers:  map[string]string{"authorization": "Basic bm9kZTpzZWNyZXQ="},
		CACert:   &config.Secret{Path: "/etc/ssl/certs/site.pem"},
	}}

	if err := writeDaemonConfig(d, cfg); err != nil {
		t.Fatalf("writeDaemonConfig: %v", err)
	}

	var got daemonConfig
	if err := json.Unmarshal(read(t, d), &got); err != nil {
		t.Fatalf("the rendered config is not JSON: %v", err)
	}

	if got.Export.Endpoint != cfg.Export.Endpoint {
		t.Errorf("endpoint = %q", got.Export.Endpoint)
	}

	if got.Export.Headers["authorization"] != cfg.Export.Headers["authorization"] {
		t.Error("the headers did not survive the render, so the collector would refuse this node")
	}

	if got.Export.CACert == nil || got.Export.CACert.Path != "/etc/ssl/certs/site.pem" {
		t.Error("the CA path did not survive the render")
	}
}

// TestTheConfigSurvivesARestart. A restart is another spawn, which is another
// render from the same file, so the second daemon comes back exporting exactly
// what the first one was.
func TestTheConfigSurvivesARestart(t *testing.T) {
	d := dirs(t)

	cfg := &config.Config{Export: &config.Export{
		Enabled: true, Endpoint: "otlp.example.gov:4317", Metrics: true, Logs: true,
	}}

	if err := writeDaemonConfig(d, cfg); err != nil {
		t.Fatalf("first spawn: %v", err)
	}

	first := string(read(t, d))

	if err := writeDaemonConfig(d, cfg); err != nil {
		t.Fatalf("second spawn: %v", err)
	}

	if second := string(read(t, d)); second != first {
		t.Errorf("a restart rendered a different config:\n%s\nwant\n%s", second, first)
	}
}

// TestTheConfigIsNotReadableByAnyoneElse. It carries the export headers, which
// authenticate this machine to a collector. anchord warns about exactly this.
func TestTheConfigIsNotReadableByAnyoneElse(t *testing.T) {
	d := dirs(t)

	if err := writeDaemonConfig(d, &config.Config{}); err != nil {
		t.Fatalf("writeDaemonConfig: %v", err)
	}

	info, err := os.Stat(d.DaemonConfigFile())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("mode is %04o; the export headers are credentials", perm)
	}
}

func read(t *testing.T, d paths.Dirs) []byte {
	t.Helper()

	b, err := os.ReadFile(d.DaemonConfigFile())
	if err != nil {
		t.Fatalf("read the rendered config: %v", err)
	}

	return b
}
