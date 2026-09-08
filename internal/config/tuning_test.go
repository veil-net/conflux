package config

import (
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/paths"
)

// dirsForTest roots every conflux path in a temporary directory, the way CONFLUX_DIR
// does for a dev run.
func dirsForTest(t *testing.T) paths.Dirs {
	t.Helper()
	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	return d
}

// base is a configuration that validates, so each case below changes exactly one
// thing and the failure names that thing rather than a missing taint.
func base(mode Mode) *Config {
	c := &Config{Mode: mode, Taints: []string{"office"}}
	if mode == ModeProxy {
		c.Proxies = []string{"8080=127.0.0.1:3000"}
	}

	return c
}

func TestExitNeedsAHostInterface(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*Config)
	}{
		{"serve", func(c *Config) { c.ServeExit = true }},
		{"use", func(c *Config) { c.UseExit = true }},
		{"both", func(c *Config) { c.ServeExit, c.UseExit = true, true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// TUN is where an exit belongs, and it must keep working.
			tun := base(ModeTUN)
			tc.set(tun)

			if err := tun.Validate(); err != nil {
				t.Errorf("TUN mode should allow an exit: %v", err)
			}

			// Userspace has no interface to route out of, and anchor refuses it.
			proxy := base(ModeProxy)
			tc.set(proxy)

			err := proxy.Validate()
			if err == nil {
				t.Fatal("userspace mode should refuse an exit")
			}

			if !strings.Contains(err.Error(), "host interface") {
				t.Errorf("the error should say why; it said: %v", err)
			}
		})
	}
}

func TestPortAndUplinkAreRefusedTogether(t *testing.T) {
	c := base(ModeTUN)
	c.Uplink = "/dev/ttyUSB0"
	c.Port = 4711

	err := c.Validate()
	if err == nil {
		t.Fatal("a port beside an uplink should be refused: no socket is bound")
	}

	if !strings.Contains(err.Error(), "no port to choose") {
		t.Errorf("the error should say why; it said: %v", err)
	}

	// Either alone is fine.
	c.Port = 0
	if err := c.Validate(); err != nil {
		t.Errorf("an uplink alone should validate: %v", err)
	}

	c.Uplink, c.Port = "", 4711
	if err := c.Validate(); err != nil {
		t.Errorf("a port alone should validate: %v", err)
	}
}

// TestTuningSurvivesTheRoundTrip: the four new fields are omitempty, so a zero value
// is absent from the document. What must not happen is a set one being dropped.
func TestTuningSurvivesTheRoundTrip(t *testing.T) {
	d := dirsForTest(t)

	want := base(ModeTUN)
	want.Port = 4711
	want.LowLatency = true
	want.ServeExit = true
	want.UseExit = true

	if err := Save(d, want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(d)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got.Port != want.Port || got.LowLatency != want.LowLatency ||
		got.ServeExit != want.ServeExit || got.UseExit != want.UseExit {
		t.Errorf("tuning did not survive: port=%d lowLatency=%v serveExit=%v useExit=%v",
			got.Port, got.LowLatency, got.ServeExit, got.UseExit)
	}
}
