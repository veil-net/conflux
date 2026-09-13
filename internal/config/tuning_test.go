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

func TestLANDiscoveryYesAndUplinkAreRefusedTogether(t *testing.T) {
	yes, no := true, false

	c := base(ModeTUN)
	c.Uplink = "/dev/ttyUSB0"
	c.LANDiscovery = &yes

	err := c.Validate()
	if err == nil {
		t.Fatal("--lan-discovery yes beside an uplink should be refused: there is no host network to probe")
	}

	if !strings.Contains(err.Error(), "no host network to probe") {
		t.Errorf("the error should say why; it said: %v", err)
	}

	// The two that are not an explicit ask are accepted, and this is the half worth
	// asserting: anchor turns the probe off beside an uplink regardless, so refusing
	// them would fail every machine that was configured once and later moved onto a
	// cable -- for a setting its operator never made.
	c.LANDiscovery = &no
	if err := c.Validate(); err != nil {
		t.Errorf("--lan-discovery no beside an uplink should validate: %v", err)
	}

	c.LANDiscovery = nil
	if err := c.Validate(); err != nil {
		t.Errorf("an unset lan-discovery beside an uplink should validate: %v", err)
	}

	// And yes is fine without the uplink.
	c.Uplink, c.LANDiscovery = "", &yes
	if err := c.Validate(); err != nil {
		t.Errorf("--lan-discovery yes alone should validate: %v", err)
	}
}

// TestLANDiscoveryRoundTripsAllThree: a *bool, so the document must tell "off" from
// "not set". omitempty drops a nil and keeps a pointer to false, which is the whole
// reason the field is a pointer -- a plain bool would read a persisted no back as an
// auto on the next start and hand the answer to the manifest.
func TestLANDiscoveryRoundTripsAllThree(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  *bool
	}{
		{"auto", nil},
		{"yes", func() *bool { v := true; return &v }()},
		{"no", func() *bool { v := false; return &v }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := dirsForTest(t)

			want := base(ModeTUN)
			want.LANDiscovery = tc.set

			if err := Save(d, want); err != nil {
				t.Fatalf("Save: %v", err)
			}

			got, err := Load(d)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}

			switch {
			case tc.set == nil && got.LANDiscovery != nil:
				t.Errorf("auto came back as %v; it must stay absent", *got.LANDiscovery)
			case tc.set != nil && got.LANDiscovery == nil:
				t.Errorf("%v came back as auto; the setting was dropped", *tc.set)
			case tc.set != nil && *got.LANDiscovery != *tc.set:
				t.Errorf("lanDiscovery is %v, want %v", *got.LANDiscovery, *tc.set)
			}
		})
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
