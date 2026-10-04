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

// TestModeRules are anchor's, and only anchor's: a proxy needs userspace, a subnet, an
// exit and an IPv4 work in either mode -- in userspace the anchor forwards from its own
// process -- and the two exits are alternatives.
func TestModeRules(t *testing.T) {
	ip := "10.128.0.7/24"

	for name, tc := range map[string]struct {
		mode Mode
		set  func(*Config)
		ok   bool
		says string
	}{
		"a proxy with an interface":   {ModeTUN, func(c *Config) { c.Proxies = []string{"8080=127.0.0.1:1"} }, false, "userspace"},
		"a subnet in userspace":       {ModeProxy, func(c *Config) { c.Subnets = []string{"10.0.0.0/24"} }, true, ""},
		"a served exit in userspace":  {ModeProxy, func(c *Config) { c.ServeExit = true }, true, ""},
		"a served exit with one":      {ModeTUN, func(c *Config) { c.ServeExit = true }, true, ""},
		"UseExit with an interface":   {ModeTUN, func(c *Config) { c.UseExit = true }, true, ""},
		"UseExit in userspace":        {ModeProxy, func(c *Config) { c.UseExit = true }, true, ""},
		"both exits":                  {ModeTUN, func(c *Config) { c.ServeExit, c.UseExit = true, true }, false, "refuses the pair"},
		"an IPv4 with an interface":   {ModeTUN, func(c *Config) { c.IPv4 = &ip }, true, ""},
		"an IPv4 in userspace":        {ModeProxy, func(c *Config) { c.IPv4 = &ip }, true, ""},
		"a declined IPv4":             {ModeProxy, func(c *Config) { c.IPv4 = new(string) }, true, ""},
		"one overlay port twice":      {ModeProxy, func(c *Config) { c.Proxies = append(c.Proxies, "8080=127.0.0.1:9") }, false, "twice"},
		"one port, two networks":      {ModeProxy, func(c *Config) { c.Proxies = append(c.Proxies, "8080/udp=127.0.0.1:9") }, true, ""},
		"no taints":                   {ModeTUN, func(c *Config) { c.Taints = nil }, false, "no taints"},
		"a subnet with host bits set": {ModeTUN, func(c *Config) { c.Subnets = []string{"192.168.1.7/24"} }, false, "host bits"},
	} {
		t.Run(name, func(t *testing.T) {
			c := base(tc.mode)
			tc.set(c)

			err := c.Validate()

			switch {
			case tc.ok && err != nil:
				t.Errorf("refused: %v", err)
			case !tc.ok && err == nil:
				t.Error("accepted")
			case !tc.ok && !strings.Contains(err.Error(), tc.says):
				t.Errorf("the error should say %q; it said: %v", tc.says, err)
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
