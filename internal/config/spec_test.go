package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseProxySpec(t *testing.T) {
	ok := []struct {
		in   string
		want ProxySpec
	}{
		{"8080=127.0.0.1:3000", ProxySpec{8080, "tcp", "127.0.0.1:3000"}},
		{"53/udp=127.0.0.1:53", ProxySpec{53, "udp", "127.0.0.1:53"}},
		{"53/UDP=127.0.0.1:53", ProxySpec{53, "udp", "127.0.0.1:53"}},
		{"5432=[::1]:5432", ProxySpec{5432, "tcp", "[::1]:5432"}},
		{"443=backend.internal:8443", ProxySpec{443, "tcp", "backend.internal:8443"}},
		{" 80 / tcp = 127.0.0.1:80 ", ProxySpec{80, "tcp", "127.0.0.1:80"}},
		{"1=127.0.0.1:1", ProxySpec{1, "tcp", "127.0.0.1:1"}},
		{"65535=127.0.0.1:1", ProxySpec{65535, "tcp", "127.0.0.1:1"}},
		// The backend is dialled per connection and only split here, as anchor does:
		// a named port resolves when it is dialled.
		{"8080=localhost:http", ProxySpec{8080, "tcp", "localhost:http"}},
	}

	for _, tc := range ok {
		got, err := ParseProxySpec(tc.in)
		if err != nil {
			t.Errorf("ParseProxySpec(%q) = error %v", tc.in, err)

			continue
		}

		if got != tc.want {
			t.Errorf("ParseProxySpec(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}

	bad := []string{
		"8080",                  // no backend at all
		"8080=",                 // the "=" but nothing after it
		"=127.0.0.1:3000",       // no port
		"0=127.0.0.1:3000",      // port 0
		"65536=127.0.0.1:3000",  // past the top
		"-1=127.0.0.1:3000",     // negative
		"8080/tpc=127.0.0.1:80", // the typo anchor's own comment calls out
		"8080/sctp=127.0.0.1:80",
		"8080=127.0.0.1", // backend without a port
		"8080=::1:5432",  // ambiguous v6, must be bracketed
		"abc=127.0.0.1:80",
	}

	for _, in := range bad {
		if got, err := ParseProxySpec(in); err == nil {
			t.Errorf("ParseProxySpec(%q) = %+v, want an error", in, got)
		}
	}
}

// TestProxySpecRoundTrip matters because String() is what reaches the anchorctl
// argv: a spec that parses but renders differently would publish the wrong port.
func TestProxySpecRoundTrip(t *testing.T) {
	for _, in := range []string{"8080=127.0.0.1:3000", "53/udp=127.0.0.1:53", "5432=[::1]:5432"} {
		s, err := ParseProxySpec(in)
		if err != nil {
			t.Fatalf("ParseProxySpec(%q): %v", in, err)
		}

		again, err := ParseProxySpec(s.String())
		if err != nil {
			t.Fatalf("ParseProxySpec(%q): %v", s.String(), err)
		}

		if again != s {
			t.Errorf("round trip of %q gave %+v then %+v", in, s, again)
		}
	}
}

// TestParseOverlayIPv4 is anchord's rule (control/config.go and Config.validate): an
// address or a prefix, IPv4, unicast, and not a /0.
func TestParseOverlayIPv4(t *testing.T) {
	for in, bits := range map[string]int{
		"10.128.0.7/24":   24,
		"10.128.0.7":      32, // an address is a /32
		"10.128.0.0/24":   24, // anybody's address, the network's included
		"192.168.1.50/16": 16,
		"198.51.100.7/1":  1, // public, and sent from rather than advertised
	} {
		p, err := ParseOverlayIPv4(in)
		if err != nil {
			t.Errorf("ParseOverlayIPv4(%q) = error %v", in, err)

			continue
		}

		if p.Bits() != bits {
			t.Errorf("ParseOverlayIPv4(%q) = %s, want a /%d", in, p, bits)
		}
	}

	for in, why := range map[string]string{
		"":                   "empty",
		"10.128.0":           "three octets",
		"10.128.0/24":        "three octets with a length",
		"fd00::1/64":         "IPv6",
		"fd00::1":            "IPv6, bare",
		"10.128.0.7/40":      "an impossible length",
		"10.128.0.7/0":       "a /0",
		"127.0.0.7/8":        "loopback",
		"169.254.1.1/16":     "link-local",
		"224.0.0.1":          "multicast",
		"255.255.255.255/32": "broadcast",
		"0.0.0.0/8":          "unspecified",
		" 10.128.0.7/24":     "surrounding space, which anchord does not trim",
		"not an address":     "not an address",
		"198.18.0.7/24":      "inside the translation pool, which anchor will not send from",
		"198.19.255.1":       "inside the translation pool, bare",
	} {
		if got, err := ParseOverlayIPv4(in); err == nil {
			t.Errorf("ParseOverlayIPv4(%q) = %v, want an error: %s", in, got, why)
		}
	}
}

func TestValidateTaint(t *testing.T) {
	for _, in := range []string{
		"prod", "t-9f3a1c04be77d2e5", "brhk-2mq9-tzva-6pjs-k4xe-nw7d-qf", "a", "eu-west-1", "zürich", "東京",
	} {
		if err := ValidateTaint(in); err != nil {
			t.Errorf("ValidateTaint(%q) = %v", in, err)
		}
	}

	bad := map[string]string{
		"":                       "empty",
		"has space":              "space",
		"prod ":                  "trailing space, which would be a second compartment",
		"a,b":                    "a comma, which reads as two compartments",
		"a@b":                    "an '@', which binds a served network",
		"a+b":                    "a '+', which joins a binding's compartments",
		"@":                      "only an '@'",
		"tab\there":              "a tab",
		"nul\x00":                "a NUL",
		"del\x7f":                "a DEL",
		string(make([]byte, 65)): "too long",
		"prod\u00a0":             "a no-break space, which anchorctl would trim off",
		"zero\u200bwidth":        "a zero-width space",
		"c1\u0085":               "a C1 control character",
		"bad\xff":                "a byte that is not UTF-8",
	}

	for in, why := range bad {
		if err := ValidateTaint(in); err == nil {
			t.Errorf("ValidateTaint(%q) succeeded; it has %s", in, why)
		}
	}
}

func TestValidateTaints(t *testing.T) {
	// A repeat names one compartment, as it does to anchor.
	if err := ValidateTaints([]string{"prod", "prod"}); err != nil {
		t.Errorf("ValidateTaints refused a repeat: %v", err)
	}

	for name, in := range map[string][]string{
		"invalid":  {"has space"},
		"comma":    {"a,b"},
		"too many": make([]string, MaxTaints+1),
	} {
		if err := ValidateTaints(in); err == nil {
			t.Errorf("ValidateTaints accepted the %s case", name)
		}
	}
}

// TestValidateSubnet is what anchor refuses without looking at the host
// (internal/hostnet.Select and IsPrivateNetwork).
func TestValidateSubnet(t *testing.T) {
	for _, in := range []string{
		"eth1", "192.168.1.0/24", "10.0.0.0/8", "172.20.0.0/16", "100.64.0.0/10", "fd12:3456::/64",
		"*", "eth1@office", "192.168.1.0/24@office+lab", "*@office", "eth@1@office", "eth1@team/a",
	} {
		if err := ValidateSubnet(in); err != nil {
			t.Errorf("ValidateSubnet(%q) = %v", in, err)
		}
	}

	for in, why := range map[string]string{
		"192.168.1.7/24":                      "host bits set",
		"10.0.0.0/7":                          "a private first address and public space after it",
		"203.0.113.0/24":                      "public",
		"169.254.0.0/16":                      "link-local, which nobody routes to",
		"fe80::/64":                           "link-local IPv6",
		"::ffff:0.0.0.0/8":                    "an IPv4-mapped prefix wider than the mapped space",
		"::ffff:10.0.0.0/104":                 "an IPv4 network written as IPv6, which anchor never finds attached",
		"10.0.0.0/8,eth1":                     "a comma, which -serve-subnets would split into two entries",
		"10.0.0.0/33":                         "a slash outside a prefix, which no interface name holds",
		"eth1@":                               "a binding to an empty compartment",
		"@office":                             "a binding of nothing",
		"eth1@a b":                            "a bound compartment with a space",
		"eth1@a++b":                           "an empty compartment between two '+'",
		"192.168.1.7/24@x":                    "host bits set, bound or not",
		"*@":                                  "a binding to an empty compartment",
		strings.Repeat("e", MaxSubnetEntry+1): "longer than anchor's entry",
	} {
		if err := ValidateSubnet(in); err == nil {
			t.Errorf("ValidateSubnet(%q) succeeded; it is %s", in, why)
		}
	}

	if err := ValidateSubnet("192.168.1.7/24"); err == nil || !strings.Contains(err.Error(), "192.168.1.0/24") {
		t.Errorf("a prefix with host bits should name the network it meant, got %v", err)
	}

	if err := ValidateSubnet("::ffff:10.0.0.0/104"); err == nil || !strings.Contains(err.Error(), "10.0.0.0/8") {
		t.Errorf("a mapped IPv4 network should name how to write it, got %v", err)
	}
}

// TestValidateSubnets is what anchor refuses of a whole list (served.go checkSubnetList
// and checkBindings): its bounds, and a binding to a compartment the machine is not in.
func TestValidateSubnets(t *testing.T) {
	own := []string{"office", "lab"}

	if err := ValidateSubnets([]string{"eth1@office", "*@office+lab", "10.0.0.0/8", "eth1@office"}, own); err != nil {
		t.Errorf("a list bound to its own compartments was refused: %v", err)
	}

	many := make([]string, MaxSubnetEntries+1)
	for i := range many {
		many[i] = "eth1"
	}

	wide := make([]string, MaxBoundTaints+1)
	for i := range wide {
		wide[i] = fmt.Sprintf("t%d", i)
	}

	for name, tc := range map[string]struct {
		entries, taints []string
		says            string
	}{
		"too many entries":    {many, own, "at most"},
		"bound elsewhere":     {[]string{"eth1@prod"}, own, "not in"},
		"one of two missing":  {[]string{"eth1@office+prod"}, own, "not in"},
		"bound with no taint": {[]string{"eth1@office"}, nil, "default compartment"},
		"bound too widely":    {[]string{"*@" + strings.Join(wide, "+")}, wide, "compartments"},
		"a bad entry":         {[]string{"eth1", "203.0.113.0/24"}, own, "private"},
	} {
		err := ValidateSubnets(tc.entries, tc.taints)
		if err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: got %v, want it to say %q", name, err, tc.says)
		}
	}
}

func TestValidateAnchorID(t *testing.T) {
	for _, in := range []string{
		"anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq",
		"ANCHORAAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ",
	} {
		if err := ValidateAnchorID(in); err != nil {
			t.Errorf("ValidateAnchorID(%q) = %v", in, err)
		}
	}

	for _, in := range []string{
		"",
		"anchor",
		"anchorabc",
		"realmaaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq",
		"anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dyp1",  // 1 is not base32
		"anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypqa", // one too long
		"anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypr",  // q's bytes, with a padding bit set
	} {
		if err := ValidateAnchorID(in); err == nil {
			t.Errorf("ValidateAnchorID(%q) succeeded", in)
		}
	}
}

func TestParseUplinkSpec(t *testing.T) {
	ok := []struct {
		in   string
		want UplinkSpec
	}{
		{"fd:3", UplinkSpec{FD: 3}},
		{"fd:0", UplinkSpec{FD: 0}},
		{"/dev/ttyUSB0", UplinkSpec{FD: -1, Path: "/dev/ttyUSB0"}},
		{"/dev/ttyUSB0:115200", UplinkSpec{FD: -1, Path: "/dev/ttyUSB0", Baud: 115200}},
		{" /dev/ttyS1:9600 ", UplinkSpec{FD: -1, Path: "/dev/ttyS1", Baud: 9600}},
		// A path holding a colon is a path: only the last one can be a speed, and
		// only when what follows it is a number.
		{"/dev/serial/by-id/usb-FTDI:x", UplinkSpec{FD: -1, Path: "/dev/serial/by-id/usb-FTDI:x"}},
	}

	for _, tc := range ok {
		got, err := ParseUplinkSpec(tc.in)
		if err != nil {
			t.Errorf("ParseUplinkSpec(%q) = error %v", tc.in, err)

			continue
		}

		if got != tc.want {
			t.Errorf("ParseUplinkSpec(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}

	bad := []string{
		"",
		"   ",
		"fd:",
		"fd:-1",
		"fd:abc",
		"/dev/ttyUSB0:0",  // a speed of zero is not a speed
		"/dev/ttyUSB0:-1", // nor a negative one
		":115200",         // a speed and no device
	}

	for _, in := range bad {
		if got, err := ParseUplinkSpec(in); err == nil {
			t.Errorf("ParseUplinkSpec(%q) = %+v, want an error", in, got)
		}
	}
}

// TestUplinkSpecRoundTrip is what keeps conflux.json and the -uplink flag the same
// language: the config file stores what ParseUplinkSpec normalised, and it has to
// parse back to the same link.
func TestUplinkSpecRoundTrip(t *testing.T) {
	for _, in := range []string{"fd:3", "/dev/ttyUSB0", "/dev/ttyUSB0:115200"} {
		spec, err := ParseUplinkSpec(in)
		if err != nil {
			t.Fatalf("ParseUplinkSpec(%q) = error %v", in, err)
		}

		if spec.String() != in {
			t.Errorf("ParseUplinkSpec(%q).String() = %q", in, spec.String())
		}

		again, err := ParseUplinkSpec(spec.String())
		if err != nil || again != spec {
			t.Errorf("round trip of %q gave %+v, %v", in, again, err)
		}
	}
}

// TestUplinkIsOrthogonalToMode pins the one thing about an uplink that is easy to
// get wrong by analogy with the subnets and the proxies: it is the medium, not the
// mode, so neither mode refuses it.
func TestUplinkIsOrthogonalToMode(t *testing.T) {
	ip := "10.128.0.7/24"
	tun := &Config{
		Mode: ModeTUN, Taints: []string{"office"},
		IPv4: &ip, Uplink: "/dev/ttyUSB0:115200",
	}
	if err := tun.Validate(); err != nil {
		t.Errorf("tun mode with an uplink: %v", err)
	}

	proxy := &Config{
		Mode: ModeProxy, Taints: []string{"office"},
		Proxies: []string{"8080=127.0.0.1:3000"}, Uplink: "/dev/ttyACM0",
	}
	if err := proxy.Validate(); err != nil {
		t.Errorf("proxy mode with an uplink: %v", err)
	}

	// A descriptor is adopted from whatever starts anchord, and conflux's supervisor
	// hands it none: refused before a daemon fails on it.
	fd := &Config{Mode: ModeProxy, Taints: []string{"office"}, Proxies: proxy.Proxies, Uplink: "fd:3"}
	if err := fd.Validate(); err == nil || !strings.Contains(err.Error(), "descriptor") {
		t.Errorf("an uplink naming a descriptor: %v, want a refusal", err)
	}

	bad := &Config{Mode: ModeTUN, Taints: []string{"office"}, Uplink: ":115200"}
	if err := bad.Validate(); err == nil {
		t.Error("a malformed uplink spec passed Validate")
	}
}
