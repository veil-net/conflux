package config

import "testing"

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
		"8080=127.0.0.1",   // backend without a port
		"8080=::1:5432",    // ambiguous v6, must be bracketed
		"8080=127.0.0.1:0", // backend port 0
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

func TestParseOverlayIPv4(t *testing.T) {
	for _, in := range []string{"10.128.0.7/24", "192.168.1.50/24", "10.0.0.1/8", "172.16.5.5/12", "10.1.2.3/32"} {
		if _, err := ParseOverlayIPv4(in); err != nil {
			t.Errorf("ParseOverlayIPv4(%q) = error %v", in, err)
		}
	}

	bad := []string{
		"",
		"10.128.0",       // three octets
		"10.128.0.7",     // no prefix length -- the commonest mistake
		"10.128.0/24",    // three octets with a length
		"fd00::1/64",     // v6
		"10.128.0.0/24",  // the network address, not a host
		"10.128.0.7/40",  // impossible length
		"10.128.0.7/4",   // below the floor
		"not an address", //
	}

	for _, in := range bad {
		if got, err := ParseOverlayIPv4(in); err == nil {
			t.Errorf("ParseOverlayIPv4(%q) = %v, want an error", in, got)
		}
	}
}

// TestParseOverlayIPv4NamesTheFix checks the two messages a user actually reads,
// because "invalid input" here costs a support round trip.
func TestParseOverlayIPv4NamesTheFix(t *testing.T) {
	_, err := ParseOverlayIPv4("10.128.0.7")
	if err == nil || !contains(err.Error(), "10.128.0.7/24") {
		t.Errorf("a bare address should suggest the /24 form, got %v", err)
	}

	_, err = ParseOverlayIPv4("10.128.0.0/24")
	if err == nil || !contains(err.Error(), "10.128.0.1/24") {
		t.Errorf("a network address should suggest a host address, got %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}

	return false
}

func TestValidateTaint(t *testing.T) {
	for _, in := range []string{"prod", "t-9f3a1c04be77d2e5", "brhk-2mq9-tzva-6pjs", "a", "eu-west-1"} {
		if err := ValidateTaint(in); err != nil {
			t.Errorf("ValidateTaint(%q) = %v", in, err)
		}
	}

	bad := map[string]string{
		"":                       "empty",
		"has space":              "space",
		"prod ":                  "trailing space, which would be a second compartment",
		"a,b":                    "a comma, which the -taints list would split",
		"tab\there":              "a tab",
		"nul\x00":                "a NUL",
		"del\x7f":                "a DEL",
		string(make([]byte, 65)): "too long",
	}

	for in, why := range bad {
		if err := ValidateTaint(in); err == nil {
			t.Errorf("ValidateTaint(%q) succeeded; it has %s", in, why)
		}
	}
}
