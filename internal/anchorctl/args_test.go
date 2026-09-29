package anchorctl

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden argv files")

// scenarios are the argv shapes conflux can produce. Each is written to a golden
// file, one argument per line, because that turns "the flag is -taint, not -taints"
// from a runtime failure on somebody's laptop into a reviewable text diff.
var scenarios = map[string]StartMode{
	"up-minimal": {
		TUN: true, TUNName: "anchor0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		Dir: "/var/lib/conflux/anchor",
	},
	"up-ipv4": {
		TUN: true, TUNName: "anchor0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		IPv4: "10.128.0.7/24", Dir: "/var/lib/conflux/anchor",
	},
	"up-subnets": {
		TUN: true, TUNName: "anchor0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		IPv4: "10.128.0.7/24", Subnets: []string{"192.168.1.0/24", "eth1"},
		Dir: "/var/lib/conflux/anchor",
	},
	"up-many-taints": {
		TUN: true, TUNName: "anchor0", Taints: []string{"office", "laptop"},
		Dir: "/var/lib/conflux/anchor",
	},
	"up-custom-interface": {
		TUN: true, TUNName: "veil0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		Dir: "/var/lib/conflux/anchor",
	},
	"proxy-tcp": {
		Taints:  []string{"brhk-2mq9-tzva-6pjs"},
		Proxies: []string{"8080=127.0.0.1:3000"},
		Dir:     "/var/lib/conflux/anchor",
	},
	"proxy-multi": {
		Taints:  []string{"brhk-2mq9-tzva-6pjs"},
		Proxies: []string{"8080=127.0.0.1:3000", "53/udp=127.0.0.1:53", "5432=[::1]:5432"},
		Dir:     "/var/lib/conflux/anchor",
	},
	"up-peers": {
		TUN: true, TUNName: "anchor0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		Peers: []string{"genesis.veilnet.com.au:4700"},
		Dir:   "/var/lib/conflux/anchor",
	},
	"up-peers-many": {
		TUN: true, TUNName: "anchor0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		Peers: []string{"genesis.veilnet.com.au:4700", "anchorabc@203.0.113.9:4700"},
		Dir:   "/var/lib/conflux/anchor",
	},
	"proxy-peers": {
		Taints:  []string{"brhk-2mq9-tzva-6pjs"},
		Proxies: []string{"8080=127.0.0.1:3000"},
		Peers:   []string{"genesis.veilnet.com.au:4700"},
		Dir:     "/var/lib/conflux/anchor",
	},
	"up-uplink": {
		TUN: true, TUNName: "anchor0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		Uplink: "/dev/ttyUSB0:115200", Dir: "/var/lib/conflux/anchor",
	},
	"up-uplink-ipv4": {
		TUN: true, TUNName: "anchor0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		IPv4: "10.128.0.7/24", Uplink: "/dev/ttyUSB0", Dir: "/var/lib/conflux/anchor",
	},
	"proxy-uplink": {
		Taints:  []string{"brhk-2mq9-tzva-6pjs"},
		Proxies: []string{"8080=127.0.0.1:3000"},
		Uplink:  "/dev/ttyS1:57600",
		Dir:     "/var/lib/conflux/anchor",
	},
	"proxy-ipv4": {
		Taints:  []string{"brhk-2mq9-tzva-6pjs"},
		Proxies: []string{"8080=127.0.0.1:3000"},
		IPv4:    "10.128.0.7/24",
		Dir:     "/var/lib/conflux/anchor",
	},
	"proxy-windows": {
		Taints:  []string{"brhk-2mq9-tzva-6pjs"},
		Proxies: []string{"8080=127.0.0.1:3000"},
		Dir:     `C:\ProgramData\conflux\anchor`,
	},
	"up-port": {
		TUN: true, TUNName: "anchor0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		Port: 4711, Dir: "/var/lib/conflux/anchor",
	},
	"up-low-latency": {
		TUN: true, TUNName: "anchor0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		LowLatency: true, Dir: "/var/lib/conflux/anchor",
	},
	// The three lan-discovery answers. "auto" is the absence of a golden of its own:
	// up-minimal above is it, and the assertion that matters is that no
	// -lan-discovery appears there -- an auto that emitted a flag would override the
	// manifest with anchorctl's default on every machine that never asked.
	"up-lan-discovery-yes": {
		TUN: true, TUNName: "anchor0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		LANDiscovery: boolp(true), Dir: "/var/lib/conflux/anchor",
	},
	"up-lan-discovery-no": {
		TUN: true, TUNName: "anchor0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		LANDiscovery: boolp(false), Dir: "/var/lib/conflux/anchor",
	},
	"proxy-lan-discovery-no": {
		Taints:       []string{"brhk-2mq9-tzva-6pjs"},
		Proxies:      []string{"8080=127.0.0.1:3000"},
		LANDiscovery: boolp(false),
		Dir:          "/var/lib/conflux/anchor",
	},
	"up-serve-exit-only": {
		TUN: true, TUNName: "anchor0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		ServeExit: true, Dir: "/var/lib/conflux/anchor",
	},
	"up-use-exit-only": {
		TUN: true, TUNName: "anchor0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		UseExit: true, Dir: "/var/lib/conflux/anchor",
	},
	"proxy-low-latency": {
		Taints:     []string{"brhk-2mq9-tzva-6pjs"},
		Proxies:    []string{"8080=127.0.0.1:3000"},
		Port:       4711,
		LowLatency: true,
		Dir:        "/var/lib/conflux/anchor",
	},
}

func TestArgvGoldens(t *testing.T) {
	for name, mode := range scenarios {
		t.Run(name, func(t *testing.T) {
			got := strings.Join(mode.Args(), "\n") + "\n"
			path := filepath.Join("testdata", "argv", name+".golden")

			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}

				return
			}

			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run `go test ./internal/anchorctl -update` to create it): %v", err)
			}

			if got != string(want) {
				t.Errorf("argv changed.\n--- want ---\n%s\n--- got ---\n%s", want, got)
			}
		})
	}
}

// TestModeIsAlwaysExplicit is the property the goldens exist to protect, stated
// directly: anchorctl lets a manifest fill in any flag the caller did not type, so
// a mode flag conflux omits is a mode the issuer chooses.
func TestModeIsAlwaysExplicit(t *testing.T) {
	for name, mode := range scenarios {
		args := strings.Join(mode.Args(), " ")

		// The value is the operator's; being written at all is conflux's. An omitted
		// flag is a field anchorctl takes from the manifest, so each of these must
		// appear with an explicit =true or =false whichever way it was set.
		for _, must := range []string{"-tun=", "-serve-exit=", "-use-exit="} {
			if !strings.Contains(args, must) {
				t.Errorf("%s: argv omits %s, which lets the manifest decide it", name, must)
			}
		}
	}
}

func TestArgsUsesTaintsPlural(t *testing.T) {
	args := StartMode{TUN: true, Taints: []string{"a", "b"}}.Args()

	var found bool

	for i, a := range args {
		if a == "-taint" {
			t.Fatal("the flag is -taints, plural; -taint is silently ignored by anchorctl")
		}

		if a == "-taints" {
			found = true

			if i+1 >= len(args) || args[i+1] != "a,b" {
				t.Errorf("-taints value = %q, want a comma-joined list", args[i+1])
			}
		}
	}

	if !found {
		t.Error("argv has no -taints")
	}
}

func boolp(v bool) *bool { return &v }

// TestAutoEmitsNoLANDiscoveryFlag is the assertion the goldens cannot make.
//
// A golden says what an argv contains; this says what it must not. Nil means auto
// means "the manifest decides", and the only way that holds is if no flag is written
// at all -- anchorctl takes a manifest field only for a flag nobody typed. An auto
// that emitted -lan-discovery=yes would look identical in every test here and would
// quietly override the issuer on every machine that never asked.
//
// On the host's network, that is. Beside an uplink the manifest must not decide; see
// TestAnUplinkLeavesTheManifestNothingAnchorRefuses.
func TestAutoEmitsNoLANDiscoveryFlag(t *testing.T) {
	for name, mode := range scenarios {
		if mode.LANDiscovery != nil || mode.Uplink != "" {
			continue
		}

		for _, a := range mode.Args() {
			if strings.HasPrefix(a, "-lan-discovery") {
				t.Errorf("%s: LANDiscovery is nil but the argv carries %q", name, a)
			}
		}
	}
}

// TestAnUplinkLeavesTheManifestNothingAnchorRefuses: anchorctl fills every field no flag
// named from the manifest, and beside an uplink anchor refuses a port and a lan-discovery
// yes. A guardian may ship either, so on a link both are typed, whatever else is set.
func TestAnUplinkLeavesTheManifestNothingAnchorRefuses(t *testing.T) {
	for name, mode := range scenarios {
		if mode.Uplink == "" {
			continue
		}

		argv := strings.Join(mode.Args(), " ")

		if !strings.Contains(argv, "-port 0") {
			t.Errorf("%s: an uplink argv leaves the port to the manifest: %s", name, argv)
		}

		if mode.LANDiscovery == nil && !strings.Contains(argv, "-lan-discovery=no") {
			t.Errorf("%s: an uplink argv leaves lan-discovery to the manifest: %s", name, argv)
		}
	}
}
