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
	"up-exit": {
		TUN: true, TUNName: "anchor0", Taints: []string{"brhk-2mq9-tzva-6pjs"},
		ServeExit: true, UseExit: true, Dir: "/var/lib/conflux/anchor",
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

func TestValidateMirrorsAnchorsRule(t *testing.T) {
	bad := map[string]StartMode{
		"a proxy with a TUN":     {TUN: true, Proxies: []string{"8080=127.0.0.1:1"}, Taints: []string{"a"}},
		"a subnet without a TUN": {Subnets: []string{"10.0.0.0/24"}, Taints: []string{"a"}},
		"an IPv4 without a TUN":  {IPv4: "10.0.0.1/24", Taints: []string{"a"}},
		"no taints":              {TUN: true},
	}

	for why, m := range bad {
		if err := m.Validate(); err == nil {
			t.Errorf("Validate accepted %s", why)
		}
	}

	ok := map[string]StartMode{
		"a plain TUN":        {TUN: true, Taints: []string{"a"}},
		"a TUN with subnets": {TUN: true, Subnets: []string{"10.0.0.0/24"}, IPv4: "10.0.0.1/24", Taints: []string{"a"}},
		"a userspace proxy":  {Proxies: []string{"8080=127.0.0.1:1"}, Taints: []string{"a"}},
	}

	for why, m := range ok {
		if err := m.Validate(); err != nil {
			t.Errorf("Validate refused %s: %v", why, err)
		}
	}
}
