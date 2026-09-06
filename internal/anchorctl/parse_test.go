package anchorctl

import (
	"testing"
	"time"
)

// The fixtures below are the exact shapes anchorctl emits, reproduced from
// printStarted and the status printer in anchor's cmd/anchorctl/lifecycle.go --
// including the tabwriter's two-space padding and the extra space Println leaves
// after "overlay ". If an anchor upgrade changes either, these fail, which is the
// entire point of pinning them.

const startedOutput = `anchor anchor1qxy8f2kz3mn4p5q6r7s8t9u0v1w2x3y4z5a6b7c8d9e0f
  underlay 203.0.113.9:41641
  overlay  fdfa:c051:57ff:28aa:33a1:2a10:f63c:42b
  overlay  10.128.0.7
  hardware 9a:1c:44:0e:22:b1
`

const statusOutput = `04:31:02  reachability=nat-cone  mtu=1280  peers=3  up=2h14m0s
  anchor       anchor1qxy8f2kz3mn4p5q6r7s8t9u0v1w2x3y4z5a6b7c8d9e0f
  underlay     203.0.113.9:41641
  overlay      fdfa:c051:57ff:28aa:33a1:2a10:f63c:42b
  overlay      10.128.0.7
  hardware     9a:1c:44:0e:22:b1
  realm        realmtglw/realmpxap
  cut depth 0  joined to the whole tree
  renew by     2026-09-20T04:12:00Z
  works until  2026-09-13T04:12:00Z
  proxy 8080/tcp  127.0.0.1:3000
  proxy 53/udp    127.0.0.1:53
`

const notRunningOutput = "no anchor is running\n"

const wantID = "anchor1qxy8f2kz3mn4p5q6r7s8t9u0v1w2x3y4z5a6b7c8d9e0f"

func TestParseStarted(t *testing.T) {
	s := ParseStarted(startedOutput)

	if s.ID != wantID {
		t.Errorf("ID = %q, want %q", s.ID, wantID)
	}

	if len(s.Underlay) != 1 || s.Underlay[0] != "203.0.113.9:41641" {
		t.Errorf("Underlay = %v", s.Underlay)
	}

	if len(s.Overlay) != 2 {
		t.Fatalf("Overlay = %v, want two addresses", s.Overlay)
	}

	if s.Overlay[1] != "10.128.0.7" {
		t.Errorf("Overlay[1] = %q, want the v4 address", s.Overlay[1])
	}

	if s.Hardware != "9a:1c:44:0e:22:b1" {
		t.Errorf("Hardware = %q", s.Hardware)
	}
}

func TestParseStatus(t *testing.T) {
	st := ParseStatus(statusOutput)

	if !st.Running {
		t.Fatal("Running = false")
	}

	if st.ID != wantID {
		t.Errorf("ID = %q, want %q", st.ID, wantID)
	}

	if st.Reachability != "nat-cone" {
		t.Errorf("Reachability = %q", st.Reachability)
	}

	if st.MTU != 1280 {
		t.Errorf("MTU = %d", st.MTU)
	}

	if st.Peers != 3 {
		t.Errorf("Peers = %d", st.Peers)
	}

	if st.Up != 2*time.Hour+14*time.Minute {
		t.Errorf("Up = %v", st.Up)
	}

	if len(st.Overlay) != 2 {
		t.Errorf("Overlay = %v, want two", st.Overlay)
	}

	if st.Realm != "realmtglw/realmpxap" {
		t.Errorf("Realm = %q", st.Realm)
	}

	if st.Cut() {
		t.Error("Cut() = true at cut depth 0")
	}

	want := time.Date(2026, 9, 13, 4, 12, 0, 0, time.UTC)
	if !st.WorksUntil.Equal(want) {
		t.Errorf("WorksUntil = %v, want %v", st.WorksUntil, want)
	}

	if len(st.Proxies) != 2 {
		t.Errorf("Proxies = %v, want two", st.Proxies)
	}
}

func TestParseStatusNotRunning(t *testing.T) {
	st := ParseStatus(notRunningOutput)

	if st.Running {
		t.Error("Running = true for `no anchor is running`")
	}

	if st.ID != "" {
		t.Errorf("ID = %q, want empty", st.ID)
	}
}

// TestParseStatusCut: a severed realm is the state an operator most needs status to
// name, and it is reported as a depth rather than a flag.
func TestParseStatusCut(t *testing.T) {
	out := `04:31:02  reachability=direct  mtu=1280  peers=1  up=5m0s
  anchor       ` + wantID + `
  realm        realmtglw/realmpxap
  cut depth 1  deals with realmpxap and below; renew the delegation above it
`

	st := ParseStatus(out)

	if !st.Cut() {
		t.Error("Cut() = false at cut depth 1")
	}

	if st.CutDepth != 1 {
		t.Errorf("CutDepth = %d, want 1", st.CutDepth)
	}
}

// TestParseStartedIsResilient: garbage must not panic, and must not invent an ID.
func TestParseStartedIsResilient(t *testing.T) {
	for _, in := range []string{"", "\n", "anchor", "some unrelated error text", "anchor \n"} {
		if got := ParseStarted(in).ID; got != "" {
			t.Errorf("ParseStarted(%q).ID = %q, want empty", in, got)
		}

		if got := ParseStatus(in); got.Running {
			t.Errorf("ParseStatus(%q).Running = true", in)
		}
	}
}
