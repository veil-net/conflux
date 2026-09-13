package cli

import (
	"bytes"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
)

func capture(t *testing.T, argv ...string) (stdout, stderr string, code int) {
	t.Helper()

	var out, errBuf bytes.Buffer

	oldOut, oldErr := ui.Out, ui.Errw
	ui.Out, ui.Errw = &out, &errBuf

	t.Cleanup(func() { ui.Out, ui.Errw = oldOut, oldErr })

	code = Main(append([]string{"conflux"}, argv...))

	return out.String(), errBuf.String(), code
}

// TestNoUnintendedShadowing is the guard on the whole two-surface design.
//
// conflux keeps a closed set of names and passes everything else through. If a
// future anchor adds a command called "up", it would silently become unreachable --
// conflux would answer it and the user would never learn that anchorctl had one.
// This fails CI on that day instead.
func TestNoUnintendedShadowing(t *testing.T) {
	if !anchor.Supported {
		t.Skip("no anchor pair for this platform")
	}

	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	tools, err := libexec.Ensure(d)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	theirs := anchorctlCommands(t, tools.Anchorctl)

	// The names conflux is knowingly taking. Every one is documented in help, and
	// every one that shadows an anchorctl command explains the collision in its own
	// error text.
	known := map[string]bool{
		"proxy": true, "status": true, "help": true, "renew": true,
		"start": true, "stop": true, "restart": true,
	}

	for name := range verbs() {
		if theirs[name] && !known[name] {
			t.Errorf("conflux's %q now shadows an anchorctl command that this build did not know about.\n"+
				"  Either rename conflux's, or add it to the known set and resolve the collision\n"+
				"  the way proxy and status do.", name)
		}
	}

	for name := range anchorLifecycleVerbs {
		if !theirs[name] {
			t.Errorf("conflux refuses to pass %q through, but anchorctl has no such command any more", name)
		}
	}

	// The two conflux resolves by shape and arity really are anchorctl's, or the
	// elaborate handling in runProxy and runStatus is dead code.
	for _, name := range []string{"proxy", "status"} {
		if !theirs[name] {
			t.Errorf("conflux resolves a collision on %q that no longer exists", name)
		}
	}
}

var usageCommand = regexp.MustCompile(`(?m)^\s{4}([a-z][a-z-]+)\s`)

func anchorctlCommands(t *testing.T, bin string) map[string]bool {
	t.Helper()

	out, _ := exec.Command(bin, "help").CombinedOutput()

	found := map[string]bool{}
	for _, m := range usageCommand.FindAllStringSubmatch(string(out), -1) {
		found[m[1]] = true
	}

	if len(found) < 10 {
		t.Fatalf("scraped only %d commands from anchorctl help; the format changed:\n%s", len(found), out)
	}

	return found
}

func TestLifecycleVerbsAreRefusedWithTheAlternative(t *testing.T) {
	// start is absent: conflux has its own now. restart names it rather than "up",
	// which was wrong on a userspace machine -- up changes the mode and drops the
	// proxies, so it is not the way back to what was running.
	for name, want := range map[string]string{
		"stop": "conflux down", "restart": "conflux start",
	} {
		_, errOut, code := capture(t, name)

		if code != ExitUsage {
			t.Errorf("conflux %s exited %d, want %d", name, code, ExitUsage)
		}

		if !strings.Contains(errOut, want) {
			t.Errorf("conflux %s should name %q; it said:\n%s", name, want, errOut)
		}

		if !strings.Contains(errOut, "conflux anchorctl "+name) {
			t.Errorf("conflux %s should name the escape hatch; it said:\n%s", name, errOut)
		}
	}
}

// TestStartRefusesAnchorctlFlags: conflux's start takes no arguments, so a flag names
// anchorctl's and is answered with both meanings rather than guessed at.
func TestStartRefusesAnchorctlFlags(t *testing.T) {
	for _, args := range [][]string{
		{"start", "-cred", "x.cred"},
		{"start", "-identity=k.key"},
		{"start", "--root", "genesis.pub"},
	} {
		_, errOut, code := capture(t, args...)

		if code != ExitUsage {
			t.Errorf("conflux %v exited %d, want %d", args, code, ExitUsage)
		}

		if !strings.Contains(errOut, "conflux anchorctl start") {
			t.Errorf("conflux %v should name the escape hatch; it said:\n%s", args, errOut)
		}
	}
}

// TestStartRefusesArguments: a positional is not conflux's start either.
func TestStartRefusesArguments(t *testing.T) {
	_, errOut, code := capture(t, "start", "somewhere")

	if code != ExitUsage {
		t.Errorf("conflux start somewhere exited %d, want %d", code, ExitUsage)
	}

	if !strings.Contains(errOut, "takes no arguments") {
		t.Errorf("should say it takes no arguments; it said:\n%s", errOut)
	}
}

// TestProxyRefusesAnchorctlFlags: the ambiguous case is explained, never guessed.
func TestProxyRefusesAnchorctlFlags(t *testing.T) {
	for _, args := range [][]string{
		{"proxy", "-add", "8080=127.0.0.1:3000"},
		{"proxy", "-rm", "8080"},
		{"proxy", "-add=8080=127.0.0.1:3000"},
	} {
		_, errOut, code := capture(t, args...)

		if code != ExitUsage {
			t.Errorf("%v exited %d, want %d", args, code, ExitUsage)
		}

		if !strings.Contains(errOut, "conflux anchorctl proxy") {
			t.Errorf("%v should point at the escape hatch; it said:\n%s", args, errOut)
		}
	}
}

func TestBareProxyExplainsBothMeanings(t *testing.T) {
	_, errOut, code := capture(t, "proxy")

	if code != ExitUsage {
		t.Errorf("bare proxy exited %d, want %d", code, ExitUsage)
	}

	for _, want := range []string{"8080=127.0.0.1:3000", "conflux anchorctl proxy"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("bare proxy should mention %q; it said:\n%s", want, errOut)
		}
	}
}

// TestTopLevelFlagIsNotForwarded: "conflux -socket X status" would be ambiguous
// with conflux's own status, so nothing is forwarded from the first position.
func TestTopLevelFlagIsNotForwarded(t *testing.T) {
	_, errOut, code := capture(t, "-socket", "/tmp/x", "status")

	if code != ExitUsage {
		t.Errorf("exited %d, want %d", code, ExitUsage)
	}

	if !strings.Contains(errOut, "conflux anchorctl") {
		t.Errorf("should point at the escape hatch; it said:\n%s", errOut)
	}
}

func TestHelpListsEveryVisibleVerb(t *testing.T) {
	t.Setenv("CONFLUX_DIR", t.TempDir())

	out, _, code := capture(t, "help")
	if code != ExitOK {
		t.Fatalf("help exited %d", code)
	}

	for name, v := range verbs() {
		if v.hidden {
			if strings.Contains(out, "  "+name+" ") {
				t.Errorf("help lists the hidden verb %q", name)
			}

			continue
		}

		if !strings.Contains(out, name) {
			t.Errorf("help does not mention %q", name)
		}
	}
}

func TestVersionNamesTheAnchorBuild(t *testing.T) {
	out, _, code := capture(t, "version")
	if code != ExitOK {
		t.Fatalf("version exited %d", code)
	}

	if !strings.Contains(out, "conflux") {
		t.Errorf("version does not name conflux:\n%s", out)
	}

	if anchor.Supported && !strings.Contains(out, anchor.SetID()) {
		t.Errorf("version does not name the anchor set, which a bug report needs:\n%s", out)
	}
}

// TestStatusWithNoConfigExits78: the code the systemd unit keys
// RestartPreventExitStatus on, so a registered service with no configuration stops
// rather than restarting forever.
func TestStatusWithNoConfigExits78(t *testing.T) {
	t.Setenv("CONFLUX_DIR", t.TempDir())

	_, _, code := capture(t, "status")
	if code != ExitNoConfig {
		t.Errorf("status with no configuration exited %d, want %d", code, ExitNoConfig)
	}
}

// TestProxyKeepsItsOwnUplinkFlag: --uplink is conflux proxy's, so the gate that
// hands anchorctl's flags back must not catch it, and the splitter has to know it
// takes a value -- otherwise the device path lands in the positional list and is
// read as a port spec.
func TestProxyKeepsItsOwnUplinkFlag(t *testing.T) {
	for _, args := range [][]string{
		{"--uplink", "/dev/ttyUSB0", "8080=127.0.0.1:3000"},
		{"8080=127.0.0.1:3000", "--uplink=/dev/ttyUSB0:115200"},
		{"--no-uplink", "8080=127.0.0.1:3000"},
	} {
		if hint := unknownProxyFlag(args); hint != "" {
			t.Errorf("%v: unknownProxyFlag said %q", args, hint)
		}

		specs, _ := splitPositional(args)

		if len(specs) != 1 || specs[0] != "8080=127.0.0.1:3000" {
			t.Errorf("%v: positional args are %v, want just the port spec", args, specs)
		}
	}
}

// TestUplinkFDIsExplainedRatherThanPassed: a descriptor is adopted from whatever
// started the daemon, and conflux's supervisor starts anchord with none, so the
// form has to be refused here rather than fail as "bad file descriptor" from a
// child process.
func TestUplinkFDIsExplainedRatherThanPassed(t *testing.T) {
	var cfg config.Config

	err := chooseUplink(&cfg, "fd:3", false)
	if err == nil {
		t.Fatal("chooseUplink accepted fd:3")
	}

	for _, want := range []string{"/dev/ttyUSB0", "conflux anchorctl start -uplink fd:3"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should mention %q; it said:\n%s", want, err)
		}
	}

	if cfg.Uplink != "" {
		t.Errorf("a refused uplink was still stored: %q", cfg.Uplink)
	}
}

// TestUplinkFlagsContradict, and TestNoUplinkClears: a machine on a cable has to be
// able to go back to the host's network, and the two flags cannot both be meant.
func TestUplinkFlagsContradict(t *testing.T) {
	var cfg config.Config

	if err := chooseUplink(&cfg, "/dev/ttyUSB0", true); err == nil {
		t.Error("--uplink and --no-uplink were both accepted")
	}
}

func TestNoUplinkClears(t *testing.T) {
	cfg := config.Config{Uplink: "/dev/ttyUSB0:115200"}

	if err := chooseUplink(&cfg, "", true); err != nil {
		t.Fatalf("--no-uplink: %v", err)
	}

	if cfg.Uplink != "" {
		t.Errorf("uplink is still %q", cfg.Uplink)
	}

	// And no flag at all keeps what is configured, the same rule the overlay
	// address follows.
	cfg.Uplink = "/dev/ttyUSB0:115200"

	if err := chooseUplink(&cfg, "", false); err != nil || cfg.Uplink != "/dev/ttyUSB0:115200" {
		t.Errorf("a second up without --uplink changed it to %q (%v)", cfg.Uplink, err)
	}
}

// TestRenewRefusesAnchorctlFlags: conflux renew takes no arguments, and anchorctl's
// takes -cred. The overlap is resolved by shape, like proxy's, rather than by
// shadowing anchorctl's renew out of reach.
func TestRenewRefusesAnchorctlFlags(t *testing.T) {
	for _, args := range [][]string{
		{"renew", "-cred", "/tmp/c"},
		{"renew", "-cred=/tmp/c"},
		{"renew", "-inline"},
	} {
		_, errOut, code := capture(t, args...)

		if code != ExitUsage {
			t.Errorf("%v exited %d, want %d", args, code, ExitUsage)
		}

		if !strings.Contains(errOut, "conflux anchorctl renew") {
			t.Errorf("%v should point at the escape hatch; it said:\n%s", args, errOut)
		}
	}
}

// TestRenewTakesNoPositional keeps the no-argument contract honest: a stray word is
// a typo, and guessing what it meant is how a credential gets installed from a file
// nobody named.
func TestRenewTakesNoPositional(t *testing.T) {
	_, errOut, code := capture(t, "renew", "somefile")

	if code != ExitUsage {
		t.Errorf("renew with a positional exited %d, want %d", code, ExitUsage)
	}

	if !strings.Contains(errOut, "takes no arguments") {
		t.Errorf("renew should say it takes none; it said:\n%s", errOut)
	}
}

func TestPeersFlagsContradict(t *testing.T) {
	var cfg config.Config

	if err := choosePeers(&cfg, []string{"genesis.veilnet.com.au:4700"}, true); err == nil {
		t.Error("--peers and --no-peers were both accepted")
	}
}

// TestNoPeersClears and, more importantly, that no flag at all leaves the list
// empty: empty is what makes anchorctl take bootstrap from the manifest, so an
// invented default here would quietly override the issuer's own nodes.
func TestNoPeersClears(t *testing.T) {
	cfg := config.Config{Peers: []string{"genesis.veilnet.com.au:4700"}}

	if err := choosePeers(&cfg, nil, true); err != nil {
		t.Fatalf("--no-peers: %v", err)
	}

	if len(cfg.Peers) != 0 {
		t.Errorf("peers are still %v", cfg.Peers)
	}

	var fresh config.Config

	if err := choosePeers(&fresh, nil, false); err != nil || len(fresh.Peers) != 0 {
		t.Errorf("up with no --peers invented %v (%v)", fresh.Peers, err)
	}
}

func TestPeersAreValidatedBeforeTheyReachAnchor(t *testing.T) {
	var cfg config.Config

	for _, bad := range []string{"genesis.veilnet.com.au", "a,b:4700", ":4700", "host:0", "host:notaport"} {
		if err := choosePeers(&cfg, []string{bad}, false); err == nil {
			t.Errorf("peer %q was accepted", bad)
		}
	}

	good := []string{"genesis.veilnet.com.au:4700", "anchorabc@203.0.113.9:4700", "[::1]:4700"}
	if err := choosePeers(&cfg, good, false); err != nil {
		t.Errorf("peers %v were refused: %v", good, err)
	}
}

// TestProxyKeepsItsOwnLANDiscoveryFlag: the tristate is a value flag, and proxy's
// positional parser is the one place that has to be told so. `--lan-discovery no
// 8080=...` reads as two positionals to a parser that thinks the flag is a boolean,
// and the second of them is a proxy spec called "no".
func TestProxyKeepsItsOwnLANDiscoveryFlag(t *testing.T) {
	for _, args := range [][]string{
		{"--lan-discovery", "no", "8080=127.0.0.1:3000"},
		{"8080=127.0.0.1:3000", "--lan-discovery=yes"},
		{"--lan-discovery", "auto", "8080=127.0.0.1:3000"},
	} {
		if hint := unknownProxyFlag(args); hint != "" {
			t.Errorf("%v: unknownProxyFlag said %q", args, hint)
		}

		specs, _ := splitPositional(args)

		if len(specs) != 1 || specs[0] != "8080=127.0.0.1:3000" {
			t.Errorf("%v: positional args are %v, want just the port spec", args, specs)
		}
	}
}

// TestLANDiscoveryTristate covers the three answers and the two rules that are not
// obvious from them: an absent flag keeps what is configured, because that is how
// every other re-run of up keeps its settings, and typing auto is the way back from
// a persisted yes or no -- the job the --no-x negations do for the toggles.
func TestLANDiscoveryTristate(t *testing.T) {
	yes, no := true, false

	for _, tc := range []struct {
		name    string
		typed   bool
		value   string
		current *bool
		want    *bool
	}{
		{"absent keeps a persisted yes", false, "auto", &yes, &yes},
		{"absent keeps a persisted no", false, "auto", &no, &no},
		{"absent keeps auto", false, "auto", nil, nil},
		{"yes sets yes", true, "yes", nil, &yes},
		{"no sets no", true, "no", &yes, &no},
		{"auto is the way back", true, "auto", &yes, nil},
		{"case and space are forgiven", true, " YES ", nil, &yes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			typed := map[string]bool{}
			if tc.typed {
				typed["lan-discovery"] = true
			}

			got, err := chooseTristate("lan-discovery", typed, tc.value, tc.current)
			if err != nil {
				t.Fatalf("chooseTristate: %v", err)
			}

			switch {
			case tc.want == nil && got != nil:
				t.Errorf("got %v, want auto", *got)
			case tc.want != nil && got == nil:
				t.Errorf("got auto, want %v", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Errorf("got %v, want %v", *got, *tc.want)
			}
		})
	}

	if _, err := chooseTristate("lan-discovery",
		map[string]bool{"lan-discovery": true}, "maybe", nil); err == nil {
		t.Error("a value that is not yes, no or auto should be refused")
	}
}
