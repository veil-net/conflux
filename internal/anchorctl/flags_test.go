package anchorctl_test

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
)

// flagLine matches the way Go's flag package prints a flag in a usage block:
// a tab, a dash, the name, then either a type or end of line.
var flagLine = regexp.MustCompile(`(?m)^\s+-([a-z0-9-]+)`)

// TestEveryFlagWeUseExists runs the embedded anchorctl and checks that every flag
// conflux's argv names is one it actually has.
//
// This is the test that catches an anchor upgrade renaming or dropping a flag. Go's
// flag package refuses an unknown flag rather than ignoring it, so the failure would
// otherwise be a daemon that will not start -- discovered after the binaries were
// dropped into anchor/bin and shipped, not before.
func TestEveryFlagWeUseExists(t *testing.T) {
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

	for _, sub := range []struct {
		name string
		argv []string
	}{
		{"start", anchorctl.StartMode{
			TUN: true, TUNName: "anchor0", IPv4: "10.0.0.1/24",
			Subnets: []string{"10.0.0.0/24"}, Proxies: nil,
			Taints: []string{"t"}, Dir: "/tmp/x",
		}.Args()},
		{"start-proxy", anchorctl.StartMode{
			Proxies: []string{"8080=127.0.0.1:1"}, Taints: []string{"t"}, Dir: "/tmp/x",
		}.Args()},
		{"renew", anchorctl.RenewArgs("/tmp/c")},
		{"stop", anchorctl.StopArgs()},
		{"status", anchorctl.StatusArgs()},
	} {
		t.Run(sub.name, func(t *testing.T) {
			have := supportedFlags(t, tools.Anchorctl, sub.argv[0])

			for _, tok := range sub.argv[1:] {
				// A bare "-" is the stdin marker that -manifest takes as its
				// value, not a flag.
				if tok == "-" || !strings.HasPrefix(tok, "-") {
					continue
				}

				name := strings.TrimPrefix(tok, "-")
				if i := strings.IndexByte(name, '='); i >= 0 {
					name = name[:i]
				}

				if !have[name] {
					t.Errorf("anchorctl %s has no -%s flag; conflux's argv would be refused outright.\n"+
						"  it has: %s", sub.argv[0], name, strings.Join(sorted(have), " "))
				}
			}
		})
	}
}

// supportedFlags scrapes `anchorctl <sub> -h`. The usage goes to stderr and the
// call exits non-zero, both of which are normal for -h with Go's flag package.
func supportedFlags(t *testing.T, bin, sub string) map[string]bool {
	t.Helper()

	out, _ := exec.Command(bin, sub, "-h").CombinedOutput()

	found := map[string]bool{}
	for _, m := range flagLine.FindAllStringSubmatch(string(out), -1) {
		found[m[1]] = true
	}

	if len(found) == 0 {
		t.Fatalf("scraped no flags from `anchorctl %s -h`; the output format changed:\n%s", sub, out)
	}

	return found
}

func sorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, "-"+k)
	}

	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}

	return out
}
