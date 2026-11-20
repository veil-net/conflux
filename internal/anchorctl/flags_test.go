package anchorctl_test

import (
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/pathstest"
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
//
// Every start and observe -start conflux can make is an argv golden of its own (args_test.go),
// so those are read from testdata/argv, all of them; what has no golden is listed here.
func TestEveryFlagWeUseExists(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)

	tools, err := libexec.Ensure(d)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	argvs := map[string][]string{
		"renew":         anchorctl.RenewArgs(),
		"stop":          anchorctl.StopArgs(),
		"status":        anchorctl.StatusArgs(),
		"metrics":       anchorctl.MetricsArgs(),
		"observe-renew": anchorctl.ObserveRenewArgs(),
		"observe-stop":  anchorctl.ObserveStopArgs(),
		"export":        anchorctl.ExportArgs("collector.example:4317", true, []string{"metrics", "flows"}),
	}

	goldens, err := filepath.Glob(filepath.Join("testdata", "argv", "*.golden"))
	if err != nil || len(goldens) == 0 {
		t.Fatalf("no argv goldens to read (%v)", err)
	}

	for _, path := range goldens {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		argvs[strings.TrimSuffix(filepath.Base(path), ".golden")] = strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	}

	// Each command's flags, scraped once.
	scraped := map[string]map[string]bool{}

	for name, argv := range argvs {
		t.Run(name, func(t *testing.T) {
			have, ok := scraped[argv[0]]
			if !ok {
				have = supportedFlags(t, tools.Anchorctl, argv[0])
				scraped[argv[0]] = have
			}

			for _, tok := range argv[1:] {
				// A bare "-" is the stdin marker that -manifest and -cred take as
				// their value, not a flag.
				if tok == "-" || !strings.HasPrefix(tok, "-") {
					continue
				}

				name := strings.TrimPrefix(tok, "-")
				if i := strings.IndexByte(name, '='); i >= 0 {
					name = name[:i]
				}

				if !have[name] {
					t.Errorf("anchorctl %s has no -%s flag; conflux's argv would be refused outright.\n"+
						"  it has: %s", argv[0], name, strings.Join(sorted(have), " "))
				}
			}
		})
	}
}

// supportedFlags scrapes `anchorctl <sub> -h`. The usage goes to stderr, and the exit
// status is not read: anchorctl answers -h with zero, and a stray failure shows up as
// a flag the scrape did not find.
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
	out := slices.Sorted(maps.Keys(m))
	for i := range out {
		out[i] = "-" + out[i]
	}

	return out
}
