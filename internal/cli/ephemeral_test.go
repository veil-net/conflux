package cli

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/privcheck"
)

// handedRun is an ephemeral run prepared from doc, as `--ephemeral --manifest FILE` reads one.
func handedRun(t *testing.T, doc string) *ephemeralRun {
	t.Helper()

	path := filepath.Join(t.TempDir(), "manifest.b64")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString([]byte(doc))), 0o600); err != nil {
		t.Fatal(err)
	}

	on := true
	run, err := ephemeralFlags{on: &on, manifest: &path}.prepare()
	if err != nil {
		t.Fatal(err)
	}

	return run
}

// TestManifestIsForAnEphemeralRun: a credential named without --ephemeral is one to keep,
// which is conflux enrol's, and the refusal says so before anything of the machine's is read.
func TestManifestIsForAnEphemeralRun(t *testing.T) {
	t.Setenv("CONFLUX_DIR", t.TempDir())

	for _, verb := range [][]string{{"up"}, {"proxy", "8080=127.0.0.1:3000"}} {
		_, errOut, code := capture(t, append(verb, "--manifest", "-")...)
		if code == ExitOK || !strings.Contains(errOut, "conflux enrol --manifest") {
			t.Errorf("%s --manifest without --ephemeral: exit %d, %q; want a refusal naming conflux enrol", verb[0], code, errOut)
		}
	}

	if _, err := os.Stat(filepath.Join(os.Getenv("CONFLUX_DIR"), "conflux.json")); err == nil {
		t.Error("a refused run wrote a configuration")
	}
}

// TestAnEphemeralRunTakesTheHandedCredentialsAPIAndTaints: as enrol takes them, but into a
// configuration nothing saves -- the API the credential renews against, and the taints it
// grants -- and an --api naming another host is refused, as enrol refuses it.
func TestAnEphemeralRunTakesTheHandedCredentialsAPIAndTaints(t *testing.T) {
	run := handedRun(t, alphaDoc)

	cfg, err := run.fresh("")
	if err != nil {
		t.Fatal(err)
	}

	if cfg.APIBaseURL != "https://api.veilnet.com.au" {
		t.Errorf("APIBaseURL = %q, want the credential's own", cfg.APIBaseURL)
	}

	if want := []string{"brhk-2mq9-tzva-6pjs-k4xe-nw7d-qf"}; !slices.Equal(cfg.Taints, want) {
		t.Errorf("Taints = %v, want the credential's %v", cfg.Taints, want)
	}

	if _, err := run.fresh("https://elsewhere.example"); err == nil {
		t.Error("an --api naming another host than the credential renews against was taken")
	}
}

// TestAnEphemeralRunAsksNothing: the IPv4 is decided by the flags, then the credential, then
// nothing -- never by a question, since an ephemeral run is as often started by a script.
func TestAnEphemeralRunAsksNothing(t *testing.T) {
	alpha := handedRun(t, alphaDoc)
	enrolling := &ephemeralRun{}

	for _, c := range []struct {
		name  string
		run   *ephemeralRun
		flag  string
		none  bool
		want  string
		error bool
	}{
		{"the flag", enrolling, "10.128.0.9/24", false, "10.128.0.9/24", false},
		{"none", enrolling, "", true, "", false},
		{"nothing given", enrolling, "", false, "", false},
		{"a credential with none", alpha, "", false, "", false},
		{"both", enrolling, "10.128.0.9", true, "", true},
		{"a bad one", enrolling, "not an address", false, "", true},
	} {
		cfg := &config.Config{}

		err := c.run.ipv4(cfg, c.flag, c.none)
		if (err != nil) != c.error {
			t.Errorf("%s: err = %v, want error %v", c.name, err, c.error)

			continue
		}

		if c.error {
			continue
		}

		if cfg.IPv4 == nil || *cfg.IPv4 != c.want {
			t.Errorf("%s: IPv4 = %v, want %q, decided", c.name, cfg.IPv4, c.want)
		}
	}
}

// TestAnEphemeralProxyNeedsNoRoot: userspace needs no privilege, and an ephemeral run registers
// nothing that would, so proxy runs as anybody; a TUN, and observing, still need root, and on
// Windows every root conflux keeps is Administrators'.
func TestAnEphemeralProxyNeedsNoRoot(t *testing.T) {
	was := privcheck.Elevated
	privcheck.Elevated = func() bool { return false }

	t.Cleanup(func() { privcheck.Elevated = was })

	run := &ephemeralRun{}

	if err := run.root("proxy", &config.Config{}, nil); (err == nil) != (runtime.GOOS != "windows") {
		t.Errorf("an unprivileged ephemeral proxy on %s: %v", runtime.GOOS, err)
	}

	if err := run.root("proxy", &config.Config{Observer: &config.Observer{}}, nil); err == nil {
		t.Error("an unprivileged ephemeral proxy that observes was let through")
	}

	if err := run.root("up", &config.Config{}, nil); err == nil {
		t.Error("an unprivileged ephemeral up was let through")
	}
}
