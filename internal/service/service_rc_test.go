package service

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// shParses checks a rendered script is valid shell, which is as far as a machine that
// is not a BSD can take it.
func shParses(t *testing.T, script string) {
	t.Helper()

	if runtime.GOOS == "windows" {
		return
	}

	path := filepath.Join(t.TempDir(), "rc")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
		t.Errorf("the script does not parse: %v\n%s\n%s", err, out, script)
	}
}

func TestFreeBSDScript(t *testing.T) {
	script, err := freebsdScript("conflux", "/var/db/conflux/conflux", []string{"serve"}, "/var/log/conflux.log")
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"# PROVIDE: conflux",
		"# KEYWORD: shutdown",
		"rcvar=conflux_enable",
		"procname=/var/db/conflux/conflux\n",
		`command_args="-f -o /var/log/conflux.log -p ${pidfile} /var/db/conflux/conflux serve"`,
		`: "${conflux_enable:=NO}"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the script has no %q:\n%s", want, script)
		}
	}

	// No restart from daemon(8): a supervisor that exits 78 or 70 would only repeat it.
	if strings.Contains(script, " -r") {
		t.Errorf("daemon(8) is told to restart conflux:\n%s", script)
	}

	shParses(t, script)
}

func TestOpenBSDScript(t *testing.T) {
	script, err := openbsdScript("/var/db/conflux/conflux", []string{"serve", "--dir", "/srv/conflux-dev"})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"daemon=/var/db/conflux/conflux\n",
		`daemon_flags="serve --dir /srv/conflux-dev"`,
		"daemon_logger=daemon.info",
		". /etc/rc.d/rc.subr",
		"rc_bg=YES",
		"rc_cmd $1",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the script has no %q:\n%s", want, script)
		}
	}

	shParses(t, script)
}

// TestAnRCScriptRefusesWhatItCannotMatch: both rc.subr implementations find the running
// service by matching its command line unquoted, and OpenBSD's runs it through a shell,
// so a word either would read differently is refused rather than written into a service
// that starts and can then be neither stopped nor asked about.
func TestAnRCScriptRefusesWhatItCannotMatch(t *testing.T) {
	for _, root := range []string{"/srv/my dir", "/srv/$HOME", "/srv/a;b", "/srv/it's", "/srv/[x]", "/srv/a*"} {
		args := []string{"serve", "--dir", root}

		if _, err := openbsdScript(root+"/conflux", args); err == nil {
			t.Errorf("an OpenBSD script was written for the root %q", root)
		}

		if _, err := freebsdScript("conflux_1a2b3c4d", root+"/conflux", args, root+"/logs/conflux.log"); err == nil {
			t.Errorf("a FreeBSD script was written for the root %q", root)
		}
	}
}

func TestRCNameIsAShellWord(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "/tmp/somewhere")

	if name := rcName(); strings.ContainsAny(name, "-/ .") || !strings.HasPrefix(name, "conflux_") {
		t.Errorf("rcName() = %q, which rc.subr cannot build %s_enable from", name, name)
	}
}
