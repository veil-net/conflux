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
	script, err := freebsdScript("conflux", "/var/db/.conflux/conflux", []string{"serve"}, "/var/db/.conflux/rc.pid")
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"# PROVIDE: conflux",
		// daemon(8) -S hands conflux's output to syslogd, which is started first so none of
		// it is lost.
		"# REQUIRE: NETWORKING syslogd\n",
		"# KEYWORD: shutdown",
		"rcvar=conflux_enable",
		"pidfile=/var/db/.conflux/rc.pid\n",
		"procname=/var/db/.conflux/conflux\n",
		`command_args="-f -S -T conflux -p ${pidfile} /var/db/.conflux/conflux serve"`,
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
	script, err := openbsdScript("/var/db/.conflux/conflux", []string{"serve"})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"daemon=/var/db/.conflux/conflux\n",
		`daemon_flags="serve"`,
		"daemon_logger=daemon.info",
		". /etc/rc.d/rc.subr",
		"rc_bg=YES",
		"rc_cmd $1",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the script has no %q:\n%s", want, script)
		}
	}

	// rc.subr sets daemon_class itself, read-only, to the login class named after the script
	// where there is one: conflux's own (openbsdClass), never one the script names.
	if strings.Contains(script, "daemon_class") {
		t.Errorf("the script sets daemon_class, which rc.subr holds read-only:\n%s", script)
	}

	shParses(t, script)
}

// TestOpenBSDClass: the login class rc.subr runs conflux under, found by the script's name,
// raises the open-file limit the daemon class holds to 1024 -- both halves, since the daemon
// class's own -cur and -max, reached through tc, would otherwise decide them -- and is the
// daemon class in everything else.
func TestOpenBSDClass(t *testing.T) {
	class := openbsdClass()

	if !strings.Contains(class, "\n"+rcName+":\\\n") {
		t.Errorf("the class is not named %s, the script's name, which rc.subr looks for:\n%s", rcName, class)
	}

	for _, want := range []string{
		"\t:openfiles-cur=1048576:\\\n",
		"\t:openfiles-max=1048576:\\\n",
		"\t:tc=daemon:\n",
	} {
		if !strings.Contains(class, want) {
			t.Errorf("the class has no %q:\n%s", strings.TrimSpace(want), class)
		}
	}

	if !strings.HasSuffix(class, ":tc=daemon:\n") {
		t.Errorf("the record does not end at tc=daemon:\n%s", class)
	}
}

// TestAnRCScriptRefusesWhatItCannotMatch: both rc.subr implementations find the running
// service by matching its command line unquoted, and OpenBSD's runs it through a shell,
// so a word either would read differently is refused rather than written into a service
// that starts and can then be neither stopped nor asked about.
func TestAnRCScriptRefusesWhatItCannotMatch(t *testing.T) {
	for _, root := range []string{"/srv/my dir", "/srv/$HOME", "/srv/a;b", "/srv/it's", "/srv/[x]", "/srv/a*"} {
		args := []string{"serve"}

		if _, err := openbsdScript(root+"/conflux", args); err == nil {
			t.Errorf("an OpenBSD script was written for the executable %q", root+"/conflux")
		}

		if _, err := freebsdScript(rcName, root+"/conflux", args, root+"/rc.pid"); err == nil {
			t.Errorf("a FreeBSD script was written for the executable %q", root+"/conflux")
		}
	}
}
