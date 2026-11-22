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
	script := freebsdScript("/var/db/.conflux/conflux", []string{"serve"}, "/var/db/.conflux/logs/conflux.log")

	for _, want := range []string{
		"# PROVIDE: conflux",
		"# KEYWORD: shutdown",
		"rcvar=conflux_enable",
		"procname=/var/db/.conflux/conflux\n",
		`command_args="-f -o /var/db/.conflux/logs/conflux.log -p ${pidfile} /var/db/.conflux/conflux serve"`,
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
	script := openbsdScript("/var/db/.conflux/conflux", []string{"serve"})

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

	shParses(t, script)
}
