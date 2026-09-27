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
	script := freebsdScript("conflux", "/usr/local/bin/conflux", []string{"serve"}, "/var/log/conflux.log")

	for _, want := range []string{
		"# PROVIDE: conflux",
		"# KEYWORD: shutdown",
		"rcvar=conflux_enable",
		"procname='/usr/local/bin/conflux'",
		`command_args="-f -o '/var/log/conflux.log' -p ${pidfile} '/usr/local/bin/conflux' 'serve'"`,
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

// TestFreeBSDScriptQuotesAnything: a CONFLUX_DIR run registers its root, and a path is
// allowed any character.
func TestFreeBSDScriptQuotesAnything(t *testing.T) {
	root := `/srv/it's "odd" $HOME`
	script := freebsdScript("conflux_1a2b3c4d", "/usr/local/bin/conflux", []string{"serve", "--dir", root}, root+"/logs/conflux.log")

	shParses(t, script)

	// What rc.subr eval's must come back as the three words it was given.
	line := script[strings.Index(script, "command_args="):]
	line = line[:strings.IndexByte(line, '\n')]

	out, err := exec.Command("sh", "-c", `pidfile=/p; `+line+`; eval "set -- $command_args"; shift 5; printf '%s\n' "$@"`).Output()
	if err != nil {
		t.Fatalf("evaluating command_args: %v", err)
	}

	if got := strings.Split(strings.TrimSpace(string(out)), "\n"); len(got) != 4 || got[3] != root {
		t.Errorf("command_args evaluates to %q, want conflux serve --dir %q", got, root)
	}
}

func TestOpenBSDScript(t *testing.T) {
	script := openbsdScript("/usr/local/bin/conflux", []string{"serve"})

	for _, want := range []string{
		"daemon='/usr/local/bin/conflux'",
		"daemon_flags='serve'",
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

func TestRCNameIsAShellWord(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "/tmp/somewhere")

	if name := rcName(); strings.ContainsAny(name, "-/ .") || !strings.HasPrefix(name, "conflux_") {
		t.Errorf("rcName() = %q, which rc.subr cannot build %s_enable from", name, name)
	}
}
