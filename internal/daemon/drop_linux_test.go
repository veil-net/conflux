package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestDropReachesTheProcess: the stand-in anchord, started through the drop as root, runs
// as the account with exactly the capabilities it was given -- none for userspace, with
// no_new_privs, and CAP_NET_ADMIN alone for a TUN. Run as root, and only then.
func TestDropReachesTheProcess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("dropping to another uid needs root")
	}

	nobody := lookupNobody(t)

	// A copy of this binary the account can reach: the build cache is root's alone.
	dir := t.TempDir()
	for d := dir; d != os.TempDir() && d != "/"; d = filepath.Dir(d) {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	stand := filepath.Join(dir, "anchord")

	b, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(stand, b, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		p    Privilege
		eff  string
		nnp  string
	}{
		{"userspace", Privilege{Account: true, NoNewPrivs: true}, "0000000000000000", "1"},
		{"tun", Privilege{Account: true, Caps: []string{capNetAdmin}}, "0000000000001000", "0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := c.p
			p.As, p.UID, p.GID = nobody.As, nobody.UID, nobody.GID

			s := &Supervisor{}
			cmd := exec.Command(stand, "-socket", "unused")
			cmd.SysProcAttr = s.procAttrFor(p)
			cmd.Env = append(anchordEnv(p, "token"), fakeAnchordEnv+"=serve")
			cmd.Dir = workDir

			if err := startProcess(cmd, p); err != nil {
				t.Fatal(err)
			}

			defer func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}()

			status := procStatus(t, cmd.Process.Pid)

			for key, want := range map[string]string{
				"Uid":        itoa4(p.UID),
				"CapEff":     c.eff,
				"CapPrm":     c.eff,
				"CapAmb":     c.eff,
				"NoNewPrivs": c.nnp,
			} {
				if got := status[key]; got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
		})
	}
}

// procStatus is /proc/<pid>/status, once the child has exec'd: its Uid line names the
// account by then, where the forked supervisor's would still be root's.
func procStatus(t *testing.T, pid int) map[string]string {
	t.Helper()

	path := "/proc/" + strconv.Itoa(pid) + "/status"

	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		fields := map[string]string{}

		for line := range strings.Lines(string(b)) {
			k, v, ok := strings.Cut(line, ":")
			if ok {
				fields[k] = strings.Join(strings.Fields(v), "\t")
			}
		}

		if !strings.HasPrefix(fields["Uid"], "0\t") || time.Now().After(deadline) {
			return fields
		}
	}
}

// itoa4 is a uid as the Uid line gives it: real, effective, saved and filesystem.
func itoa4(uid int) string {
	u := strconv.Itoa(uid)

	return u + "\t" + u + "\t" + u + "\t" + u
}
