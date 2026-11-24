package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestTheEphemeralRootIsNotTheMachines: an ephemeral run is kept apart from the
// installation, never in or under the machine's .conflux, so it touches nothing of it.
func TestTheEphemeralRootIsNotTheMachines(t *testing.T) {
	for _, euid := range []int{0, 1000} {
		r := ephemeralRoot(euid, func(string) string { return "" })
		if rel, err := filepath.Rel(platformRoot(), r); err == nil && !strings.HasPrefix(rel, "..") {
			t.Errorf("the ephemeral root %s is inside the machine's %s", r, platformRoot())
		}
	}
}

// TestTheEphemeralRootIsWhatABootEmpties: root's run under the system's runtime directory,
// a user's in their own runtime directory or temporary one, and nothing anywhere a reboot
// keeps -- never a cache directory in a home.
func TestTheEphemeralRootIsWhatABootEmpties(t *testing.T) {
	xdg := func(v string) func(string) string {
		return func(k string) string {
			if k == "XDG_RUNTIME_DIR" {
				return v
			}

			return ""
		}
	}

	tmp := filepath.Join(os.TempDir(), "conflux-ephemeral-1000")

	cases := []struct {
		name   string
		euid   int
		getenv func(string) string
		want   string
	}{
		{"root", 0, xdg(""), map[string]string{
			"linux": "/run/conflux-ephemeral", "windows": filepath.Join(os.TempDir(), "conflux-ephemeral"),
		}[runtime.GOOS]},
		{"a user with a runtime directory", 1000, xdg("/run/user/1000"), map[string]string{
			"linux": "/run/user/1000/conflux-ephemeral", "windows": filepath.Join(os.TempDir(), "conflux-ephemeral"),
		}[runtime.GOOS]},
		{"a user with none", 1000, xdg(""), map[string]string{
			"linux": tmp, "windows": filepath.Join(os.TempDir(), "conflux-ephemeral"),
		}[runtime.GOOS]},
		{"a relative runtime directory", 1000, xdg("run/user"), map[string]string{
			"linux": tmp, "windows": filepath.Join(os.TempDir(), "conflux-ephemeral"),
		}[runtime.GOOS]},
	}

	for _, c := range cases {
		want := c.want
		if want == "" { // macOS and the BSDs
			want = tmp
			if c.euid == 0 {
				want = "/var/run/conflux-ephemeral"
			}
		}

		if got := ephemeralRoot(c.euid, c.getenv); got != want {
			t.Errorf("%s: the ephemeral root is %s, want %s", c.name, got, want)
		}
	}
}
