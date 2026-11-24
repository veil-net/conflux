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
		r := ephemeralRoot(runtime.GOOS, euid, func(string) string { return "" })
		if rel, err := filepath.Rel(platformRoot(), r); err == nil && !strings.HasPrefix(rel, "..") {
			t.Errorf("the ephemeral root %s is inside the machine's %s", r, platformRoot())
		}
	}
}

// TestTheEphemeralRootIsWhatABootEmpties: root's run under the system's runtime directory, a
// user's in their own runtime directory, on every Unix that names one, or else their temporary
// one, and nothing anywhere a reboot keeps by design -- never a cache directory in a home.
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
	windows := filepath.Join(os.TempDir(), "conflux-ephemeral")

	for _, goos := range []string{"linux", "darwin", "freebsd", "openbsd", "windows"} {
		system := map[string]string{"linux": "/run/conflux-ephemeral", "windows": windows}[goos]
		if system == "" {
			system = "/var/run/conflux-ephemeral"
		}

		user := func(unix string) string {
			if goos == "windows" {
				return windows
			}

			return unix
		}

		for _, c := range []struct {
			name   string
			euid   int
			getenv func(string) string
			want   string
		}{
			{"root", 0, xdg(""), system},
			{"root with a runtime directory", 0, xdg("/run/user/0"), system},
			{"a user with a runtime directory", 1000, xdg("/run/user/1000"), user("/run/user/1000/conflux-ephemeral")},
			{"a user with none", 1000, xdg(""), user(tmp)},
			{"a relative runtime directory", 1000, xdg("run/user"), user(tmp)},
		} {
			if got := ephemeralRoot(goos, c.euid, c.getenv); got != c.want {
				t.Errorf("%s, %s: the ephemeral root is %s, want %s", goos, c.name, got, c.want)
			}
		}
	}
}
