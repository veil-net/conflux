package anchorctl

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestAnErrorSaysWhyNothingRan: an anchorctl that never started writes nothing to
// stderr, and an exit code of -1 is not a reason. The error has to carry the run's own
// -- a failed exec on Unix, a failed lookup on Windows -- and not read as an exit.
func TestAnErrorSaysWhyNothingRan(t *testing.T) {
	c := &Ctl{Bin: filepath.Join(t.TempDir(), "anchorctl")}

	_, err := c.Status(t.Context())
	if err == nil {
		t.Fatal("Status succeeded with no binary to run")
	}

	var e *Error
	if !errors.As(err, &e) || e.Err == nil {
		t.Fatalf("the error carries no reason: %v", err)
	}

	if exit := new(exec.ExitError); errors.As(err, &exit) || strings.Contains(err.Error(), "exit status") {
		t.Errorf("a binary that never started reads as an exit: %v", err)
	}
}

// TestConfluxsOwnCallsReachConfluxsDaemon: a shell that exports anchor's ANCHOR_SOCKET and
// ANCHORD_TOKEN, as anchor's operations guide says to, keeps them for what is typed through
// to anchorctl, and never for a call conflux makes for itself: a start that pipes an ephemeral
// run's credential to the daemon the shell names would leave it there when the run ends.
func TestConfluxsOwnCallsReachConfluxsDaemon(t *testing.T) {
	t.Setenv(SocketEnv, "/run/other/anchord.sock")
	t.Setenv(TokenEnv, "theirs")

	c := &Ctl{Socket: "/run/conflux/anchord.sock", Token: "ours"}

	values := func(env []string, name string) []string {
		var got []string

		for _, kv := range env {
			if k, v, _ := strings.Cut(kv, "="); k == name {
				got = append(got, v)
			}
		}

		return got
	}

	own := c.Env()
	if got := values(own, SocketEnv); !slices.Equal(got, []string{c.Socket}) {
		t.Errorf("conflux's own call: %s = %q, want only %q", SocketEnv, got, c.Socket)
	}

	if got := values(own, TokenEnv); !slices.Equal(got, []string{c.Token}) {
		t.Errorf("conflux's own call: %s = %q, want only %q", TokenEnv, got, c.Token)
	}

	typed := c.PassthroughEnv()
	if got := values(typed, SocketEnv); !slices.Equal(got, []string{"/run/other/anchord.sock"}) {
		t.Errorf("pass-through: %s = %q, want the caller's", SocketEnv, got)
	}

	if got := values(typed, TokenEnv); !slices.Equal(got, []string{"theirs"}) {
		t.Errorf("pass-through: %s = %q, want the caller's", TokenEnv, got)
	}

	t.Setenv(SocketEnv, "")
	os.Unsetenv(SocketEnv)

	if got := values(c.PassthroughEnv(), SocketEnv); !slices.Equal(got, []string{c.Socket}) {
		t.Errorf("pass-through with nothing set: %s = %q, want conflux's", SocketEnv, got)
	}
}
