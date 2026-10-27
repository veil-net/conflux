package account

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// TestNameFollowsThePlatformAndTheScope: the platform's own convention for a daemon's
// account, and a CONFLUX_DIR installation's never the machine's.
func TestNameFollowsThePlatformAndTheScope(t *testing.T) {
	for _, c := range []struct{ goos, scope, want string }{
		{"linux", "", "conflux"},
		{"freebsd", "", "conflux"},
		{"darwin", "", "_conflux"},
		{"openbsd", "-44a6e4f4", "_conflux-44a6e4f4"},
		{"linux", "-44a6e4f4", "conflux-44a6e4f4"},
	} {
		if got := nameFor(c.goos, c.scope); got != c.want {
			t.Errorf("nameFor(%q, %q) = %q, want %q", c.goos, c.scope, got, c.want)
		}
	}
}

// TestCreateCommands: a system account with no home and no shell on every platform, its
// own group made first only when there is none, and the comment that marks it conflux's.
func TestCreateCommands(t *testing.T) {
	for _, c := range []struct {
		goos             string
		useradd, grouped bool
		want             []string
	}{
		{"linux", true, false, []string{
			"groupadd --system conflux",
			"useradd --system --gid conflux --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --comment 'conflux anchord' conflux",
		}},
		{"linux", true, true, []string{
			"useradd --system --gid conflux --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --comment 'conflux anchord' conflux",
		}},
		{"linux", false, false, []string{
			"addgroup -S conflux",
			"adduser -S -D -H -h /nonexistent -s /sbin/nologin -G conflux -g 'conflux anchord' conflux",
		}},
		{"freebsd", false, false, []string{
			"pw groupadd conflux",
			"pw useradd conflux -g conflux -d /nonexistent -s /usr/sbin/nologin -c 'conflux anchord'",
		}},
		{"openbsd", false, false, []string{
			"groupadd conflux",
			"useradd -g conflux -d /var/empty -s /sbin/nologin -L daemon -c 'conflux anchord' conflux",
		}},
	} {
		var got []string
		for _, argv := range createCommands(c.goos, "conflux", c.useradd, c.grouped, 0) {
			got = append(got, shell(argv))
		}

		if !slices.Equal(got, c.want) {
			t.Errorf("%s useradd=%v grouped=%v:\n got %q\nwant %q", c.goos, c.useradd, c.grouped, got, c.want)
		}
	}

	// macOS has no tool that picks an id, so one is given to the group and the user both,
	// and the account is hidden and can log in to nothing.
	mac := createCommands("darwin", "_conflux", false, false, 211)
	joined := make([]string, len(mac))

	for i, argv := range mac {
		joined[i] = shell(argv)
	}

	for _, want := range []string{
		"dscl . -create /Groups/_conflux PrimaryGroupID 211",
		"dscl . -create /Users/_conflux UniqueID 211",
		"dscl . -create /Users/_conflux PrimaryGroupID 211",
		"dscl . -create /Users/_conflux UserShell /usr/bin/false",
		"dscl . -create /Users/_conflux RealName 'conflux anchord'",
		"dscl . -create /Users/_conflux Password '*'",
		"dscl . -create /Users/_conflux IsHidden 1",
	} {
		if !slices.Contains(joined, want) {
			t.Errorf("the macOS account is not made with %q:\n%s", want, strings.Join(joined, "\n"))
		}
	}
}

// TestRemoveCommandsUndoCreate: the account first, then the group.
func TestRemoveCommandsUndoCreate(t *testing.T) {
	for goos, want := range map[string]string{
		"linux":   "userdel conflux; groupdel conflux",
		"freebsd": "pw userdel conflux; pw groupdel conflux",
		"openbsd": "userdel conflux; groupdel conflux",
		"darwin":  "dscl . -delete /Users/conflux; dscl . -delete /Groups/conflux",
	} {
		var got []string
		for _, argv := range removeCommands(goos, "conflux", true) {
			got = append(got, shell(argv))
		}

		if strings.Join(got, "; ") != want {
			t.Errorf("%s: %q, want %q", goos, strings.Join(got, "; "), want)
		}
	}
}

func TestFreeID(t *testing.T) {
	if id, err := freeID(map[int]bool{200: true, 201: true}); err != nil || id != 202 {
		t.Errorf("freeID = %d, %v; want 202", id, err)
	}

	full := map[int]bool{}
	for id := 200; id <= 400; id++ {
		full[id] = true
	}

	if _, err := freeID(full); err == nil {
		t.Error("an id was found where none is free")
	}
}

// TestHowToCreateSaysWhatToRun: an account conflux could not make is one the operator
// can, with exactly the commands conflux would have run.
func TestHowToCreateSaysWhatToRun(t *testing.T) {
	err := howToCreate("conflux", createCommands("linux", "conflux", true, false, 0), errors.New("no useradd"))

	for _, want := range []string{"no useradd", "  groupadd --system conflux\n", "--comment 'conflux anchord' conflux"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal has no %q:\n%v", want, err)
		}
	}
}
