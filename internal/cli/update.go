package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/service"
	"github.com/veil-net/conflux/internal/ui"
	"github.com/veil-net/conflux/internal/update"
	"github.com/veil-net/conflux/internal/version"
)

// updateFrom and updateExecutable are what a test points elsewhere: the release an update
// reads, and the file it replaces.
var (
	updateFrom       = update.Source{}
	updateExecutable = paths.InstalledExecutable
)

// channel is the release this build updates to, and what to call it: the newest build of its
// own channel, `latest` for a release and the pre-release `dev-latest` for a dev build. Never
// the other's: a dev build's anchor is pinned to the dev tree and a release's to the production
// tree, and the credential a machine holds is valid in one alone.
func channel() (tag, what string) {
	if version.Dev() {
		return update.DevTag, "dev build"
	}

	return update.ReleaseTag, "release"
}

// runUpdate replaces the installed conflux with the one the newest build of its channel holds
// for this platform, and moves the boot service onto it.
//
// Only when typed. Nothing checks on a schedule, so a machine changes version when
// somebody decides it should, and never because a release was published.
//
// "Up to date" is a digest, not a version string: this file is the release's binary, byte
// for byte, or it is not. A rebuild of the same version is an update, as release.yml
// publishes one.
func runUpdate(ctx context.Context, args []string) int {
	fs := verbFlags("update", fmt.Sprintf("conflux update — replace the installed conflux with the newest build of its channel\n\n"+
		"  conflux update           download it, verify it, put it in place, and move\n"+
		"                           the boot service onto it\n"+
		"  conflux update --check   say whether there is one, and change nothing\n\n"+
		"A release updates to the `latest` release of github.com/veil-net/conflux, and a dev\n"+
		"build to its newest dev build, the pre-release `dev-latest`: never one to the other,\n"+
		"since each one's anchor is pinned to its own tree. Held to the SHA-256 the release\n"+
		"lists, into %s, where the installer puts it. A running anchor is\n"+
		"restarted on the new conflux; a stopped one is left stopped, and starts on it next\n"+
		"time.\n\n", paths.InstalledExecutable()))

	check := fs.Bool("check", false, "say whether there is an update, and change nothing")
	if err := fs.Parse(args); err != nil {
		return usageExit(err)
	}

	if fs.NArg() > 0 {
		ui.Errf("conflux update takes no arguments, and got %q.\n\n"+
			"  conflux update\n"+
			"  conflux update --check", fs.Arg(0))

		return ExitUsage
	}

	exe := updateExecutable()

	src := updateFrom
	src.UserAgent = version.UserAgent()

	tag, what := channel()

	rel, err := update.Latest(ctx, src, tag, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return fail(err)
	}

	// Nothing installed yet is no reason to refuse: the update installs it.
	if same, err := rel.Is(exe); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	} else if same {
		ui.Printf("%s is conflux's newest %s: %s.\n", exe, what, rel.Name)

		return ExitOK
	}

	ui.Printf("This is %s.\nThe newest %s is %s, built from %s.\n", version.String(), what, rel.Name, short(rel.Commit))

	if *check {
		ui.Printf("\n  conflux update    install it\n")

		return ExitOK
	}

	if err := needsRoot("updating conflux", "update", args); err != nil {
		return fail(err)
	}

	// A Windows image an earlier update moved aside, which nothing runs any more.
	_ = os.Remove(exe + ".old")

	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		return fail(err)
	}

	tmp, err := rel.Download(ctx, filepath.Dir(exe))
	if err != nil {
		return fail(err)
	}

	defer os.Remove(tmp) // nothing once it has been renamed

	// Run before it replaces anything. The digest says these are the bytes the release
	// holds; this says they are a conflux that starts on this machine.
	now, err := versionOf(ctx, tmp)
	if err != nil {
		return fail(err)
	}

	if err := update.Replace(tmp, exe); err != nil {
		return fail(err)
	}

	ui.Printf("Updated %s: %s.\n", exe, now)

	return moveService(ctx, exe)
}

// moveService puts the boot service on the conflux at exe, which has just replaced this one.
//
// A running anchor is restarted by the new conflux's own `start`, which places the copy
// the service runs and restarts it: the new code decides how it is started. A stopped one
// is left stopped, as `down` left it, with its copy refreshed so that whatever starts it
// next starts the new one.
func moveService(ctx context.Context, exe string) int {
	installed, err := services().Installed()
	if err != nil {
		return fail(err)
	}

	if !installed {
		return ExitOK
	}

	d := paths.Default()

	a := askDaemon(ctx, d, false)
	a.wg.Wait()

	if a.asked && a.statErr == nil {
		ui.Printf("The anchor is running the previous conflux; restarting it on this one.\n\n")

		return runChild(ctx, exe, "start")
	}

	placed, err := service.PlaceFrom(d, exe)
	if err != nil {
		return fail(err)
	}

	if err := register(services(), placed); err != nil {
		return fail(err)
	}

	ui.Printf("The anchor is not running; the boot service starts it on this conflux next time.\n")

	return ExitOK
}

// versionOf runs the binary at path and returns the line its `version` leads with.
func versionOf(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	out, err := runQuiet(ctx, path, os.Environ(), []string{"version"})

	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	if err != nil || !strings.HasPrefix(line, "conflux ") {
		return "", errors.New("the downloaded conflux does not run on this machine, so nothing was replaced: " +
			strings.TrimSpace(line+" "+errString(err)))
	}

	return line, nil
}

// runChild runs exe with args on this terminal and returns its exit code.
func runChild(ctx context.Context, exe string, args ...string) int {
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}

		return fail(err)
	}

	return ExitOK
}

func short(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}

	return commit
}

func errString(err error) string {
	if err == nil {
		return ""
	}

	return "(" + err.Error() + ")"
}
