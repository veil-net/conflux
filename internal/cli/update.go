package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/service"
	"github.com/veil-net/conflux/internal/ui"
	"github.com/veil-net/conflux/internal/update"
	"github.com/veil-net/conflux/internal/version"
)

// updateFrom, updateExecutable and updateLink are what a test points elsewhere: the release an
// update reads, the file it replaces, and the link it makes for sudo (none on Windows).
var (
	updateFrom       = update.Source{}
	updateExecutable = paths.InstalledExecutable
	updateLink       = paths.SudoLink
)

// channel is the release a build updates to, and what to call it: the newest build of its own
// channel, `latest` for a release and the pre-release `dev-latest` for a dev build. Never the
// other's: a dev build's anchor is pinned to the dev tree and a release's to the production
// tree, and the credential a machine holds is valid in one alone.
func channel(dev bool) (tag, what string) {
	if dev {
		return update.DevTag, "dev build"
	}

	return update.ReleaseTag, "release"
}

// installed is the conflux an update replaces, as it says what it is, and whether it is a dev
// build, which decides the channel the update follows: the machine's credential is valid in
// the installed build's tree alone, whichever conflux runs the update. It is asked, by running
// it for its `version`, where it is there and is not this process; this build answers where
// nothing is installed, where this is it, and where what is installed does not run and so
// cannot say.
func installed(ctx context.Context, exe string) (says string, dev bool) {
	if _, err := os.Stat(exe); errors.Is(err, os.ErrNotExist) {
		return fmt.Sprintf("Nothing is installed at %s.\nThis is %s, so its channel is followed.", exe, version.String()),
			version.Dev()
	}

	if isThis(exe) {
		return fmt.Sprintf("%s is %s.", exe, version.String()), version.Dev()
	}

	line, dev, err := versionOf(ctx, exe)
	if err != nil {
		return fmt.Sprintf("%s does not run here: %v.\nThis is %s, so its channel is followed.",
			exe, err, version.String()), version.Dev()
	}

	return fmt.Sprintf("%s is %s.", exe, line), dev
}

// isThis reports whether path is the file this process runs.
func isThis(path string) bool {
	self, err := service.Executable()

	return err == nil && sameFile(self, path)
}

// sameFile reports whether a and b name one file, or one directory, by what each is rather than
// how it is spelled: through a link, in another case, by a short name. The one way conflux asks
// whether a path is a conflux it knows: update of the installed file, which it need not run to
// ask its version where it is this one (isThis), and on Unix of the conflux root's PATH finds,
// which needs no link for sudo where it is the one installed (putOnPath); and uninstall on
// Windows of the directory it removes, which waits for this process to exit where its image is
// in it.
func sameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}

	bi, err := os.Stat(b)

	return err == nil && os.SameFile(ai, bi)
}

// runUpdate replaces the installed conflux with the one the newest build of the installed
// conflux's channel holds for this platform, and moves the boot service onto it.
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
		"The installed conflux decides: a release updates to the `latest` release of\n"+
		"github.com/veil-net/conflux, and a dev build to the newest dev build, the pre-release\n"+
		"`dev-latest`, whichever conflux runs the update: never one to the other, since each\n"+
		"one's anchor is pinned to its own tree. With nothing installed, this conflux's channel.\n"+
		"Held to the SHA-256 the release lists, into %s, where the installer\n"+
		"puts it. A running anchor is restarted on the new conflux; a stopped one is left\n"+
		"stopped, and starts on it next time.\n\n", paths.InstalledExecutable()))

	check := fs.Bool("check", false, "say whether there is an update, and change nothing")
	if exit, ok := flagsAlone(fs, args); !ok {
		return exit
	}

	exe := updateExecutable()

	src := updateFrom
	src.UserAgent = version.UserAgent()

	says, dev := installed(ctx, exe)
	tag, what := channel(dev)

	rel, err := update.Latest(ctx, src, tag, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return fail(err)
	}

	// Nothing installed yet is no reason to refuse: the update installs it.
	same, err := rel.Is(exe)
	fresh := errors.Is(err, os.ErrNotExist)

	switch {
	case err != nil && !fresh:
		return fail(err)
	case same:
		ui.Printf("%s is conflux's newest %s: %s.\n", exe, what, rel.Name)

		return ExitOK
	}

	ui.Printf("%s\nThe newest %s is %s, built from %s.\n", says, what, rel.Name, short(rel.Commit))

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
	now, _, err := versionOf(ctx, tmp)
	if err != nil {
		return fail(fmt.Errorf("the downloaded conflux does not run on this machine, so nothing was replaced: %w", err))
	}

	if err := update.Replace(tmp, exe); err != nil {
		return fail(err)
	}

	ui.Printf("Updated %s: %s.\n", exe, now)

	// Installed where there was none, it is found by name as the installer has it found: on
	// Windows through the machine's PATH, elsewhere through the link for sudo where root's PATH
	// leaves its directory out. Said rather than refused, since the update itself is done.
	if fresh {
		if err := putOnPath(exe); err != nil {
			ui.Errf("%v", err)
		}
	}

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

// versionOf runs the conflux at path for its `version`, and returns the line that leads it and
// whether it says it is a dev build.
func versionOf(ctx context.Context, path string) (line string, dev bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	out, err := runQuiet(ctx, path, os.Environ(), []string{"version"})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if err != nil || !strings.HasPrefix(lines[0], "conflux ") {
		return "", false, errors.New(strings.TrimSpace(lines[0] + " " + errString(err)))
	}

	return lines[0], slices.ContainsFunc(lines[1:], func(l string) bool { return strings.HasPrefix(l, devBuild) }), nil
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
