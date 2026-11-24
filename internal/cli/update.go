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

// updateFrom, updateExecutable and updateAtTerminal are what a test points elsewhere: the release
// an update reads, the file it replaces, and whether there is a terminal to ask at before it
// replaces it (ui.IsTerminal, which a test's own stdin never is). On Unix, updateLink is the
// fourth: the link it makes for sudo.
var (
	updateFrom       = update.Source{}
	updateExecutable = paths.InstalledExecutable
	updateAtTerminal = ui.IsTerminal
)

// installed says what the conflux an update replaces is, and whether it is a dev build. Nothing
// is none. This process is this build, a dev build where version.Dev says so. Any other file is
// what it says when run for its `version`, a dev build where it says so (devBuild), or a file
// that does not run, which cannot say what it is, and so is none.
func installed(ctx context.Context, exe string) (says string, dev bool) {
	if _, err := os.Stat(exe); errors.Is(err, os.ErrNotExist) {
		return fmt.Sprintf("Nothing is installed at %s.", exe), false
	}

	if isThis(exe) {
		return fmt.Sprintf("%s is %s.", exe, version.String()), version.Dev()
	}

	line, dev, err := versionOf(ctx, exe)
	if err != nil {
		return fmt.Sprintf("%s does not run here: %v.", exe, err), false
	}

	return fmt.Sprintf("%s is %s.", exe, line), dev
}

// askFirst asks at a terminal before update installs what, the release or the dev build, saying
// first why it asks, and says whether to go on, and where not, update's exit. Off a terminal it
// refuses, saying refused, as up refuses an IPv4 nobody is there to give, and nothing gets past
// that; declined, nothing changes, and the exit is a declined observe's or uninstall's, 2.
func askFirst(what, why, refused string) (exit int, ok bool) {
	if !updateAtTerminal() {
		return fail(errors.New(refused)), false
	}

	ui.Printf("\n%s\n\n", why)

	if !ui.Confirm("Install the " + what + "?") {
		ui.Errf("the %s was not installed, and nothing changed", what)

		return ExitUsage, false
	}

	return ExitOK, true
}

// isThis reports whether path is the file this process runs.
func isThis(path string) bool {
	self, err := service.Executable()

	return err == nil && sameFile(self, path)
}

// sameFile reports whether a and b name one file, or one directory, by what each is rather than
// how it is spelled: through a link, in another case, by a short name. The one way conflux asks
// whether a path is a conflux it knows: update of the installed file, which it need not run to
// ask its version where it is this one (isThis), and on Unix of the conflux root's PATH finds
// (rootFinds), which needs no link for sudo where it is the one installed, and keeps one only
// where it is once linked (putOnPath); and uninstall on Windows of the directory it removes,
// which waits for this process to exit where its image is in it.
func sameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}

	bi, err := os.Stat(b)

	return err == nil && os.SameFile(ai, bi)
}

// runUpdate replaces the installed conflux with the newest release for this platform, or with
// --dev the newest dev build, and moves the boot service onto it.
//
// Only when typed. Nothing checks on a schedule, so a machine changes version when
// somebody decides it should, and never because a release was published.
//
// "Up to date" is a digest, not a version string: this file is the release's binary, byte
// for byte, or it is not. A rebuild of the same version is an update, as release.yml
// publishes one.
func runUpdate(ctx context.Context, args []string) int {
	fs := verbFlags("update", fmt.Sprintf("conflux update — replace the installed conflux with the newest release, or dev build\n\n"+
		"  conflux update                   download the newest release, verify it, put it in\n"+
		"                                   place, and move the boot service onto it\n"+
		"  conflux update --dev             the same with the newest dev build, once asked\n"+
		"  conflux update [--dev] --check   say whether there is one, and change nothing\n\n"+
		"The newest release is the `latest` release of github.com/veil-net/conflux, whatever\n"+
		"build runs the update. The newest dev build is the pre-release `dev-latest`, built\n"+
		"from conflux's dev branch with anchor's dev build inside it. Its anchor is pinned to\n"+
		"the dev tree (https://api-dev.veilnet.com.au) and a release's to the production tree,\n"+
		"and neither works with a credential from the other tree. So --dev asks at a terminal\n"+
		"before it installs a dev build, and a plain update before it puts the release in\n"+
		"place of a dev build, as the installed conflux's version says it is; each refuses\n"+
		"where there is no terminal to ask at. --check asks nothing.\n"+
		"Held to the SHA-256 the release lists, into %s, where the installer\n"+
		"puts it. A running anchor is restarted on the new conflux; a stopped one is left\n"+
		"stopped, and starts on it next time.\n\n", paths.InstalledExecutable()))

	check := fs.Bool("check", false, "say whether there is an update, and change nothing")
	dev := fs.Bool("dev", false, "the newest dev build, the pre-release dev-latest, rather than the release; asked first")

	if exit, ok := flagsAlone(fs, args); !ok {
		return exit
	}

	exe := updateExecutable()

	src := updateFrom
	src.UserAgent = version.UserAgent()

	tag, what, install := update.ReleaseTag, "release", "conflux update"
	if *dev {
		tag, what, install = update.DevTag, "dev build", "conflux update --dev"
	}

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

	says, installedDev := installed(ctx, exe)
	ui.Printf("%s\nThe newest %s is %s, built from %s.\n", says, what, rel.Name, short(rel.Commit))

	if *check {
		ui.Printf("\n  %s    install it\n", install)

		return ExitOK
	}

	if err := needsRoot("updating conflux", "update", args); err != nil {
		return fail(err)
	}

	// One tree's build in place of what may be the other's is asked for once there is one to
	// install, named above, and before anything is downloaded or replaced; after the privilege
	// check, so the command typed again under sudo asks once, rather than once before the
	// refusal and again after it. --dev asks its own question alone, of a dev build too.
	var why, refused string

	switch {
	case *dev:
		why = "A dev build is the pre-release dev-latest, built from conflux's dev branch with anchor's\n" +
			"dev build inside it. Its anchor is pinned to the dev tree (https://api-dev.veilnet.com.au),\n" +
			"so a credential from the production tree, which a release enrols in, does not work with it."
		refused = "update --dev asks before it installs a dev build, and there is no terminal to ask at"
	case installedDev:
		why = "The conflux installed here is a dev build, whose anchor is pinned to the dev tree. The\n" +
			"release's anchor is pinned to the production tree, so a credential this machine holds from\n" +
			"the dev tree does not work with it: the anchor will not start on it."
		refused = "update asks before it installs the release in place of a dev build, and there is no terminal to ask at"
	}

	if why != "" {
		if exit, ok := askFirst(what, why, refused); !ok {
			return exit
		}
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
	// does not find it, kept where root's PATH then finds it there. What is left undone is said
	// rather than refused, since the update itself is done.
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
// whether it says it is a dev build (devBuild).
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
