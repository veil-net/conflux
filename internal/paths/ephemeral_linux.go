package paths

import (
	"errors"
	"os"
	"path/filepath"
)

// runtimeFolder is the folder an ephemeral run keeps its root in, a filesystem in memory the system
// empties at boot: /run as root, and for anybody else their own runtime directory, $XDG_RUNTIME_DIR,
// refused where that is not set, or is not an absolute path.
func runtimeFolder() (string, error) {
	if os.Geteuid() == 0 {
		return "/run", nil
	}

	xdg := os.Getenv("XDG_RUNTIME_DIR")
	if xdg == "" || !filepath.IsAbs(xdg) {
		return "", errors.New("an ephemeral run keeps its root in your runtime directory, and XDG_RUNTIME_DIR does " +
			"not name one: run it from a login session that sets it (systemd-logind does), or as root, in /run")
	}

	return xdg, nil
}
