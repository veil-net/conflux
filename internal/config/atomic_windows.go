package config

import (
	"io/fs"
	"os"
)

// keep: a file holding what conflux writes stays as it is. Its mode bits mean nothing here,
// and no registration is a file: the SCM keeps the service's.
func keep(*os.File, string, fs.FileMode) (bool, error) { return true, nil }
