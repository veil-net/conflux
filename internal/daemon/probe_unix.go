//go:build !windows

package daemon

import (
	"os"
	"syscall"

	"github.com/veil-net/conflux/internal/config"
)

// deviceFacts is the uplink's device, or nil for a spec that names none or a device that
// is not there yet -- decided again once it is.
func deviceFacts(uplink string) *fileFacts {
	if uplink == "" {
		return nil
	}

	spec, err := config.ParseUplinkSpec(uplink)
	if err != nil || spec.Path == "" {
		return nil
	}

	return fileAt(spec.Path)
}

// fileAt is who may open the file at path, or nil when there is none.
func fileAt(path string) *fileFacts {
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}

	f := &fileFacts{path: path, mode: fi.Mode(), gid: -1}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		f.gid = int(st.Gid)
	}

	return f
}
