//go:build !windows

package service

import (
	"errors"
	"fmt"
	"strings"
)

// rcEnabled is how a BSD's rc enables conflux at boot: a line in the administrator's rc
// configuration, a command that takes it out, and a question whose yes is that line still there.
// Both BSDs' are here, under no tag of either, so Remove's half is tested where conflux is built.
type rcEnabled struct {
	file, line    string   // the file the line is in, and what it does there
	disable, left []string // the command that takes it out; the question that finds it there
}

var (
	// sysrc -x takes the variable out of rc.conf, and refuses one that is not set; -n prints a
	// set one's value, whatever it is, and exits 1 for one that is not.
	freebsdEnabled = rcEnabled{
		"rc.conf", "sets " + rcName + "_enable",
		[]string{"sysrc", "-x", rcName + "_enable"}, []string{"sysrc", "-n", rcName + "_enable"},
	}

	// rcctl(8): disable takes the service out of rc.conf.local; get ... status exits 0 for one
	// that is enabled.
	openbsdEnabled = rcEnabled{
		"rc.conf.local", "enables " + rcName,
		[]string{"rcctl", "disable", rcName}, []string{"rcctl", "get", rcName, "status"},
	}
)

// remove takes conflux's line out, then asks whether it is still there. One that is, is said,
// with whatever the command answered: it is conflux, left on the machine, as a file systemd's
// Remove could not remove is. The command's answer is forgiven once the line is gone, which is
// what was asked for: sysrc -x refuses a variable that was never set.
func (e rcEnabled) remove() error {
	disable := run(e.disable[0], e.disable[1:]...)

	out, left := query(e.left[0], e.left[1:]...)
	if !left {
		return nil
	}

	asked := strings.Join(e.left, " ")
	if out != "" {
		asked += ": " + out
	}

	return errors.Join(fmt.Errorf("%s still %s (%s)", e.file, e.line, asked), disable)
}
