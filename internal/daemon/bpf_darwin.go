//go:build darwin

package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/veil-net/conflux/internal/account"
	"golang.org/x/sys/unix"
)

// The BPF devices, and why the supervisor is the one to open them up.
//
// On macOS the observer captures through a BPF device on each interface, and only root may
// read one: devfs makes each root:wheel 0600, and makes a new one only as the last there is
// is opened, up to the kernel's limit. What Wireshark's ChmodBPF does at every boot is the
// usual answer -- open each so it exists, then give a group read access -- and the
// supervisor, which launchd starts as root at every boot, does the same before it starts
// anchord as the account, giving the account's own group read and nothing more. Read is all
// a capture needs: a member can see what the host carries and send nothing.
//
// devfs makes the devices afresh at every boot, so what is given here lasts until the next
// one and is given again by the next start; and it is taken back, the devices root's alone
// again, by a start that does not observe as the account and by `conflux uninstall`. Only the
// devices whose group is the account's are touched: a host whose devices another group can
// read already (ChmodBPF's access_bpf) is left as it is, and the account is given that group
// instead (decide).

// bpfDevices is how many BPF devices are made and opened up: the kernel's limit, and 256 at
// most, as ChmodBPF does.
func bpfDevices() int {
	n, err := unix.SysctlUint32("debug.bpf_maxdevices")
	if err != nil || n == 0 {
		return 256
	}

	return min(int(n), 256)
}

// bpfFacts is the first BPF device, for decide, and the account's own group, which a
// device is given by this supervisor and so is not a group of the host's.
func bpfFacts() (*fileFacts, int) {
	own := -1
	if a, err := account.Lookup(); err == nil && a != nil {
		own = a.GID
	}

	return fileAt("/dev/bpf0"), own
}

// grantBPF makes the BPF devices and gives gid read access to every one.
func grantBPF(gid int) error {
	if gid <= 0 {
		return fmt.Errorf("the account's group is %d, which is root's or none", gid)
	}

	// Opened, so that devfs makes the next: a device that exists already opens or is busy,
	// and either way the one after it is made.
	for i := range bpfDevices() {
		if f, err := os.Open("/dev/bpf" + strconv.Itoa(i)); err == nil {
			_ = f.Close()
		}
	}

	devices, err := filepath.Glob("/dev/bpf*")
	if err != nil {
		return err
	}

	if len(devices) == 0 {
		return errors.New("there are no /dev/bpf* devices")
	}

	for _, d := range devices {
		if err := os.Chown(d, 0, gid); err != nil {
			return err
		}

		if err := os.Chmod(d, 0o640|fs.ModeDevice|fs.ModeCharDevice); err != nil {
			return err
		}
	}

	return nil
}

// RevokeBPF gives every BPF device whose group is the account's back to root alone, as
// devfs makes them. Nothing where the account does not exist, or no device is its.
func RevokeBPF() error {
	a, err := account.Lookup()
	if err != nil || a == nil {
		return nil
	}

	devices, err := filepath.Glob("/dev/bpf*")
	if err != nil {
		return err
	}

	var errs []error

	for _, d := range devices {
		fi, err := os.Stat(d)
		if err != nil {
			continue
		}

		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Gid) != a.GID {
			continue
		}

		if err := os.Chown(d, 0, 0); err != nil {
			errs = append(errs, err)

			continue
		}

		if err := os.Chmod(d, 0o600); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
