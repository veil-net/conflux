package daemon

import (
	"fmt"
	"os/exec"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// capNumbers are the capabilities anchord is ever given, by name.
var capNumbers = map[string]uintptr{
	capNetBindService: unix.CAP_NET_BIND_SERVICE,
	capNetAdmin:       unix.CAP_NET_ADMIN,
	capNetRaw:         unix.CAP_NET_RAW,
}

// secbitNoCapAmbientRaise is SECBIT_NO_CAP_AMBIENT_RAISE: set, no process may raise an
// ambient capability, so none reaches a process that is not root.
const secbitNoCapAmbientRaise = 1 << 6

// canGive says what keeps this supervisor from handing anchord to the account, or "".
//
// Handing it over needs CAP_SETUID and CAP_SETGID for the child's setgroups, setgid and
// setuid; CAP_CHOWN and CAP_FOWNER to give the account its directories; CAP_DAC_OVERRIDE
// to reach the account's socket and directory afterwards; and CAP_KILL to stop what it
// runs. A container started with only CAP_NET_ADMIN has none of them, and there anchord
// runs as the supervisor does, which is all the container gave either.
//
// A capability p asks for that the supervisor does not hold, in its permitted and its
// bounding set both, is dropped from p rather than refused: running as the supervisor
// would not have it either.
func canGive(p *Privilege) string {
	effective, permitted, err := capabilitySets()
	if err != nil {
		return "the supervisor could not read its own capabilities: " + err.Error()
	}

	for _, need := range []struct {
		name string
		cap  uintptr
	}{
		{"CAP_SETUID", unix.CAP_SETUID},
		{"CAP_SETGID", unix.CAP_SETGID},
		{"CAP_CHOWN", unix.CAP_CHOWN},
		{"CAP_FOWNER", unix.CAP_FOWNER},
		{"CAP_DAC_OVERRIDE", unix.CAP_DAC_OVERRIDE},
		{"CAP_KILL", unix.CAP_KILL},
	} {
		if effective&(1<<need.cap) == 0 {
			return "the supervisor has no " + need.name + ", which handing anchord to an account of its own needs"
		}
	}

	p.keepCaps(func(name string) bool {
		c := capNumbers[name]

		return permitted&(1<<c) != 0 && inBounding(c)
	})

	if len(p.Caps) > 0 {
		if bits, err := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0); err == nil && bits&secbitNoCapAmbientRaise != 0 {
			return "this host forbids raising an ambient capability (SECBIT_NO_CAP_AMBIENT_RAISE), which the account needs"
		}
	}

	return ""
}

// capabilitySets are this process's effective and permitted capabilities, as bit masks.
func capabilitySets() (effective, permitted uint64, err error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}

	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return 0, 0, fmt.Errorf("capget: %w", err)
	}

	effective = uint64(data[0].Effective) | uint64(data[1].Effective)<<32
	permitted = uint64(data[0].Permitted) | uint64(data[1].Permitted)<<32

	return effective, permitted, nil
}

func inBounding(c uintptr) bool {
	n, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, c, 0, 0, 0)

	return err == nil && n == 1
}

// withCaps gives the account caps as ambient capabilities, which it keeps across exec and
// hands to the commands it runs -- nft and iptables need CAP_NET_ADMIN themselves. Go keeps
// them across the setuid with PR_SET_KEEPCAPS and raises them in the child; with none, the
// setuid clears every capability the supervisor had.
func withCaps(attr *syscall.SysProcAttr, caps []string) {
	for _, c := range caps {
		attr.AmbientCaps = append(attr.AmbientCaps, capNumbers[c])
	}
}

// startProcess starts cmd, under no_new_privs where p asks for it.
//
// Go has no field for no_new_privs, and it is a thread's: set on the thread that forks,
// the child inherits it. So it is set on a goroutine locked to its thread, which starts
// the child and then returns without unlocking -- and a goroutine that ends locked takes
// its thread with it, so nothing else in the supervisor is ever run under it.
func startProcess(cmd *exec.Cmd, p Privilege) error {
	if !p.Account || !p.NoNewPrivs {
		return cmd.Start()
	}

	errc := make(chan error, 1)

	go func() {
		runtime.LockOSThread()

		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			errc <- fmt.Errorf("set no_new_privs: %w", err)

			return
		}

		errc <- cmd.Start()
	}()

	return <-errc
}
