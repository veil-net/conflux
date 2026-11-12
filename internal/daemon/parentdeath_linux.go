package daemon

import "syscall"

// setParentDeath has the child sent SIGTERM when the thread that started it ends, which
// startProcess arranges to be when this process ends. SIGTERM rather than SIGKILL, so
// anchord still closes its anchor and takes its interface and host rules down with it.
func setParentDeath(attr *syscall.SysProcAttr) {
	if attr != nil {
		attr.Pdeathsig = syscall.SIGTERM
	}
}
