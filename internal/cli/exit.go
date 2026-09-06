package cli

// Exit codes. Most are conventional; 78 is load-bearing.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2

	// ExitDenied means root or Administrator is needed.
	ExitDenied = 13

	// ExitUnavailable means nothing is running here. EX_UNAVAILABLE.
	ExitUnavailable = 69

	// ExitChildFailed means anchord itself would not start.
	ExitChildFailed = 70

	// ExitNoConfig means this machine has never been configured. EX_CONFIG.
	//
	// The systemd unit names this exact number in RestartPreventExitStatus, so a
	// machine with a registered service and no configuration stops cleanly instead
	// of restarting every five seconds until somebody notices.
	ExitNoConfig = 78
)
