package cli

import "github.com/veil-net/conflux/internal/service"

// Exit codes. Most are conventional; 78 and 70 are load-bearing, and service defines them.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2

	// ExitDenied means root or Administrator is needed.
	ExitDenied = 13

	// ExitUnavailable means nothing is running here. EX_UNAVAILABLE.
	ExitUnavailable = 69

	// ExitChildFailed means a configuration conflux or anchor refuses for good: no
	// restart would start it, so no boot manager restarts the supervisor after it.
	ExitChildFailed = service.ExitChildFailed

	// ExitNoConfig means this machine has never been configured. EX_CONFIG.
	//
	// No boot manager restarts the supervisor after it, so a machine with a registered
	// service and no configuration stops cleanly instead of restarting every five seconds
	// until somebody notices.
	ExitNoConfig = service.ExitNoConfig
)
