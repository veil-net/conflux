//go:build linux

package cli

import (
	"net"
	"os"
)

// notifyReadyWhen tells systemd the unit has actually started, once the anchor is up.
//
// Fifteen lines, and it is what makes Type=notify honest: `systemctl start conflux`
// then returns when the machine is on the overlay, rather than when fork succeeded.
// A dependent unit ordered After=conflux.service gets the same guarantee for free.
func notifyReadyWhen(ready <-chan struct{}) {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" || ready == nil {
		return
	}

	go func() {
		<-ready

		// An abstract socket is spelled with a leading @ in the environment.
		if socket[0] == '@' {
			socket = "\x00" + socket[1:]
		}

		conn, err := net.Dial("unixgram", socket)
		if err != nil {
			return
		}
		defer conn.Close()

		_, _ = conn.Write([]byte("READY=1\nSTATUS=anchor is up\n"))
	}()
}
