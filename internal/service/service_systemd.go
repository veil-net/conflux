package service

import (
	"fmt"
	"strings"
)

// The systemd unit, rendered here without a build tag -- as the rc scripts are -- so
// its quoting is tested on every machine that builds conflux rather than only on Linux.

// unitTemplate is the unit conflux writes.
//
// Type=notify, with sd_notify from the supervisor, is what makes `systemctl start`
// return only once the anchor is actually up rather than once fork succeeded.
//
// RestartPreventExitStatus=78 70 is the two answers a restart would only repeat.
// `conflux serve` exits 78 when there is nothing to start, and 70 when it has given up
// on a configuration or a host that no retry changes; without this the unit would
// restart into the same answer every five seconds forever, instead of showing failed.
//
// Restart=on-failure rather than always, so a deliberate clean exit stays exited.
//
// RuntimeDirectory, StateDirectory and ConfigurationDirectory make systemd create
// and mode the three directories, and clean /run/conflux on stop. conflux still
// creates them itself, so running in the foreground and on non-systemd hosts works.
//
// Deliberately absent: PrivateTmp, because nothing conflux does touches /tmp and it
// would only confuse the extraction path; and ProtectSystem=strict, which would need
// a ReadWritePaths list and would break pass-through writes such as
// `conflux keygen -out ~/key`.
const unitTemplate = `[Unit]
Description=Conflux — VeilNet anchor
Documentation=https://github.com/veil-net/conflux
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
ExecStart=%s
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=78 70
TimeoutStartSec=90
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM
User=root
Group=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
RuntimeDirectory=conflux
RuntimeDirectoryMode=0700
StateDirectory=conflux
StateDirectoryMode=0700
ConfigurationDirectory=conflux
ConfigurationDirectoryMode=0700
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`

// systemdUnit is the unit for exe run with args.
func systemdUnit(exe string, args []string) string {
	return fmt.Sprintf(unitTemplate, execLine(append([]string{exe}, args...)))
}

// execLine renders an ExecStart= command line, each word quoted where systemd would
// otherwise split it or read it: whitespace, quotes and backslashes are quoted and
// escaped, and a % or a $ -- a specifier or a variable to systemd, quoted or not -- is
// doubled. A CONFLUX_DIR run registers its root here, and a path may hold any of them.
func execLine(words []string) string {
	literal := strings.NewReplacer("%", "%%", "$", "$$")
	quoted := strings.NewReplacer(`\`, `\\`, `"`, `\"`)

	out := make([]string, len(words))

	for i, w := range words {
		w = literal.Replace(w)
		if w == "" || strings.ContainsAny(w, " \t\n\"'\\;") {
			w = `"` + quoted.Replace(w) + `"`
		}

		out[i] = w
	}

	return strings.Join(out, " ")
}
