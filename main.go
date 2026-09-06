// Command conflux puts this machine on a VeilNet overlay.
//
// It carries anchord and anchorctl inside itself and adds the four things anchor
// deliberately leaves to whoever is deploying it: enrolment, credential renewal, a
// configuration file, and a boot service. Everything anchorctl can do, conflux can
// do -- an argument vector conflux does not recognise is handed to anchorctl
// unchanged.
package main

import (
	"os"

	"github.com/veil-net/conflux/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args)) }
