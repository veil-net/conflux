// Package main is the entry point for the VeilNet Conflux CLI.
package main

import (
	"os"

	"github.com/alecthomas/kong"
	"github.com/veil-net/conflux/cli"
)

// version is the internal version string used by kong for the CLI.
var version = "beta-v1.0.2"

// main parses the CLI with kong, runs the selected command, and exits with 1 on error.
//
// Inputs: none.
//
// Outputs: none. Exits with code 0 on success or 1 if the selected command returns an error.
func main() {
	// Parse the CLI arguments
	var cli cli.CLI
	ctx := kong.Parse(&cli, kong.Vars{"version": version})
	err := ctx.Run()
	if err != nil {
		os.Exit(1)
	}
}
