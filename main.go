package main

import (
	"os"

	"github.com/alecthomas/kong"
	"github.com/veil-net/conflux/cli"
)

var version = "0.0.6"

func main() {
	// Parse the CLI arguments
	var cli cli.CLI
	ctx := kong.Parse(&cli, kong.Vars{"version": version})
	err := ctx.Run()
	if err != nil {
		os.Exit(1)
	}
}
