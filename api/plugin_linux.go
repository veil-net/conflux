//go:build linux
// +build linux

package api

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/hashicorp/go-plugin"
	"github.com/veil-net/conflux/anchor"
)

//go:embed veilnet
var anchorPlugin []byte

func (a *API) anchor() error {
	// Extract the embedded file to a temporary directory
	pluginPath := filepath.Join(os.TempDir(), "veilnet")
	if err := os.WriteFile(pluginPath, anchorPlugin, 0755); err != nil {
		return err
	}

	// Load the plugin
	a.plugin = plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: handshakeConfig,
		Plugins:         pluginMap,
		Cmd:             exec.Command(pluginPath),
	})

	// Connect via RPC
	rpcClient, err := a.plugin.Client()
	if err != nil {
		return err
	}

	// Request the plugin
	raw, err := rpcClient.Dispense("anchor")
	if err != nil {
		return err
	}

	// Cast the raw interface to the anchor interface
	anchor := raw.(anchor.Anchor)
	a.anchorInterface = anchor
	return nil
}