//go:build darwin && amd64

package anchor

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/hashicorp/go-plugin"
)

//go:embed bin/anchor-darwin-10.12-amd64
var anchorPlugin []byte

func NewAnchor() (Anchor, *plugin.Client, error) {
	// Extract the embedded file to a temporary directory
	pluginPath := filepath.Join(os.TempDir(), "anchor")
	// Remove existing file if it exists to avoid "text file busy" error
	os.Remove(pluginPath)
	if err := os.WriteFile(pluginPath, anchorPlugin, 0755); err != nil {
		return nil, nil, err
	}

	// Load the plugin
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: handshakeConfig,
		Plugins:         pluginMap,
		Cmd:             exec.Command(pluginPath),
		Logger:          HCLogger,
	})

	// Connect via RPC
	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, nil, err
	}

	// Request the plugin
	raw, err := rpcClient.Dispense("anchor")
	if err != nil {
		client.Kill()
		return nil, nil, err
	}

	// Cast the raw interface to the anchor interface
	anchor := raw.(Anchor)
	return anchor, client, nil
}
