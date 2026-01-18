package anchor

import (
	"net/rpc"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
)

type AnchorPlugin struct {
	Impl Anchor
}

func (p *AnchorPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return &AnchorRPCServer{Impl: p.Impl}, nil
}

func (AnchorPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &AnchorRPC{client: c}, nil
}

var handshakeConfig = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "ANCHOR",
	MagicCookieValue: "anchor",
}

var pluginMap = map[string]plugin.Plugin{
	"anchor": &AnchorPlugin{},
}

var HCLogger = hclog.New(&hclog.LoggerOptions{
	Name:       "conflux",
	Level:      hclog.Info,
	Output:     os.Stderr,
	JSONFormat: false,
	Color:      hclog.ForceColor,
	DisableTime: true,
})
