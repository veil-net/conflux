package anchor

import (
	"net/rpc"

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
