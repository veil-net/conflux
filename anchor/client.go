// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package anchor

import (
	"net/rpc"
)

// AnchorRPC is the RPC client implementation that talks over RPC.
// This is what the host application uses to communicate with the plugin.
type AnchorRPC struct {
	client *rpc.Client
}

func (g *AnchorRPC) CreateAnchor() error {
	var resp error
	err := g.client.Call("Plugin.CreateAnchor", new(interface{}), &resp)
	if err != nil {
		return err
	}
	return resp
}

func (g *AnchorRPC) DestroyAnchor() error {
	var resp error
	err := g.client.Call("Plugin.DestroyAnchor", new(interface{}), &resp)
	if err != nil {
		return err
	}
	return resp
}

func (g *AnchorRPC) StartAnchor(guardianURL, veilURL string, veilPort int, anchorToken string, portal bool) error {
	args := &StartAnchorArgs{
		GuardianURL: guardianURL,
		VeilURL:     veilURL,
		VeilPort:    veilPort,
		AnchorToken: anchorToken,
		Portal:      portal,
	}
	var resp error
	err := g.client.Call("Plugin.StartAnchor", args, &resp)
	if err != nil {
		return err
	}
	return resp
}

func (g *AnchorRPC) StopAnchor() error {
	var resp error
	err := g.client.Call("Plugin.StopAnchor", new(interface{}), &resp)
	if err != nil {
		return err
	}
	return resp
}

func (g *AnchorRPC) CreateTUN(ifname string, mtu int) error {
	var resp error
	err := g.client.Call("Plugin.CreateTUN", &CreateTUNArgs{Ifname: ifname, MTU: mtu}, &resp)
	if err != nil {
		return err
	}
	return resp
}

func (g *AnchorRPC) DestroyTUN() error {
	var resp error
	err := g.client.Call("Plugin.DestroyTUN", new(interface{}), &resp)
	if err != nil {
		return err
	}
	return resp
}

func (g *AnchorRPC) LinkWithTUN() error {
	var resp error
	err := g.client.Call("Plugin.LinkWithTUN", new(interface{}), &resp)
	if err != nil {
		return err
	}
	return resp
}

func (g *AnchorRPC) LinkWithFileDescriptor(fileDescriptor int) error {
	var resp error
	err := g.client.Call("Plugin.LinkWithFileDescriptor", &LinkWithFileDescriptorArgs{FileDescriptor: fileDescriptor}, &resp)
	if err != nil {
		return err
	}
	return resp
}

func (g *AnchorRPC) GetID() (string, error) {
	var resp string
	err := g.client.Call("Plugin.GetID", new(interface{}), &resp)
	if err != nil {
		return "", err
	}
	return resp, nil
}