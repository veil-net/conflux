package cli

import (
	"context"
	"fmt"

	"github.com/veil-net/conflux/anchor"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Info shows conflux, realm, veil, tracer info, or raw ID via subcommands.
type Info struct {
	Conflux InfoConflux `cmd:"conflux" default:"1" help:"Show conflux info (ID, tag, UID, CIDR, portal, public)"`
	ID      InfoID      `cmd:"id" help:"Print conflux ID only (single line, for scripts)"`
	Realm   InfoRealm   `cmd:"realm" help:"Show realm info (realm, realm ID, subnet)"`
	Veil    InfoVeil    `cmd:"veil" help:"Show veil connection info (host, port, region)"`
	Tracer  InfoTracer  `cmd:"tracer" help:"Show tracer config (enabled, endpoint, use TLS, insecure, CA, cert, key)"`
}

// InfoConflux shows conflux info (ID, tag, UID, CIDR, portal, public).
type InfoConflux struct{}

// Run prints conflux info from the anchor gRPC client.
//
// Inputs:
//   - cmd: *InfoConflux. The subcommand.
//
// Outputs:
//   - err: error. Non-nil if the anchor client or RPC fails.
func (cmd *InfoConflux) Run() error {
	client, err := anchor.NewAnchorClient()
	if err != nil {
		Logger.Sugar().Errorf("failed to create anchor gRPC client: %v", err)
		return err
	}
	info, err := client.GetInfo(context.Background(), &emptypb.Empty{})
	if err != nil {
		Logger.Sugar().Errorf("failed to get conflux info: %v", err)
		return err
	}
	out, err := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}.Marshal(info)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

// InfoID prints only the conflux node ID.
type InfoID struct{}

// Run prints the conflux ID as a single line of stdout (no labels or headers).
func (cmd *InfoID) Run() error {
	client, err := anchor.NewAnchorClient()
	if err != nil {
		Logger.Sugar().Errorf("failed to create anchor gRPC client: %v", err)
		return err
	}
	info, err := client.GetInfo(context.Background(), &emptypb.Empty{})
	if err != nil {
		Logger.Sugar().Errorf("failed to get conflux info: %v", err)
		return err
	}
	fmt.Println(info.GetId())
	return nil
}

// InfoRealm shows realm info (realm, realm ID, subnet).
type InfoRealm struct{}

// Run prints realm info from the anchor gRPC client.
//
// Inputs:
//   - cmd: *InfoRealm. The subcommand.
//
// Outputs:
//   - err: error. Non-nil if the anchor client or RPC fails.
func (cmd *InfoRealm) Run() error {
	client, err := anchor.NewAnchorClient()
	if err != nil {
		Logger.Sugar().Errorf("failed to create anchor gRPC client: %v", err)
		return err
	}
	info, err := client.GetRealmInfo(context.Background(), &emptypb.Empty{})
	if err != nil {
		Logger.Sugar().Errorf("failed to get realm info: %v", err)
		return err
	}
	out, err := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}.Marshal(info)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

// InfoVeil shows veil connection info (host, port, region).
type InfoVeil struct{}

// Run prints veil info from the anchor gRPC client.
//
// Inputs:
//   - cmd: *InfoVeil. The subcommand.
//
// Outputs:
//   - err: error. Non-nil if the anchor client or RPC fails.
func (cmd *InfoVeil) Run() error {
	client, err := anchor.NewAnchorClient()
	if err != nil {
		Logger.Sugar().Errorf("failed to create anchor gRPC client: %v", err)
		return err
	}
	info, err := client.GetVeilInfo(context.Background(), &emptypb.Empty{})
	if err != nil {
		Logger.Sugar().Errorf("failed to get veil info: %v", err)
		return err
	}
	out, err := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}.Marshal(info)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

// InfoTracer shows tracer config (enabled, endpoint, use TLS, insecure, CA, cert, key).
type InfoTracer struct{}

// Run prints tracer config from the anchor gRPC client.
//
// Inputs:
//   - cmd: *InfoTracer. The subcommand.
//
// Outputs:
//   - err: error. Non-nil if the anchor client or RPC fails.
func (cmd *InfoTracer) Run() error {
	client, err := anchor.NewAnchorClient()
	if err != nil {
		Logger.Sugar().Errorf("failed to create anchor gRPC client: %v", err)
		return err
	}
	info, err := client.GetTracerConfig(context.Background(), &emptypb.Empty{})
	if err != nil {
		Logger.Sugar().Errorf("failed to get tracer config: %v", err)
		return err
	}
	out, err := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}.Marshal(info)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}
