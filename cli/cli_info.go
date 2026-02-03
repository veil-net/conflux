package cli

import (
	"context"
	"fmt"

	"github.com/veil-net/conflux/anchor"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Info shows conflux, realm, veil, or tracer info via subcommands.
type Info struct {
	Conflux InfoConflux `cmd:"conflux" default:"1" help:"Show conflux info (ID, tag, UID, CIDR, portal, public)"`
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
	fmt.Println("Conflux Info")
	fmt.Println("------------")
	fmt.Printf("  %-8s %s\n", "ID:", info.GetId())
	fmt.Printf("  %-8s %s\n", "Tag:", info.GetTag())
	fmt.Printf("  %-8s %s\n", "UID:", info.GetUid())
	fmt.Printf("  %-8s %s\n", "CIDR:", info.GetCidr())
	fmt.Printf("  %-8s %v\n", "Rift:", info.GetRift())
	fmt.Printf("  %-8s %v\n", "Portal:", info.GetPortal())
	fmt.Printf("  %-8s %v\n", "Public:", info.GetPublic())
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
	fmt.Println("Realm Info")
	fmt.Println("----------")
	fmt.Printf("  %-10s %s\n", "Realm:", info.GetRealm())
	fmt.Printf("  %-10s %s\n", "Realm ID:", info.GetRealmId())
	fmt.Printf("  %-10s %s\n", "Subnet:", info.GetSubnet())
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
	fmt.Println("Veil Info")
	fmt.Println("---------")
	fmt.Printf("  %-10s %s\n", "Host:", info.GetVeilHost())
	fmt.Printf("  %-10s %d\n", "Port:", info.GetVeilPort())
	fmt.Printf("  %-10s %s\n", "Region:", info.GetRegion())
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
	fmt.Println("Tracer Info")
	fmt.Println("-------------")
	fmt.Printf("  %-10s %v\n", "Enabled:", info.GetEnabled())
	fmt.Printf("  %-10s %s\n", "Endpoint:", info.GetEndpoint())
	fmt.Printf("  %-10s %v\n", "Use TLS:", info.GetUseTls())
	fmt.Printf("  %-10s %v\n", "Insecure:", info.GetInsecure())
	fmt.Printf("  %-10s %s\n", "CA:", info.GetCa())
	fmt.Printf("  %-10s %s\n", "Cert:", info.GetCert())
	fmt.Printf("  %-10s %s\n", "Key:", info.GetKey())
	return nil
}