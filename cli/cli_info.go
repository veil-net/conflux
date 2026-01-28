package cli

import (
	"context"
	"fmt"

	"github.com/veil-net/conflux/anchor"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Info struct {
	Conflux InfoConflux `cmd:"conflux" default:"1" help:"Show conflux info (ID, tag, UID, CIDR, portal, public)"`
	Realm   InfoRealm   `cmd:"realm" help:"Show realm info (realm, realm ID, subnet)"`
	Veil    InfoVeil    `cmd:"veil" help:"Show veil connection info (host, port, region)"`
}

type InfoConflux struct{}

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
	fmt.Printf("  %-8s %v\n", "Portal:", info.GetPortal())
	fmt.Printf("  %-8s %v\n", "Public:", info.GetPublic())
	return nil
}

type InfoRealm struct{}

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

type InfoVeil struct{}

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
