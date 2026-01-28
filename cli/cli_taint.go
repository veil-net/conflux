package cli

import (
	"context"
	"slices"

	"github.com/veil-net/conflux/anchor"
	pb "github.com/veil-net/conflux/proto"
)

type Taint struct {
	Add    TaintAdd    `cmd:"add" help:"Add a taint"`
	Remove TaintRemove `cmd:"remove" help:"Remove a taint"`
}

type TaintAdd struct {
	Taint string `arg:"" help:"The taint to add (e.g. key=value)"`
}

func (cmd *TaintAdd) Run() error {
	client, err := anchor.NewAnchorClient()
	if err != nil {
		Logger.Sugar().Errorf("failed to create anchor gRPC client: %v", err)
		return err
	}

	_, err = client.AddTaint(context.Background(), &pb.AddTaintRequest{Taint: cmd.Taint})
	if err != nil {
		Logger.Sugar().Errorf("failed to add taint: %v", err)
		return err
	}

	config, err := anchor.LoadConfig()
	if err != nil {
		Logger.Sugar().Errorf("failed to load config: %v", err)
		return err
	}

	if config.Taints == nil {
		config.Taints = []string{}
	}
	if !slices.Contains(config.Taints, cmd.Taint) {
		config.Taints = append(config.Taints, cmd.Taint)
	}
	if err := anchor.SaveConfig(config); err != nil {
		Logger.Sugar().Errorf("failed to save config: %v", err)
		return err
	}

	Logger.Sugar().Infof("added taint %q and updated config", cmd.Taint)
	return nil
}

type TaintRemove struct {
	Taint string `arg:"" help:"The taint to remove"`
}

func (cmd *TaintRemove) Run() error {
	client, err := anchor.NewAnchorClient()
	if err != nil {
		Logger.Sugar().Errorf("failed to create anchor gRPC client: %v", err)
		return err
	}

	_, err = client.RemoveTaint(context.Background(), &pb.RemoveTaintRequest{Taint: cmd.Taint})
	if err != nil {
		Logger.Sugar().Errorf("failed to remove taint: %v", err)
		return err
	}

	config, err := anchor.LoadConfig()
	if err != nil {
		Logger.Sugar().Errorf("failed to load config: %v", err)
		return err
	}

	if config.Taints != nil {
		config.Taints = slices.DeleteFunc(config.Taints, func(s string) bool { return s == cmd.Taint })
	}
	if err := anchor.SaveConfig(config); err != nil {
		Logger.Sugar().Errorf("failed to save config: %v", err)
		return err
	}

	Logger.Sugar().Infof("removed taint %q and updated config", cmd.Taint)
	return nil
}
