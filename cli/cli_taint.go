package cli

import (
	"context"
	"slices"

	"github.com/veil-net/conflux/anchor"
	pb "github.com/veil-net/conflux/proto"
)

// Taint adds or removes taints via add/remove subcommands.
type Taint struct {
	Add    TaintAdd    `cmd:"add" help:"Add a taint"`
	Remove TaintRemove `cmd:"remove" help:"Remove a taint"`
}

// TaintAdd adds a taint to the conflux (e.g. dev, prod).
type TaintAdd struct {
	Taint string `arg:"" help:"The taint to add (e.g. dev, prod)"`
}

// Run adds the taint via the anchor client and updates the local config.
//
// Inputs:
//   - cmd: *TaintAdd. cmd.Taint is the taint string (e.g. dev, prod).
//
// Outputs:
//   - err: error. Non-nil if the client or config update fails.
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

// TaintRemove removes a taint from the conflux.
type TaintRemove struct {
	Taint string `arg:"" help:"The taint to remove"`
}

// Run removes the taint via the anchor client and updates the local config.
//
// Inputs:
//   - cmd: *TaintRemove. cmd.Taint is the taint to remove.
//
// Outputs:
//   - err: error. Non-nil if the client or config update fails.
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
