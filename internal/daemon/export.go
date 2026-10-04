package daemon

import (
	"encoding/json"
	"fmt"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
)

// daemonConfig is anchor.v1.DaemonConfig: one field, and nothing about the anchor.
//
// The anchor's own configuration arrives with the Start call, which is what lets
// conflux own the lifecycle. This file is the daemon's, and today it holds exactly
// one thing.
type daemonConfig struct {
	Export *config.Export `json:"export,omitempty"`
}

// writeDaemonConfig renders anchord's -config from conflux.json, on every spawn.
//
// Every spawn, so the daemon starts on what conflux.json says -- and with no export
// block when conflux.json names none, which anchord reads as export nothing, at start
// and on the SIGHUP that re-reads the file. That makes `conflux anchorctl export
// -endpoint ...`, a SetExport call held in the daemon's memory, a temporary override
// rather than a setting: it lasts until the next restart or SIGHUP. `conflux status`
// reports which surface the daemon is actually obeying, so an operator who is
// surprised can see it rather than infer it. The durable way is conflux.json.
func writeDaemonConfig(d paths.Dirs, cfg *config.Config) error {
	b, err := json.MarshalIndent(daemonConfig{Export: cfg.Export}, "", "  ")
	if err != nil {
		return fmt.Errorf("render the daemon config: %w", err)
	}

	// 0600, because export.headers authenticate this machine to a collector and
	// this file is where they land. The directory is 0700 already.
	return config.WriteFileAtomic(d.DaemonConfigFile(), append(b, '\n'), 0o600)
}
