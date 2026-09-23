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
	Export *config.Export `json:"export"`
}

// writeDaemonConfig renders the export block for anchord, on every spawn.
//
// **Written every time, including when there is nothing to export**, and that is
// the precedence decision rather than an implementation detail. Three surfaces can
// configure export and they disagree by design: this file, a SetExport call, and a
// SIGHUP that re-reads the file and discards whatever the call did. Writing an
// explicit `enabled: false` when conflux.json has no export block means a restart
// always lands on what conflux.json says, so:
//
//   - a machine configured to export comes back exporting, which is the whole
//     point -- an RPC-set export dies with the daemon and the only symptom is a
//     machine quietly missing from a dashboard;
//   - a machine configured not to export comes back not exporting, even if
//     somebody turned it on by hand over the socket an hour ago.
//
// The second half is the part worth stating out loud, because it makes
// `conflux anchorctl export -endpoint ...` a temporary override rather than a
// setting. It lasts until the next restart or the next SIGHUP. `conflux status`
// reports which surface the daemon is actually obeying, so an operator who is
// surprised can see it rather than infer it. The durable way is this file.
//
// Leaving the field absent instead would have been quieter and wrong: anchord would
// then apply nothing, and a daemon restarting after an RPC-set export would keep
// exporting to an endpoint no file on this machine records.
func writeDaemonConfig(d paths.Dirs, cfg *config.Config) error {
	export := cfg.Export
	if export == nil {
		export = &config.Export{Enabled: false}
	}

	b, err := json.MarshalIndent(daemonConfig{Export: export}, "", "  ")
	if err != nil {
		return fmt.Errorf("render the daemon config: %w", err)
	}

	// 0600, because export.headers authenticate this machine to a collector and
	// this file is where they land. The directory is 0700 already.
	return config.WriteFileAtomic(d.DaemonConfigFile(), append(b, '\n'), 0o600)
}
