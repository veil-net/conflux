package daemon

import (
	"encoding/json"
	"fmt"
	"os"

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
//
// TLS material conflux.json names by path is read here, by the supervisor, and written in
// whole: anchord reads the file as whoever it runs as, which may be an account a key in
// /etc/ssl/private is not readable to, and a daemon that cannot read its -config does not
// start. A path that cannot be read here is left a path, for anchord to name in its own
// refusal. Relative paths resolve against the directory anchord used to start in, which
// is this process's.
func writeDaemonConfig(d paths.Dirs, cfg *config.Config, p Privilege) error {
	b, err := json.MarshalIndent(daemonConfig{Export: inlined(cfg.Export)}, "", "  ")
	if err != nil {
		return fmt.Errorf("render the daemon config: %w", err)
	}

	// 0600, because export.headers authenticate this machine to a collector and this file
	// is where they land, and anchord's own, whoever that is.
	return writeDaemonFile(d.DaemonConfigFile(), append(b, '\n'), p)
}

// inlined is e with every TLS secret it names by path read in, where it can be.
func inlined(e *config.Export) *config.Export {
	if e == nil {
		return nil
	}

	out := *e

	for _, sec := range []**config.Secret{&out.CACert, &out.ClientCert, &out.ClientKey} {
		if *sec == nil || (*sec).Path == "" {
			continue
		}

		if b, err := os.ReadFile((*sec).Path); err == nil {
			*sec = &config.Secret{Inline: b}
		}
	}

	return &out
}
