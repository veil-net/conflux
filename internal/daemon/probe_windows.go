package daemon

import "github.com/veil-net/conflux/internal/config"

// probeHost has nothing to ask on Windows: no port is reserved, and an uplink has no
// device conflux opens.
func probeHost(*config.Config) hostFacts { return hostFacts{} }
