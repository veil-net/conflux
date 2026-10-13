package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/veil-net/conflux/internal/paths"
)

// StateVersion tracks the derived file's shape.
const StateVersion = 1

// State is what conflux worked out, as against what the operator asked for.
//
// Most of it is re-learned by the next start: the credential window from the manifest,
// and the AnchorID from what `anchorctl start` reports. Not all of it. A renewal names
// the anchor by its AnchorID and anchor will not start on an expired credential, so a
// machine whose credential has expired and whose state.json is gone has no way to learn
// its AnchorID again, and is refused for good until it is given a new identity. The
// manifest, the one thing recoverable from nowhere at all, is a file of its own.
type State struct {
	Version int `json:"version"`

	// AnchorID is this machine's permanent name in the realm, derived from the
	// identity seed and the realm root. It is what the renewal route needs, and
	// it is the half that does not change.
	AnchorID string `json:"anchorId,omitempty"`

	// IssuedAt and NotAfter bound the credential the running anchor holds. Both are
	// mirrored from the manifest so the renewal timer needs no other state, and both
	// are rewritten at every start and every renewal the anchor installs.
	IssuedAt time.Time `json:"issuedAt,omitzero"`
	NotAfter time.Time `json:"notAfter,omitzero"`

	// ClockSkew is how far this machine's clock was from the API's at the last call
	// that measured it, which every enrolment and renewal does. Here rather than in
	// memory because the supervisor that measures it and the `conflux status` that
	// reports it are different processes.
	ClockSkew time.Duration `json:"clockSkew,omitempty"`

	// BinSetID names the extracted anchor pair that is live. When it disagrees
	// with the pair this conflux carries, the binary was upgraded under a running
	// service and `conflux status` says so.
	BinSetID string `json:"binSetId,omitempty"`

	// LastRenewalError and LastRenewalTry record a renewal that is failing, so
	// status can say "failing for 3h: no route to host" instead of reporting
	// health it cannot vouch for.
	LastRenewalError string    `json:"lastRenewalError,omitempty"`
	LastRenewalTry   time.Time `json:"lastRenewalTry,omitzero"`

	// LinkReopens and LastLinkReopen record an uplink found dead and rebuilt.
	//
	// Persisted rather than counted in memory because the supervisor that does the
	// reopening and the `conflux status` that reports it are different processes. A
	// machine quietly restarting its anchor every few minutes is a failing cable,
	// and it should be legible as one rather than as an anchor that has been up all
	// along -- the uptime resets, so nothing else would say.
	LinkReopens    int       `json:"linkReopens,omitempty"`
	LastLinkReopen time.Time `json:"lastLinkReopen,omitzero"`
}

// LoadState reads it. A missing file is an empty State and not an error: every
// field is derived, so absent and unknown are the same thing.
func LoadState(d paths.Dirs) (*State, error) {
	b, err := os.ReadFile(d.StateFile())
	if err != nil {
		if os.IsNotExist(err) {
			return &State{Version: StateVersion}, nil
		}

		return nil, err
	}

	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		// A corrupt derived file is not worth failing a start over -- everything
		// in it can be worked out again.
		return &State{Version: StateVersion}, nil //nolint:nilerr // deliberate
	}

	return &s, nil
}

// SaveState writes it, atomically and 0600. It holds no key material, but it does
// hold the AnchorID, and there is no reason to be looser than the file beside it.
func SaveState(d paths.Dirs, s *State) error {
	s.Version = StateVersion

	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}

	return WriteFileAtomic(d.StateFile(), append(b, '\n'), 0o600)
}

// NewIdentity forgets everything this state held about the identity before: what a
// machine given a new manifest -- enrolled, or imported -- must not carry over. The
// AnchorID above all, which a renewal would otherwise send for the old anchor and splice
// the chain it got back into the new one's manifest.
func (s *State) NewIdentity() {
	s.AnchorID, s.IssuedAt, s.NotAfter, s.ClockSkew = "", time.Time{}, time.Time{}, 0
	s.LastRenewalError, s.LastRenewalTry = "", time.Time{}
	s.LinkReopens, s.LastLinkReopen = 0, time.Time{}
}
