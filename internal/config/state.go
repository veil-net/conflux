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
// Everything here is recoverable. Delete it and the next start re-learns the
// AnchorID from `anchorctl status` and the credential window from the manifest, at
// the cost of one extra call. That is the whole reason it is a separate file from
// the manifest, which is recoverable from nowhere at all.
type State struct {
	Version int `json:"version"`

	// AnchorID is this machine's permanent name in the realm, derived from the
	// identity seed and the realm root. It is what the renewal route needs, and
	// it is the half that does not change.
	AnchorID string `json:"anchorId,omitempty"`

	// IssuedAt and NotAfter bound the credential currently held. Both are mirrored
	// from the manifest so the renewal timer needs no other state, and both are
	// rewritten on every successful renewal.
	IssuedAt time.Time `json:"issuedAt,omitzero"`
	NotAfter time.Time `json:"notAfter,omitzero"`

	// RenewalURL is read out of the manifest rather than composed from a constant,
	// so the endpoint that issued a credential is the endpoint asked to renew it.
	RenewalURL string `json:"renewalUrl,omitempty"`

	EnrolledAt time.Time `json:"enrolledAt,omitzero"`

	// BinSetID names the extracted anchor pair that is live. When it disagrees
	// with the pair this conflux carries, the binary was upgraded under a running
	// service and `conflux status` says so.
	BinSetID string `json:"binSetId,omitempty"`

	// LastRenewalError and LastRenewalTry record a renewal that is failing, so
	// status can say "failing for 3h: no route to host" instead of reporting
	// health it cannot vouch for.
	LastRenewalError string    `json:"lastRenewalError,omitempty"`
	LastRenewalTry   time.Time `json:"lastRenewalTry,omitzero"`
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

// DeleteState removes it.
func DeleteState(d paths.Dirs) error {
	if err := os.Remove(d.StateFile()); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
