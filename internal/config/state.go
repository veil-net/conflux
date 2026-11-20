package config

import (
	"encoding/json"
	"errors"
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
// and the AnchorID from what `anchorctl start` reports, or the observer's start. Not all of
// it. A renewal names the identity by its AnchorID and neither starts on an expired
// credential, so a machine whose credential has expired and whose state.json is gone has no
// way to learn its AnchorID again, and is refused for good until it is given a new identity.
// The manifest, the one thing recoverable from nowhere at all, is a file of its own.
type State struct {
	Version int `json:"version"`

	// AnchorID is this machine's permanent name in the realm, derived from the
	// identity seed and the realm root: what its anchor reports starting as, and its
	// observer running as. It is what the renewal route needs, and it is the half that
	// does not change.
	AnchorID string `json:"anchorId,omitempty"`

	// IssuedAt and NotAfter bound the credential what runs holds, the anchor or the
	// observer. Both are mirrored from the manifest so the renewal timer needs no other
	// state, and both are rewritten at every start and every renewal installed.
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

	// AnchorRefused and AnchorRefusedAt record the anchor the supervisor gave up on, refused for
	// good: why, and when. Written where it stops trying it -- the watcher giving up its
	// rebuilds, or the service ending on it with nothing else running -- and cleared when an
	// anchor comes up, wherever the supervisor is to try it again (as the service starts, once
	// anchord has ended and is to be started again, and at a whole bring-up), at `conflux down`,
	// and for a new identity.
	// Persisted for the reason the link's reopens are: the supervisor that gives up and the
	// `conflux status` that reports it are different processes, and without it status could
	// say only that no anchor runs.
	AnchorRefused   string    `json:"anchorRefused,omitempty"`
	AnchorRefusedAt time.Time `json:"anchorRefusedAt,omitzero"`
}

// ErrStateCorrupt is what LoadState's refusal of a state.json it cannot parse wraps. No
// retry changes the file, so a start refuses it for good.
var ErrStateCorrupt = errors.New("corrupt")

// LoadState reads it. A missing file is an empty State and not an error: nothing has
// been worked out yet, or what was is gone, and a start learns what it can again.
//
// A file that does not parse is refused, naming it, rather than read as an empty State:
// that would lose the AnchorID, which a machine whose credential has expired can learn
// from nowhere else, the next time the State was saved. The operator repairs or deletes it.
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
		return nil, fmt.Errorf("%s is %w (%v); conflux will not start until it is repaired or deleted, "+
			"and deleting it loses the AnchorID, which the next start learns again unless the credential has expired",
			d.StateFile(), ErrStateCorrupt, err)
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

// AnchorGivenUp records that the supervisor gave up on the anchor, refused for good with
// refusal, now; nil clears the record.
func (s *State) AnchorGivenUp(refusal error) {
	if refusal == nil {
		s.AnchorRefused, s.AnchorRefusedAt = "", time.Time{}

		return
	}

	s.AnchorRefused, s.AnchorRefusedAt = refusal.Error(), time.Now().UTC()
}

// NewIdentity forgets everything this state held about the identity before: what a
// machine given a new manifest -- enrolled, or imported -- must not carry over. The
// AnchorID above all, which a renewal would otherwise send for the old anchor and splice
// the chain it got back into the new one's manifest.
func (s *State) NewIdentity() {
	s.AnchorID, s.IssuedAt, s.NotAfter, s.ClockSkew = "", time.Time{}, time.Time{}, 0
	s.LastRenewalError, s.LastRenewalTry = "", time.Time{}
	s.LinkReopens, s.LastLinkReopen = 0, time.Time{}
	s.AnchorGivenUp(nil)
}
