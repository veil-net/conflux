// Package taint mints the label that decides who can reach a machine.
//
// A taint is anchor's compartment label, and the rule is containment rather than
// overlap: two anchors in a realm exchange data only if one carries every taint the
// other does. Two machines with the same single taint have equal sets, containment
// holds both ways, and they talk. Two machines with different ones are not merely
// unreachable -- they have no address for each other.
//
// An anchor with no taints is not exempt from that rule. It carries the realm's
// default compartment, which every other unconfigured anchor also carries, so
// "no taint" means "in the commons with every stranger in the realm". That is the
// right default for the messaging realm this credential comes from and the wrong
// one for a machine somebody is joining to their own network, which is why conflux
// mints one rather than leaving the field empty.
package taint

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/veil-net/conflux/internal/config"
)

// alphabet has no i, l, o, 0 or 1, because a taint gets read off one screen and
// typed into another, and often dictated in between.
const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"

const (
	// length is 16 symbols from a 31-symbol alphabet: a little over 79 bits, which
	// is far past guessing. Taint names are not secret from the realm -- the tag is
	// derived from a public root id, so any member can compute the tag for a name
	// it can guess -- so unguessability is the whole of the protection a generated
	// one provides.
	length = 16

	// group inserts a hyphen every four symbols. Purely for reading aloud.
	group = 4
)

// New mints a label for a network that does not exist yet.
func New() string {
	b := make([]byte, length)

	// rand.Read from crypto/rand cannot fail; it panics internally if the system
	// source is broken, which is the correct outcome for this.
	_, _ = rand.Read(b)

	var sb strings.Builder

	sb.Grow(length + length/group)

	for i, v := range b {
		if i > 0 && i%group == 0 {
			sb.WriteByte('-')
		}

		sb.WriteByte(alphabet[int(v)%len(alphabet)])
	}

	return sb.String()
}

// Validate applies anchor's rule to a taint the operator supplied, so that a
// mistyped one is refused here rather than becoming a compartment of one that
// nothing can reach -- a failure that presents as "the network does not work",
// days later, with nothing pointing at the typo.
func Validate(v string) error { return config.ValidateTaint(v) }

// ValidateSet checks a whole list, including anchor's ceiling on how many.
func ValidateSet(vs []string) error {
	if len(vs) == 0 {
		return fmt.Errorf("no taints")
	}

	if len(vs) > config.MaxTaints {
		return fmt.Errorf("%d taints, and anchor allows %d", len(vs), config.MaxTaints)
	}

	seen := make(map[string]bool, len(vs))

	for _, v := range vs {
		if err := Validate(v); err != nil {
			return err
		}

		if seen[v] {
			return fmt.Errorf("taint %q is listed twice", v)
		}

		seen[v] = true
	}

	return nil
}
