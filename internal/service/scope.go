package service

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/veil-net/conflux/internal/paths"
)

// scope is what distinguishes a service registered against a CONFLUX_DIR from the
// machine's own, and is "" for the ordinary install that has no CONFLUX_DIR at all.
//
// Without it there is one service name per machine, and a dev run rooted in /tmp
// registers itself over the top of a real node: same unit path, same label, same SCM
// entry. The data was isolated and the registration was not, which made "CONFLUX_DIR
// cannot disturb a real machine" false in the one way that costs somebody a node.
//
// A hash of the root rather than the root itself, because a unit name cannot hold a
// path -- slashes especially -- and a truncated one would collide between two dirs
// with the same last segment. Four bytes: this distinguishes a handful of dev roots
// on one machine, not a namespace.
func scope() string {
	root := paths.Root()
	if root == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(root))

	return "-" + hex.EncodeToString(sum[:4])
}
