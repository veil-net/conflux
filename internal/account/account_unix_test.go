//go:build !windows

package account

import (
	"slices"
	"testing"
)

// TestGroupUsersFrom: who an existing group of the account's name lets in, read from what
// getent and dscl answer -- its listed members, and every account whose primary group it is --
// so that one that lets anybody in is never adopted as the account's own.
func TestGroupUsersFrom(t *testing.T) {
	for name, tc := range map[string]struct {
		goos, group, users, gid string
		want                    []string
	}{
		"getent, a group conflux left": {
			goos: "linux", group: "conflux:x:997:\n", gid: "997",
			users: "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n",
		},
		"getent, listed members": {
			goos: "linux", group: "conflux:x:997:alice,bob\n", gid: "997",
			users: "root:x:0:0:root:/root:/bin/bash\n",
			want:  []string{"alice", "bob"},
		},
		"getent, a primary group": {
			goos: "freebsd", group: "conflux:*:997:\n", gid: "997",
			users: "carol:*:1001:997:Carol:/home/carol:/bin/sh\nalice:*:1000:1000::/home/alice:/bin/sh\n",
			want:  []string{"carol"},
		},
		"getent, both, once each": {
			goos: "openbsd", group: "conflux:*:997:carol,alice\n", gid: "997",
			users: "carol:*:1001:997:Carol:/home/carol:/bin/ksh\n",
			want:  []string{"alice", "carol"},
		},
		"dscl, a group conflux left": {
			goos: "darwin", gid: "450",
			group: "AppleMetaNodeLocation: /Local/Default\nPrimaryGroupID: 450\nRecordName: _conflux\n",
			users: "_spotlight       89\nalice            20\n",
		},
		"dscl, members and a primary group": {
			goos: "darwin", gid: "450",
			group: "GroupMembership: alice bob\nPrimaryGroupID: 450\nRecordName: _conflux\n",
			users: "_spotlight       89\ncarol            450\n",
			want:  []string{"alice", "bob", "carol"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := groupUsersFrom(tc.goos, tc.group, tc.users, tc.gid); !slices.Equal(got, tc.want) {
				t.Errorf("groupUsersFrom = %q, want %q", got, tc.want)
			}
		})
	}
}
