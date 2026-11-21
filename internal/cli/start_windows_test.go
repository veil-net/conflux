package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/privtest"
)

// TestStartGivesTheAdministratorsWhatTheAdministratorOwns: update hands a running service to the
// conflux it put in place through that conflux's start, so start secures the root as the service
// does at every start before it places or registers anything: a root an earlier conflux left on a
// Windows client, its logs\ and lock file the administrator's own, as that client's default-owner
// policy made them, holds neither by the time the service is registered: logs\ is the
// Administrators' -- what the SYSTEM service takes -- and the lock file, which nothing holds, is
// gone, for whatever next takes it to make again (tidy). Windows-only, so it runs in CI's platforms
// job alone.
func TestStartGivesTheAdministratorsWhatTheAdministratorOwns(t *testing.T) {
	anchortest.Require(t)

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := pathstest.Dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"},
		Taints: []string{"t"}}); err != nil {
		t.Fatal(err)
	}

	restore := privtest.CreatorOwns(t)

	if err := os.RemoveAll(d.Log); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(d.Log, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.LockFile(), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	restore()

	old := []string{d.Log, d.LockFile()}

	for _, p := range old {
		if privtest.ReadSecurity(t, p).Owner.Equals(privtest.Admins) {
			t.Fatalf("%s, made under a client's policy, is the Administrators' already", p)
		}
	}

	mgr := &fakeManager{d: d, restartErr: errStartsNothing}
	standInService(t, mgr)

	if _, errOut, code := capture(t, "start"); code != ExitError || !strings.Contains(errOut, errStartsNothing.Error()) {
		t.Fatalf("conflux start exited %d, saying:\n%s\nwant the stand-in's Restart refused", code, errOut)
	}

	if owner := privtest.ReadSecurity(t, d.Log).Owner; !owner.Equals(privtest.Admins) {
		t.Errorf("%s belongs to %v once start secured the root, not the Administrators", d.Log, owner)
	}

	if _, err := os.Lstat(d.LockFile()); !os.IsNotExist(err) {
		t.Errorf("%s, the administrator's and held by nothing, is still there once start secured the root (Lstat: %v)",
			d.LockFile(), err)
	}

	if len(mgr.installs) != 1 {
		t.Errorf("start registered the service %d times, want once", len(mgr.installs))
	}
}
