package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestReadUntrustedRefusesALink: on Windows as on Unix, a file the account could have made
// anything of is read only when it is one regular file of its own, under the size asked --
// never through a symbolic link or a junction to something else, and never as a second
// name of a file the account could name but not read.
func TestReadUntrustedRefusesALink(t *testing.T) {
	dir := t.TempDir()

	ok := filepath.Join(dir, "subnets.json")
	if err := os.WriteFile(ok, []byte(`{"subnets": []}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if b, err := ReadUntrusted(ok, 1<<20); err != nil || string(b) != `{"subnets": []}` {
		t.Errorf("ReadUntrusted = %q, %v", b, err)
	}

	if _, err := ReadUntrusted(ok, 4); err == nil {
		t.Error("a file past the size asked was read")
	}

	elsewhere := t.TempDir()

	secret := filepath.Join(elsewhere, "shadow")
	if err := os.WriteFile(secret, []byte("SYSTEM's"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A symbolic link needs SeCreateSymbolicLinkPrivilege, which CI's runners hold.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatalf("make a symbolic link: %v", err)
	}

	hard := filepath.Join(dir, "hard")
	if err := os.Link(secret, hard); err != nil {
		t.Fatal(err)
	}

	// A junction needs no privilege at all, which is what makes it the account's way in.
	junction := filepath.Join(dir, "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, elsewhere).CombinedOutput(); err != nil {
		t.Fatalf("make a junction: %v\n%s", err, out)
	}

	for _, path := range []string{link, hard, junction} {
		if b, err := ReadUntrusted(path, 1<<20); err == nil {
			t.Errorf("%s was read: %q", path, b)
		}
	}
}
