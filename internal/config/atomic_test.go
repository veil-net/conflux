package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFileAtomicSetsModeBeforeContent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not meaningful on windows; the DACL is")
	}

	path := filepath.Join(t.TempDir(), "secret")

	if err := WriteFileAtomic(path, []byte("seed"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600", got)
	}
}

// TestWriteFileAtomicNarrowsAnExistingFile is the case a plain os.WriteFile gets
// wrong: it keeps the mode of a file that already exists, so a manifest that was
// once 0644 stays world-readable forever.
func TestWriteFileAtomicNarrowsAnExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not meaningful on windows; the DACL is")
	}

	path := filepath.Join(t.TempDir(), "secret")

	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("seed the file: %v", err)
	}

	if err := WriteFileAtomic(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o after rewriting a 0644 file, want 600", got)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(b) != "new" {
		t.Errorf("content = %q, want %q", b, "new")
	}
}

// TestWriteFileAtomicLeavesNoTempFiles guards against the rename path leaking a
// .tmp-* sibling on every write, which over a year of renewals would be thousands.
func TestWriteFileAtomicLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conflux.json")

	for range 3 {
		if err := WriteFileAtomic(path, []byte("{}"), 0o600); err != nil {
			t.Fatalf("WriteFileAtomic: %v", err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}

		t.Errorf("directory holds %v, want only conflux.json", names)
	}
}

// TestWriteFileAtomicPreservesOnFailure asserts the promise the whole function
// exists for: a failed write leaves the previous content, never a truncated file.
func TestWriteFileAtomicPreservesOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conflux.json")

	if err := WriteFileAtomic(path, []byte("good"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}

	// A directory that cannot be written to is the reachable way to fail between
	// "the old file exists" and "the new one is in place".
	if runtime.GOOS != "windows" && unwritable(t, dir) {
		if err := WriteFileAtomic(path, []byte("bad"), 0o600); err == nil {
			t.Fatal("WriteFileAtomic succeeded into a read-only directory")
		}
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(b) != "good" {
		t.Errorf("content = %q after a failed write, want the previous %q", b, "good")
	}
}

// unwritable makes dir read-only and reports whether that actually took.
//
// The premise, checked rather than assumed. chmod succeeds for root and root writes
// anyway, so as root this half of the test was asserting nothing -- and it did not
// skip, it failed, which is a worse way to assert nothing. That cost nothing while CI
// was hosted VMs whose runner user is unprivileged; it is a red build the moment the
// suite runs somewhere the runner process is root, which is what a self-hosted machine
// may well be.
//
// The rest of the test is unaffected and still runs: whatever happened to the write,
// the previous content must still be there afterwards.
func unwritable(t *testing.T, dir string) bool {
	t.Helper()

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make the directory read-only here: %v", err)
	}

	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	probe := filepath.Join(dir, ".writable-probe")
	if err := os.WriteFile(probe, nil, 0o600); err == nil {
		_ = os.Remove(probe)
		t.Log("this directory is still writable after chmod 0500 -- running as root, " +
			"so there is no unwritable case here to exercise")

		return false
	}

	return true
}
