package libexec

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/paths/pathstest"
)

// TestIntactPutsAChangedBinaryRight: the supervisor runs the extracted anchord as root, so a
// binary changed on disk after it was extracted -- its size kept, which the hot path alone
// would take as whole -- is found by its digest, and the set is extracted again.
func TestIntactPutsAChangedBinaryRight(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Root(t)

	tools, err := Intact(d)
	if err != nil {
		t.Fatalf("Intact: %v", err)
	}

	want, err := os.ReadFile(tools.Anchord)
	if err != nil {
		t.Fatal(err)
	}

	// The same length, the first bytes changed: Ensure's stat of the size cannot tell.
	changed := append([]byte(nil), want...)
	copy(changed, "not anchord")

	if err := os.WriteFile(tools.Anchord, changed, 0o700); err != nil {
		t.Fatal(err)
	}

	again, err := Intact(d)
	if err != nil {
		t.Fatalf("Intact after the change: %v", err)
	}

	got, err := os.ReadFile(again.Anchord)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != string(want) {
		t.Error("the changed anchord was kept")
	}
}

// TestIntactTrustsWhatItVerified: a set held to its digests once is taken as it is at the
// next start while its files are as they were, so a start reads no binary; a set with no
// record of holding this build's bytes -- one whose record went, or that a conflux writing
// none extracted -- is verified, not taken on its stat; and one a stat of which the
// supervisor changed since, and nothing it holds, is recorded again (Reverified).
func TestIntactTrustsWhatItVerified(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Root(t)

	tools, err := Ensure(d)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(filepath.Join(tools.Dir, verifiedMarker)); err != nil {
		t.Fatal(err)
	}

	if tools.verified() {
		t.Fatal("a set with no record reads as verified")
	}

	if _, err := Intact(d); err != nil {
		t.Fatal(err)
	}

	if !tools.verified() {
		t.Error("a set Intact verified does not read as verified")
	}

	// What the supervisor's grant to its account's group does to anchord's owner and mode, a
	// time stands in for here, on every platform: a stat that says otherwise, the bytes kept.
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(tools.Anchord, later, later); err != nil {
		t.Fatal(err)
	}

	if tools.verified() {
		t.Fatal("a set whose files changed since its record reads as verified")
	}

	tools.Reverified()

	if !tools.verified() {
		t.Error("a set recorded again does not read as verified")
	}
}

// TestAnExtractionIsTakenOnAStat: a set this process extracts holds this build's bytes by
// construction, so it is recorded as written, and the supervisor's Intact takes it on a stat
// rather than reading back the fifty-odd megabytes it has just written.
func TestAnExtractionIsTakenOnAStat(t *testing.T) {
	anchortest.Require(t)

	tools, err := Ensure(pathstest.Root(t))
	if err != nil {
		t.Fatal(err)
	}

	if !tools.verified() {
		t.Error("a set this process extracted is not recorded as holding this build's bytes")
	}
}
