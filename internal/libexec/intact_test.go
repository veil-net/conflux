package libexec

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/veil-net/conflux/internal/anchortest"
)

// TestIntactPutsAChangedBinaryRight: the supervisor runs the extracted anchord as root, so a
// binary changed on disk after it was extracted -- its size kept, which the hot path alone
// would take as whole -- is found by its digest, and the set is extracted again.
func TestIntactPutsAChangedBinaryRight(t *testing.T) {
	anchortest.Require(t)

	d := dirs(t)

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
// next start while its files are as they were, so a start reads no binary; and a set it never
// verified is verified, not taken on its stat.
func TestIntactTrustsWhatItVerified(t *testing.T) {
	anchortest.Require(t)

	d := dirs(t)

	tools, err := Ensure(d)
	if err != nil {
		t.Fatal(err)
	}

	if tools.verified() {
		t.Fatal("a set Ensure extracted reads as verified before anything verified it")
	}

	if _, err := Intact(d); err != nil {
		t.Fatal(err)
	}

	if !tools.verified() {
		t.Error("a set Intact verified does not read as verified")
	}

	if _, err := os.Stat(filepath.Join(tools.Dir, verifiedMarker)); err != nil {
		t.Errorf("no record of the verification: %v", err)
	}
}
