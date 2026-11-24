package anchor

import (
	"strings"
	"testing"
)

// TestSetIDIsTheStampedFormula guards the extraction key. It has to be a pure function of
// the pair, or every invocation would extract to a new directory and the disk would fill,
// and a stamped build has to arrive at the same answer as one that read the bytes, or
// `make build` and `go build` of one tree would not share their extracted set. No skip:
// the placeholders have digests too.
func TestSetIDIsTheStampedFormula(t *testing.T) {
	d, c := computeDigests()

	if gd, gc := Digests(); gd != d || gc != c {
		t.Errorf("Digests() = %s %s in an unstamped build, want the pair's own %s %s", gd, gc, d, c)
	}

	id := SetID()
	if len(id) != 16 {
		t.Fatalf("SetID() = %q, want 16 hex characters", id)
	}

	if want := setID(d, c); id != want {
		t.Errorf("SetID() = %q, want %q from the two digests", id, want)
	}

	if again := SetID(); again != id {
		t.Errorf("SetID() = %q then %q; it is not stable", id, again)
	}
}

// TestWellFormedStampsAreUsedAsGiven: a stamp is taken as the digest only when both are
// sixty-four lowercase hex digits; anything else is computed rather than trusted.
func TestWellFormedStampsAreUsedAsGiven(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)

	if d, c := digests(a, b); d != a || c != b {
		t.Errorf("digests(well formed) = %s %s, want the stamps", d, c)
	}

	wantD, wantC := computeDigests()

	for _, stamps := range [][2]string{{"", ""}, {a, ""}, {"zz", b}, {strings.ToUpper(a), b}, {a[:63], b}} {
		if d, c := digests(stamps[0], stamps[1]); d != wantD || c != wantC {
			t.Errorf("digests(%q, %q) used the stamps; a malformed stamp must be computed instead", stamps[0], stamps[1])
		}
	}
}
