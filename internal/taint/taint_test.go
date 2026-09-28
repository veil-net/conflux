package taint

import (
	"math"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/config"
)

func TestNewIsValidAndUnambiguous(t *testing.T) {
	seen := make(map[string]bool, 512)

	for range 512 {
		v := New()

		if err := config.ValidateTaint(v); err != nil {
			t.Fatalf("New() produced %q, which anchor would refuse: %v", v, err)
		}

		if strings.ContainsAny(v, "ilo01") {
			t.Errorf("New() = %q, which contains a glyph that is misread when dictated", v)
		}

		if seen[v] {
			t.Fatalf("New() returned %q twice in 512 draws", v)
		}

		seen[v] = true
	}
}

func TestNewShape(t *testing.T) {
	v := New()

	if got, want := len(v), length+length/group-1; got != want {
		t.Errorf("len(New()) = %d, want %d (%q)", got, want, v)
	}

	if strings.Count(v, "-") != length/group-1 {
		t.Errorf("New() = %q, want it grouped for reading", v)
	}
}

// TestNewIsUniform: every symbol of the alphabet is drawn about equally often. A byte
// taken modulo 31 favours the first eight by an eighth, which a count this size sees.
func TestNewIsUniform(t *testing.T) {
	counts := map[rune]int{}

	const draws = 16384

	for range draws {
		for _, r := range strings.ReplaceAll(New(), "-", "") {
			counts[r]++
		}
	}

	// Each symbol's expected count, and five standard deviations either side of it.
	expected := float64(draws*length) / float64(len(alphabet))
	spread := 5 * math.Sqrt(expected)

	for _, r := range alphabet {
		if got := float64(counts[r]); math.Abs(got-expected) > spread {
			t.Errorf("%q was drawn %v times, expected %.0f ± %.0f", r, got, expected, spread)
		}
	}
}
