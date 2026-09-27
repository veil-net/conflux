package taint

import (
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
