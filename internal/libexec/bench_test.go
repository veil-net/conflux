package libexec

import (
	"testing"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/paths/pathstest"
)

// BenchmarkExtract is what a start pays for the anchor pair: cold, extracting it into a root
// that has none, fsyncs and the smoke run included; and warm, finding the extraction whole,
// which is every start after the first. Compare on one host and one filesystem: a cold
// extraction is mostly fsync, which tmpfs makes free.
func BenchmarkExtract(b *testing.B) {
	anchortest.Require(b)

	b.Run("cold", func(b *testing.B) {
		for b.Loop() {
			b.StopTimer()

			d := pathstest.Root(b)

			b.StartTimer()

			if _, err := Ensure(d); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("warm", func(b *testing.B) {
		d := pathstest.Root(b)

		if _, err := Ensure(d); err != nil {
			b.Fatal(err)
		}

		for b.Loop() {
			if _, err := Ensure(d); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkIntact is what a supervisor's start pays for a pair held to this build's bytes:
// cold, extracting it into a root that has none; and warm, finding it as it was when last
// held to them, which is every start after the first. Compare on one host and one
// filesystem, as BenchmarkExtract.
func BenchmarkIntact(b *testing.B) {
	anchortest.Require(b)

	b.Run("cold", func(b *testing.B) {
		for b.Loop() {
			b.StopTimer()

			d := pathstest.Root(b)

			b.StartTimer()

			if _, err := Intact(d); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("warm", func(b *testing.B) {
		d := pathstest.Root(b)

		if _, err := Intact(d); err != nil {
			b.Fatal(err)
		}

		for b.Loop() {
			if _, err := Intact(d); err != nil {
				b.Fatal(err)
			}
		}
	})
}
