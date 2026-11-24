package libexec

import (
	"testing"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/paths"
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

			b.Setenv("CONFLUX_DIR", b.TempDir())

			d := paths.Default()
			if err := d.EnsureAll(); err != nil {
				b.Fatal(err)
			}

			b.StartTimer()

			if _, err := Ensure(d); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("warm", func(b *testing.B) {
		b.Setenv("CONFLUX_DIR", b.TempDir())

		d := paths.Default()
		if err := d.EnsureAll(); err != nil {
			b.Fatal(err)
		}

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
