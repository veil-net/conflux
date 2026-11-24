package anchor_test

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"runtime"
	"strconv"
	"testing"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/anchortest"
)

// TestPairIsRealExecutables is the tripwire for the two ways this package breaks
// silently rather than loudly.
//
// The first is Git LFS: the Go module proxy serves pointer files, so a build from
// the proxy would embed 130 bytes of text and ship a "anchord" that is not one. The
// second is a Windows checkout with core.autocrlf=true and no .gitattributes, which
// rewrites CRLF inside a binary and corrupts it. Neither fails the build; both fail on a
// user's machine, at exec, with nothing useful to say. A pointer, or anything else under
// anchor.Supported's floor, is a build with no pair, which this skips as every test
// needing the pair does and CI fails; a corrupted binary keeps its size, and its header
// is what gives it away.
func TestPairIsRealExecutables(t *testing.T) {
	anchortest.Require(t)

	for name, b := range map[string][]byte{"anchord": anchor.Anchord(), "anchorctl": anchor.Anchorctl()} {
		if err := checkFormat(b); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// checkFormat parses the header for this GOOS and asserts the machine field agrees
// with GOARCH, which is what catches a file misnamed in bin/ — an arm64 binary
// dropped in under the amd64 name builds and links perfectly and cannot run.
func checkFormat(b []byte) error {
	r := bytes.NewReader(b)

	switch runtime.GOOS {
	case "windows":
		f, err := pe.NewFile(r)
		if err != nil {
			return err
		}
		defer f.Close()

		return wantMachine(uint64(f.Machine), map[string]uint64{
			"amd64": pe.IMAGE_FILE_MACHINE_AMD64,
			"arm64": pe.IMAGE_FILE_MACHINE_ARM64,
		})

	case "darwin":
		f, err := macho.NewFile(r)
		if err != nil {
			return err
		}
		defer f.Close()

		return wantMachine(uint64(f.Cpu), map[string]uint64{
			"amd64": uint64(macho.CpuAmd64),
			"arm64": uint64(macho.CpuArm64),
		})

	default: // linux, freebsd, openbsd
		f, err := elf.NewFile(r)
		if err != nil {
			return err
		}
		defer f.Close()

		return wantMachine(uint64(f.Machine), map[string]uint64{
			"amd64": uint64(elf.EM_X86_64),
			"arm64": uint64(elf.EM_AARCH64),
		})
	}
}

func wantMachine(got uint64, by map[string]uint64) error {
	want, ok := by[runtime.GOARCH]
	if !ok {
		return nil // an arch this test has no constant for; the header parsed, and that stands
	}

	if got != want {
		return &mismatch{got: got, want: want}
	}

	return nil
}

type mismatch struct{ got, want uint64 }

func (m *mismatch) Error() string {
	return "machine field is 0x" + strconv.FormatUint(m.got, 16) +
		", expected 0x" + strconv.FormatUint(m.want, 16) +
		" for " + runtime.GOARCH + ": a file in bin/ is named for the wrong architecture"
}
