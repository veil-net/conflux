package anchor

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// minSize is well under the smallest real binary (anchorctl-linux-arm64, ~13 MB)
// and far above anything that is not one.
const minSize = 5 << 20

// TestPairIsRealExecutables is the tripwire for the two ways this package breaks
// silently rather than loudly.
//
// The first is Git LFS: the Go module proxy serves pointer files, so a build from
// the proxy would embed 130 bytes of text and ship a "anchord" that is not one.
// The second is a Windows checkout with core.autocrlf=true and no .gitattributes,
// which rewrites CRLF inside a binary and corrupts it. Neither fails the build;
// both fail on a user's machine, at exec, with nothing useful to say.
func TestPairIsRealExecutables(t *testing.T) {
	if !Supported {
		t.Skipf("no anchor pair for %s/%s -- run `make anchor-bins`", runtime.GOOS, runtime.GOARCH)
	}

	for name, b := range map[string][]byte{"anchord": Anchord(), "anchorctl": Anchorctl()} {
		if len(b) < minSize {
			t.Errorf("%s is %d bytes: an LFS pointer, a truncated checkout, or the wrong file — not a binary",
				name, len(b))

			continue
		}

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
		return nil // an arch this test has no constant for; the size check stands
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
