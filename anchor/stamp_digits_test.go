package anchor

import (
	"strings"
	"testing"
)

// A stamp is a SHA-256 in lower-case hex, so every digit 0-9 and a-f is accepted and
// the characters on either side of those ranges are not.
func TestStampsAcceptEveryHexDigitAndNothingAdjacent(t *testing.T) {
	digits := strings.Repeat("0123456789abcdef", 4)
	other := strings.Repeat("fedcba9876543210", 4)

	if d, c := digests(digits, other); d != digits || c != other {
		t.Errorf("digests(%q, %q) = %q %q, want the stamps: every hex digit is valid", digits, other, d, c)
	}

	wantD, wantC := computeDigests()

	for _, bad := range []string{"/", ":", "`", "g", "@", "G"} {
		for _, at := range []int{0, 31, 63} {
			stamp := digits[:at] + bad + digits[at+1:]
			if d, c := digests(stamp, other); d != wantD || c != wantC {
				t.Errorf("digests(%q, ...) used a stamp holding %q at %d; it is not hex and must be computed instead", stamp, bad, at)
			}
		}
	}
}
