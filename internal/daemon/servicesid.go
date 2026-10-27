package daemon

import (
	"crypto/sha1" //nolint:gosec // the algorithm Windows derives a service SID with, not a choice
	"encoding/binary"
	"strconv"
	"strings"
	"unicode/utf16"
)

// serviceSID is NT SERVICE\name: S-1-5-80 and the SHA-1 of the name, upper-cased and
// UTF-16LE, as five little-endian subauthorities. The SID of conflux's own service, which
// nothing but this installation's anchord is ever given on Windows: the one identity its
// files and its process are granted to, in place of LOCAL SERVICE, which many services
// share. Computed rather than looked up, so it is the same before the service exists and
// in a test on any platform.
func serviceSID(name string) string {
	units := utf16.Encode([]rune(strings.ToUpper(name)))
	b := make([]byte, 2*len(units))

	for i, u := range units {
		binary.LittleEndian.PutUint16(b[2*i:], u)
	}

	sum := sha1.Sum(b) //nolint:gosec // see the import

	parts := []string{"S-1-5-80"}
	for i := range 5 {
		parts = append(parts, strconv.FormatUint(uint64(binary.LittleEndian.Uint32(sum[4*i:])), 10))
	}

	return strings.Join(parts, "-")
}
