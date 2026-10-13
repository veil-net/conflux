package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestExportMaterialIsNotPrinted: an export block's headers are credentials and a client
// key may be inline in it, so neither reaches anything printed.
func TestExportMaterialIsNotPrinted(t *testing.T) {
	const header, key = "Bearer sk-live-123", "-----BEGIN PRIVATE KEY-----"

	e := Export{
		Enabled: true, Endpoint: "collector:4317",
		Headers:   map[string]string{"authorization": header},
		ClientKey: &Secret{Inline: []byte(key)},
	}

	for verb, s := range map[string]string{
		"%v": fmt.Sprintf("%v", e), "%+v": fmt.Sprintf("%+v", e), "%#v": fmt.Sprintf("%#v", e),
		"secret %v": fmt.Sprintf("%v", *e.ClientKey), "secret %#v": fmt.Sprintf("%#v", *e.ClientKey),
	} {
		if strings.Contains(s, header) || strings.Contains(s, key) {
			t.Errorf("%s printed credential material: %s", verb, s)
		}
	}
}

// TestSaveManifestLeavesTheCallersEnvelope: the newline the file ends with is the
// file's, never written into spare capacity of the envelope the caller holds.
func TestSaveManifestLeavesTheCallersEnvelope(t *testing.T) {
	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := dirsForTest(t)

	backing := make([]byte, 0, 64)
	backing = append(backing, "bWFuaWZlc3Q=  XYZ"...)
	env := Envelope(backing[:14]) // "bWFuaWZlc3Q=  ", spare capacity behind it

	if err := SaveManifest(d, env); err != nil {
		t.Fatal(err)
	}

	if got := string(backing[12:17]); got != "  XYZ" {
		t.Errorf("SaveManifest wrote into the caller's slice: %q", got)
	}
}

// TestANewIdentityForgetsTheOldOne: nothing a state says about one identity survives
// the arrival of another -- the AnchorID least of all.
func TestANewIdentityForgetsTheOldOne(t *testing.T) {
	st := State{
		AnchorID: "anchorold", IssuedAt: time.Now(), NotAfter: time.Now(), ClockSkew: time.Hour,
		LastRenewalError: "x", LastRenewalTry: time.Now(), LinkReopens: 3, LastLinkReopen: time.Now(),
		BinSetID: "keep",
	}

	st.NewIdentity()

	if st != (State{BinSetID: "keep"}) {
		t.Errorf("NewIdentity left %+v; only what is not about the identity stays", st)
	}
}

// TestTUNNamesThePlatformRefuses: refused here, for good, rather than found by anchor
// once a second when the TUN is made.
func TestTUNNamesThePlatformRefuses(t *testing.T) {
	for _, tc := range []struct {
		name, goos string
		ok         bool
	}{
		{"anchor0", "linux", true},
		{"a234567890abcde", "linux", true},
		{"a234567890abcdef", "linux", false},
		{"an/chor", "linux", false},
		{"an chor", "linux", false},
		{"", "linux", false},
		{"..", "linux", false},
		{"anchor0", "darwin", true},
		{"utun", "darwin", true},
		{"utun7", "darwin", true},
		{"utunx", "darwin", false},
		{"utun-1", "darwin", false},
		{"a234567890abcdef", "freebsd", true},
		{"anything at all", "windows", true},
	} {
		if err := ValidateTUNName(tc.name, tc.goos); (err == nil) != tc.ok {
			t.Errorf("ValidateTUNName(%q, %s) = %v, want ok %v", tc.name, tc.goos, err, tc.ok)
		}
	}
}
