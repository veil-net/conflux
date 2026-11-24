package config

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/paths"
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
	t.Cleanup(paths.UseRoot(t.TempDir()))

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

// TestHasManifestIsWhatLoadManifestReads: a machine has an identity exactly when there is a
// manifest LoadManifest reads -- none, or one empty or of nothing but white space, is none.
func TestHasManifestIsWhatLoadManifestReads(t *testing.T) {
	d := dirsForTest(t)

	for content, has := range map[string]bool{"": false, " \n\t\n": false, "bWFuaWZlc3Q=\n": true} {
		if err := os.WriteFile(d.ManifestFile(), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		_, err := LoadManifest(d)

		if HasManifest(d) != has || (err == nil) != has {
			t.Errorf("a manifest of %q: HasManifest %v, LoadManifest %v; want has %v from both", content, HasManifest(d), err, has)
		}
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
