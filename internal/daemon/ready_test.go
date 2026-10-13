package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The marker exists so that `conflux up` on a Mac or on Windows learns the anchor is up
// when it happens, instead of forking anchorctl once a second until one answer is yes.
func TestMarkReadyRoundTrips(t *testing.T) {
	d := dirs(t)

	if IsReady(d) {
		t.Fatal("a directory with no marker reports ready")
	}

	if err := MarkReady(d, "anchor6btpa3gn6w4stipba4hekzho7caw6srfyy5puvbz7mfanaiept5a"); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}

	if !IsReady(d) {
		t.Error("a marker was written and IsReady says no")
	}

	if b, _ := os.ReadFile(d.ReadyFile()); !strings.Contains(string(b), "anchor6btpa3gn6w4stipba4hekzho7caw6srfyy5puvbz7mfanaiept5a") {
		t.Errorf("the marker reads %q and does not name the anchor that was marked", b)
	}
}

// Clearing is what restartWith does before it restarts anything, so it has to work on a
// machine that has never written one -- and every shutdown path calls it, including those
// that never got as far as an anchor.
func TestClearReadyIsIdempotent(t *testing.T) {
	d := dirs(t)

	if err := ClearReady(d); err != nil {
		t.Errorf("ClearReady with no marker = %v, want nil", err)
	}

	if err := MarkReady(d, "anchorabc"); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}

	if err := ClearReady(d); err != nil {
		t.Errorf("ClearReady: %v", err)
	}

	if IsReady(d) {
		t.Error("the marker was cleared and IsReady still says yes")
	}

	if err := ClearReady(d); err != nil {
		t.Errorf("ClearReady twice = %v, want nil", err)
	}
}

// Every reader falls back to asking anchorctl, so a marker that is truncated, empty or
// half-written must read as "no marker" rather than as a ready anchor with no name.
// MarkReady writes atomically and never leaves one like these; something else, in a
// directory root shares, might.
func TestUnusableMarkersReadAsNotReady(t *testing.T) {
	for name, content := range map[string]string{
		"empty":          "",
		"whitespace":     "   \n",
		"timestamp only": "2026-09-18T04:31:02Z\n",
		"no id":          "2026-09-18T04:31:02Z \n",
	} {
		d := dirs(t)

		if err := os.WriteFile(d.ReadyFile(), []byte(content), 0o600); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}

		if IsReady(d) {
			t.Errorf("%s: a marker holding %q reports ready", name, content)
		}
	}
}

// The marker lives in Run and not State, which is what stops it outliving the anchor it
// describes: most systems empty Run at boot, systemd's RuntimeDirectory= empties it on
// stop, and the supervisor clears the marker as it starts.
func TestReadyFileIsInTheRunDirectory(t *testing.T) {
	d := dirs(t)

	if filepath.Dir(d.ReadyFile()) != d.Run {
		t.Errorf("ReadyFile is %s, which is not under Run (%s) -- a marker that survives a "+
			"reboot is a marker that lies", d.ReadyFile(), d.Run)
	}
}
