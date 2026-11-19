package service

import (
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestThePlistCarriesAnyPath: a CONFLUX_DIR may hold any character a path can, and the
// characters XML gives meaning to must arrive in ProgramArguments as themselves.
func TestThePlistCarriesAnyPath(t *testing.T) {
	argv := []string{"/Library/Application Support/conflux/conflux", "serve", "--dir", "/tmp/a&b <c>"}
	plist := launchdPlist("org.veilnet.conflux-1a2b3c4d", argv, "/tmp/a&b <c>/logs/conflux.log")

	dec := xml.NewDecoder(strings.NewReader(plist))

	var strs []string

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			t.Fatalf("the plist is not well-formed XML: %v\n%s", err, plist)
		}

		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "string" {
			var v string
			if err := dec.DecodeElement(&v, &se); err != nil {
				t.Fatal(err)
			}

			strs = append(strs, v)
		}
	}

	want := append([]string{"org.veilnet.conflux-1a2b3c4d"}, argv...)
	want = append(want, "Interactive", "/tmp/a&b <c>/logs/conflux.log", "/tmp/a&b <c>/logs/conflux.log")

	if strings.Join(strs, "|") != strings.Join(want, "|") {
		t.Errorf("the plist's strings are\n  %q\nwant\n  %q", strs, want)
	}
}

// fakeLaunchd is launchd as launchctl reports it, for one job: whether it is loaded,
// running and disabled. It records every change it is asked for, and bootstraps as launchd
// does, a load being a start.
type fakeLaunchd struct {
	label                     string
	loaded, running, disabled bool
	changes                   []string
}

func (f *fakeLaunchd) ctl() launchctl {
	return launchctl{
		run: func(args ...string) error {
			f.changes = append(f.changes, strings.Join(args, " "))

			switch args[0] {
			case "bootout":
				f.loaded, f.running = false, false
			case "bootstrap":
				f.loaded, f.running = true, !f.disabled
			case "enable":
				f.disabled = false
			}

			return nil
		},
		query: func(args ...string) (string, bool) {
			switch args[0] {
			case "print-disabled":
				state := "enabled"
				if f.disabled {
					state = "disabled"
				}

				return "disabled services = {\n\t\"" + f.label + "\" => " + state + "\n}", true
			case "print":
				if !f.loaded {
					return "", false
				}

				state := "not running"
				if f.running {
					state = "running"
				}

				return "system/" + f.label + " = {\n\tstate = " + state + "\n}", true
			}

			return "", false
		},
	}
}

// TestInstallLeavesTheJobAsItFoundIt: Install registers and starts nothing, and stops
// nothing either. A plist already as it would be written is left alone, as systemd's unit
// is; a changed one reaches a loaded job by unloading it, and a running one is loaded again
// so that it keeps running, now on the new definition. A disable is lifted either way, so
// the job loads at boot.
func TestInstallLeavesTheJobAsItFoundIt(t *testing.T) {
	const label = "org.veilnet.conflux"

	plist := []byte(launchdPlist(label, []string{"/x/conflux", "serve"}, "/var/log/conflux.log"))

	for _, c := range []struct {
		name                      string
		before                    []byte // the plist on disk; nil for none
		loaded, running, disabled bool
		want                      []string
		wantRunning               bool
	}{
		{name: "unchanged and running", before: plist, loaded: true, running: true, wantRunning: true},
		{name: "unchanged and stopped", before: plist, loaded: true},
		{
			name: "changed and running", before: []byte("an older plist"), loaded: true, running: true,
			want: []string{"bootout system/" + label, "bootstrap system PLIST"}, wantRunning: true,
		},
		{
			name: "changed and stopped", before: []byte("an older plist"), loaded: true,
			want: []string{"bootout system/" + label},
		},
		{name: "changed and not loaded", before: []byte("an older plist")},
		{name: "new", want: nil},
		{name: "unchanged and disabled", before: plist, disabled: true, want: []string{"enable system/" + label}},
		{name: "new and disabled", disabled: true, want: []string{"enable system/" + label}},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), label+".plist")
			if c.before != nil {
				if err := os.WriteFile(path, c.before, 0o644); err != nil {
					t.Fatal(err)
				}
			}

			f := &fakeLaunchd{label: label, loaded: c.loaded, running: c.running, disabled: c.disabled}

			if err := (launchdJob{label: label, plistPath: path, ctl: f.ctl()}).install(plist); err != nil {
				t.Fatalf("install: %v", err)
			}

			want := make([]string, len(c.want))
			for i, w := range c.want {
				want[i] = strings.ReplaceAll(w, "PLIST", path)
			}

			if !slices.Equal(f.changes, want) {
				t.Errorf("install asked launchctl for %q, want %q", f.changes, want)
			}

			if f.running != c.wantRunning {
				t.Errorf("after install the job is running: %v, want %v", f.running, c.wantRunning)
			}

			if f.disabled {
				t.Error("install left the label disabled, so it does not load at boot")
			}

			if got, err := os.ReadFile(path); err != nil || string(got) != string(plist) {
				t.Errorf("the plist on disk is %q (%v), want the one installed", got, err)
			}
		})
	}
}
