package service

import (
	"encoding/xml"
	"errors"
	"io"
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
