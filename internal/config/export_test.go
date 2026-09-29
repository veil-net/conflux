package config

import (
	"strings"
	"testing"
)

// TestExportRefusesWhatAnchordRefuses: anchord reads the rendered block with -config
// and will not start on one it refuses, and the supervisor would retry that start for
// ever. Each of these is refused here instead, naming the field.
func TestExportRefusesWhatAnchordRefuses(t *testing.T) {
	good := func() *Export {
		return &Export{Enabled: true, Endpoint: "collector:4317", Metrics: true}
	}

	if err := good().Validate(); err != nil {
		t.Fatalf("a good block was refused: %v", err)
	}

	for name, tc := range map[string]struct {
		set  func(*Export)
		says string
	}{
		"no port":                 {func(e *Export) { e.Endpoint = "collector" }, "host:port"},
		"a URL":                   {func(e *Export) { e.Endpoint = "https://collector:4317" }, "rather than a URL"},
		"a negative interval":     {func(e *Export) { e.MetricIntervalNanos = -1 }, "negative"},
		"a negative timeout":      {func(e *Export) { e.ExportTimeoutNanos = -1 }, "negative"},
		"a header with no name":   {func(e *Export) { e.Headers = map[string]string{"": "x"} }, "no name"},
		"a secret given two ways": {func(e *Export) { e.CACert = &Secret{Inline: []byte("pem"), Path: "ca.pem"} }, "caCert"},
		"two ways, while off": {func(e *Export) {
			e.Enabled = false
			e.ClientKey = &Secret{Inline: []byte("pem"), Path: "key.pem"}
		}, "clientKey"},
	} {
		t.Run(name, func(t *testing.T) {
			e := good()
			tc.set(e)

			err := e.Validate()
			if err == nil {
				t.Fatal("accepted")
			}

			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the refusal should say %q; it said: %v", tc.says, err)
			}
		})
	}

	// Off is off: nothing but the file's own shape is checked.
	if err := (&Export{Endpoint: "collector"}).Validate(); err != nil {
		t.Errorf("a disabled block was refused for its endpoint: %v", err)
	}
}
