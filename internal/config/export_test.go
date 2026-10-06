package config

import (
	"encoding/json"
	"reflect"
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
		"a certificate without its key": {func(e *Export) { e.ClientCert = &Secret{Path: "client.pem"} }, "go together"},
		"a key without its certificate": {func(e *Export) { e.ClientKey = &Secret{Inline: []byte("pem")} }, "go together"},
		"no signal":                     {func(e *Export) { e.Metrics = false }, "export.flows"},
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

	// Flows alone is a signal: anchord exports them as logs of their own.
	flows := good()
	flows.Metrics, flows.Flows = false, true

	if err := flows.Validate(); err != nil {
		t.Errorf("a flows-only export was refused: %v", err)
	}

	// Off is off: nothing but the file's own shape is checked.
	if err := (&Export{Endpoint: "collector"}).Validate(); err != nil {
		t.Errorf("a disabled block was refused for its endpoint: %v", err)
	}

	// anchord loads the client pair only over TLS.
	half := good()
	half.Insecure, half.ClientCert = true, &Secret{Path: "client.pem"}

	if err := half.Validate(); err != nil {
		t.Errorf("half a client pair was refused on a plaintext export, which never loads it: %v", err)
	}
}

// TestExportReadsAsAnchordDoes: the block is read as protojson reads an ExportConfig,
// so one pasted from an anchord config -- in either of its names, with its int64s as
// strings -- means the same here, and a field anchord would refuse is refused rather
// than dropped.
func TestExportReadsAsAnchordDoes(t *testing.T) {
	var e Export

	err := json.Unmarshal([]byte(`{
		"enabled": true, "endpoint": "collector:4317", "metrics": true, "flows": true,
		"metricIntervalNanos": "60000000000", "export_timeout_nanos": 6e10,
		"trace_sample_ratio": "0.25", "log_level": -4, "serviceName": null,
		"ca_cert": {"inline": "-_8"}, "clientCert": {"path": "client.pem"}
	}`), &e)
	if err != nil {
		t.Fatalf("anchord's own form was refused: %v", err)
	}

	want := Export{
		Enabled: true, Endpoint: "collector:4317", Metrics: true, Flows: true,
		MetricIntervalNanos: 60e9, ExportTimeoutNanos: 60e9, TraceSampleRatio: 0.25, LogLevel: -4,
		CACert: &Secret{Inline: []byte{0xfb, 0xff}}, ClientCert: &Secret{Path: "client.pem"},
	}

	if !reflect.DeepEqual(e, want) {
		t.Errorf("read %+v\nwant %+v", e, want)
	}

	// What conflux writes reads back the same.
	b, _ := json.Marshal(want)

	var again Export
	if err := json.Unmarshal(b, &again); err != nil || !reflect.DeepEqual(again, want) {
		t.Errorf("conflux's own rendering read back as %+v, %v", again, err)
	}

	for name, in := range map[string]string{
		"an unknown field":            `{"endpiont": "collector:4317"}`,
		"one field by both names":     `{"serviceName": "a", "service_name": "b"}`,
		"one field twice":             `{"logs": true, "logs": false}`,
		"a fraction for an int64":     `{"metricIntervalNanos": "1.5"}`,
		"a padded number string":      `{"metricIntervalNanos": " 5"}`,
		"a boolean for an int64":      `{"logLevel": true}`,
		"an int64 past 64 bits":       `{"cardinalityLimit": "9223372036854775808"}`,
		"a secret given two ways":     `{"caCert": {"inline": "cGVt", "path": "ca.pem"}}`,
		"an unknown field in secret":  `{"caCert": {"file": "ca.pem"}}`,
		"a ratio that is not a ratio": `{"traceSampleRatio": "NaN"}`,
	} {
		if err := json.Unmarshal([]byte(in), new(Export)); err == nil {
			t.Errorf("%s was accepted: %s", name, in)
		}
	}
}
