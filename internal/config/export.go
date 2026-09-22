package config

import (
	"errors"
	"fmt"
	"strings"
)

// Export is where this machine's anchord sends its telemetry.
//
// **A mirror of anchor.v1.ExportConfig, field for field and name for name**, and
// the exactness is the design rather than laziness. anchord reads its own config
// file as protojson and **an unknown field is an error**, so any shape conflux
// invented here would be a second schema that can drift from the one anchord
// enforces -- and the way it would present is a daemon refusing to start over a
// field name its operator never typed. One set of names means the block below can
// be pasted into an anchord config and back out again, and means anchor's own
// documentation describes what an operator is looking at.
//
// The cost is the nanosecond fields, which are anchor's names for durations and
// are not what anyone would choose for a hand-edited file. That is the price of not
// having two vocabularies for one thing, and it is worth saying out loud rather
// than discovering when a translated name is silently ignored. docs/config.md
// carries worked values.
//
// **Headers are credentials.** Anything in them authenticates this machine to a
// collector, which is why this file is 0600 inside a 0700 directory and why the
// rendered anchord config beside it is too.
type Export struct {
	// Enabled false turns export off and ignores every other field. Always
	// written, never omitted: the rendered file is what the daemon believes on
	// every start, so "off" has to be something the file says rather than
	// something it fails to mention.
	Enabled bool `json:"enabled"`

	// Endpoint is host:port of an OTLP/gRPC collector. Required when enabled.
	Endpoint string `json:"endpoint,omitempty"`

	// Insecure sends plaintext. TLS is the default, and this is named for what it
	// does rather than for the option that would turn it off.
	Insecure bool `json:"insecure,omitempty"`

	// Headers accompany every export. This is how a collector knows which machine
	// is reporting, and every value here is a credential.
	Headers map[string]string `json:"headers,omitempty"`

	Metrics bool `json:"metrics,omitempty"`
	Traces  bool `json:"traces,omitempty"`
	Logs    bool `json:"logs,omitempty"`

	// MetricIntervalNanos is how often accumulated metrics are sent. Zero is 60s.
	MetricIntervalNanos int64 `json:"metricIntervalNanos,omitempty"`

	// TraceSampleRatio is the fraction of traces recorded, 0 to 1.
	TraceSampleRatio float64 `json:"traceSampleRatio,omitempty"`

	// ServiceName names this process at the collector. Empty is "anchord".
	ServiceName string `json:"serviceName,omitempty"`

	// ResourceAttributes are attached to everything exported.
	ResourceAttributes map[string]string `json:"resourceAttributes,omitempty"`

	ExportTimeoutNanos   int64 `json:"exportTimeoutNanos,omitempty"`
	ShutdownTimeoutNanos int64 `json:"shutdownTimeoutNanos,omitempty"`

	// TLS material, as PEM. Empty uses the system pool and no client certificate.
	CACert     *Secret `json:"caCert,omitempty"`
	ClientCert *Secret `json:"clientCert,omitempty"`
	ClientKey  *Secret `json:"clientKey,omitempty"`

	// LogLevel is the slog level at which logs are exported: -4 debug, 0 info,
	// 4 warn, 8 error.
	LogLevel int64 `json:"logLevel,omitempty"`

	// CardinalityLimit bounds the attribute sets one instrument keeps. Zero is
	// anchor's default; negative turns the limit off, which a large realm should
	// do deliberately or not at all.
	CardinalityLimit int64 `json:"cardinalityLimit,omitempty"`
}

// Secret is anchor's Secret: material itself, or a path the daemon opens.
//
// Both are kept because they are genuinely different. Inline travels in this file
// and needs no second file to keep at the right mode; a path lets a collector's CA
// come from wherever the host already manages certificates. Neither is a default:
// an empty Secret means the system pool.
type Secret struct {
	// Inline is the material. JSON renders []byte as base64, which is what
	// protojson does with a bytes field, so the two agree without a conversion.
	Inline []byte `json:"inline,omitempty"`

	// Path is a file the *daemon* reads, resolved against the daemon's working
	// directory rather than whoever wrote this file.
	Path string `json:"path,omitempty"`
}

// Validate refuses a block that would be accepted and then do nothing.
//
// Every refusal here is a configuration that starts cleanly and exports nothing,
// which is the failure this whole feature exists to stop somebody discovering
// three weeks later when they go looking for a graph.
func (e *Export) Validate() error {
	if e == nil || !e.Enabled {
		return nil
	}

	if strings.TrimSpace(e.Endpoint) == "" {
		return errors.New("export is enabled and has no endpoint: set export.endpoint to a collector's host:port")
	}

	if strings.Contains(e.Endpoint, "://") {
		return fmt.Errorf(
			"export.endpoint is %q and wants a host:port rather than a URL: the scheme is "+
				"decided by export.insecure", e.Endpoint)
	}

	// All three off is the same as not exporting, and anchor reports it as such.
	// Refusing it here means an operator who meant to pick signals finds out now
	// rather than from a collector that never hears from this machine.
	if !e.Metrics && !e.Traces && !e.Logs {
		return errors.New(
			"export is enabled and no signal is selected: set at least one of " +
				"export.metrics, export.traces, export.logs")
	}

	if e.TraceSampleRatio < 0 || e.TraceSampleRatio > 1 {
		return fmt.Errorf("export.traceSampleRatio is %v and is a fraction from 0 to 1", e.TraceSampleRatio)
	}

	return nil
}
