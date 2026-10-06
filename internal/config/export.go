package config

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
// **And it is read the way anchord reads it**: either of protojson's two names for a
// field, an int64 as a number or as a string, bytes in either base64 alphabet, and an
// unknown or repeated field refused rather than dropped -- see UnmarshalJSON. What
// conflux writes back is the canonical form, camelCase with numbers, which protojson
// reads as well.
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
	// written, so a block that is off says so rather than leaving it to be
	// inferred from a missing key.
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

	// Flows exports a log record for each interval of each IP flow the anchor carries
	// between its own side and a peer, and of each circuit it relays. The anchor counts
	// flows only while this is on.
	Flows bool `json:"flows,omitempty"`

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

// Validate refuses a block anchord would refuse, or accept and then do nothing.
//
// The first kind is fatal to anchord at startup -- it reads this file with -config and
// will not come up on one it refuses -- so it is refused here, where the message can
// name the field, rather than as a daemon that exits before it answers. The second is a
// configuration that starts cleanly and exports nothing, which is the failure this whole
// feature exists to stop somebody discovering three weeks later when they go looking for
// a graph.
func (e *Export) Validate() error {
	if e == nil {
		return nil
	}

	// Before the enabled check: a Secret is a oneof in anchor's schema, so a file giving
	// both halves fails to parse whether or not anything is exported.
	for name, s := range map[string]*Secret{"caCert": e.CACert, "clientCert": e.ClientCert, "clientKey": e.ClientKey} {
		if s != nil && len(s.Inline) > 0 && s.Path != "" {
			return fmt.Errorf("export.%s gives both inline and path, and is one or the other", name)
		}
	}

	if !e.Enabled {
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

	if _, _, err := net.SplitHostPort(e.Endpoint); err != nil {
		return fmt.Errorf("export.endpoint is %q and wants a host:port, such as collector:4317", e.Endpoint)
	}

	if e.MetricIntervalNanos < 0 || e.ExportTimeoutNanos < 0 || e.ShutdownTimeoutNanos < 0 {
		return errors.New("export has a negative metricIntervalNanos, exportTimeoutNanos or shutdownTimeoutNanos")
	}

	if _, ok := e.Headers[""]; ok {
		return errors.New("export.headers has a header with no name")
	}

	// All four off is refused by anchord at startup (REASON_EXPORT_NO_SIGNAL). Refusing it
	// here means an operator who meant to pick signals finds out now rather than from a
	// daemon that will not start.
	if !e.Metrics && !e.Traces && !e.Logs && !e.Flows {
		return errors.New(
			"export is enabled and no signal is selected: set at least one of " +
				"export.metrics, export.traces, export.logs, export.flows")
	}

	if e.TraceSampleRatio < 0 || e.TraceSampleRatio > 1 {
		return fmt.Errorf("export.traceSampleRatio is %v and is a fraction from 0 to 1", e.TraceSampleRatio)
	}

	// Only over TLS, which is the only place anchord loads the pair: half of one is mTLS
	// half-written, and it refuses to start on it rather than connect without.
	if e.Insecure {
		return nil
	}

	if e.ClientCert.given() != e.ClientKey.given() {
		return errors.New("export.clientCert and export.clientKey go together: a certificate needs its key, and a key its certificate")
	}

	return e.checkTLS()
}

// checkTLS refuses the material anchord cannot build a TLS configuration from at startup
// (otelbridge's tlsConfig): a CA that is not PEM it understands, and a client certificate
// and key that do not load as a pair. Read as anchord reads it -- inline, or the file a
// path names -- except a relative path, which resolves against the daemon's working
// directory and so cannot be read from here as the daemon would read it.
func (e *Export) checkTLS() error {
	ca, err := e.CACert.material("caCert")
	if err != nil {
		return err
	}

	if len(ca) > 0 && !x509.NewCertPool().AppendCertsFromPEM(ca) {
		return errors.New("export.caCert is not a PEM certificate anchord understands, and it would not start on it")
	}

	cert, err := e.ClientCert.material("clientCert")
	if err != nil {
		return err
	}

	key, err := e.ClientKey.material("clientKey")
	if err != nil {
		return err
	}

	if len(cert) > 0 && len(key) > 0 {
		if _, err := tls.X509KeyPair(cert, key); err != nil {
			return fmt.Errorf("export.clientCert and export.clientKey do not load as a pair, and anchord would not start on them: %w", err)
		}
	}

	return nil
}

// given reports whether a Secret names any material at all.
func (s *Secret) given() bool { return s != nil && (len(s.Inline) > 0 || s.Path != "") }

// material is what the Secret holds, read from its path when it names an absolute one;
// nil when it names nothing, or a relative path checkTLS cannot read as the daemon would.
func (s *Secret) material(field string) ([]byte, error) {
	switch {
	case s == nil:
		return nil, nil
	case len(s.Inline) > 0:
		return s.Inline, nil
	case !filepath.IsAbs(s.Path):
		return nil, nil
	}

	b, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, fmt.Errorf("export.%s: anchord reads it at startup and would not start without it: %w", field, err)
	}

	return b, nil
}

// exportNames maps both of protojson's names for each ExportConfig field -- the JSON
// name and the proto field name -- to the one conflux writes.
var exportNames = protoNames(
	"enabled", "endpoint", "insecure", "headers", "metrics", "traces", "logs", "flows",
	"metricIntervalNanos", "traceSampleRatio", "serviceName", "resourceAttributes",
	"exportTimeoutNanos", "shutdownTimeoutNanos", "caCert", "clientCert", "clientKey",
	"logLevel", "cardinalityLimit")

var secretNames = protoNames("inline", "path")

// protoNames indexes each camelCase JSON name under itself and under the snake_case
// proto field name it was derived from.
func protoNames(jsonNames ...string) map[string]string {
	out := make(map[string]string, 2*len(jsonNames))

	for _, n := range jsonNames {
		var snake strings.Builder

		for _, r := range n {
			if r >= 'A' && r <= 'Z' {
				snake.WriteByte('_')
				r += 'a' - 'A'
			}

			snake.WriteRune(r)
		}

		out[n], out[snake.String()] = n, n
	}

	return out
}

// UnmarshalJSON reads the block as protojson reads an ExportConfig, so a block anchord
// takes conflux takes, and one anchord refuses conflux refuses here, naming the field,
// rather than dropping what it does not recognise and rendering the rest.
func (e *Export) UnmarshalJSON(b []byte) error {
	fields, err := protoFields(b, exportNames)
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}

	*e = Export{}

	for name, raw := range fields {
		var err error

		switch name {
		case "enabled":
			err = json.Unmarshal(raw, &e.Enabled)
		case "endpoint":
			err = json.Unmarshal(raw, &e.Endpoint)
		case "insecure":
			err = json.Unmarshal(raw, &e.Insecure)
		case "headers":
			err = json.Unmarshal(raw, &e.Headers)
		case "metrics":
			err = json.Unmarshal(raw, &e.Metrics)
		case "traces":
			err = json.Unmarshal(raw, &e.Traces)
		case "logs":
			err = json.Unmarshal(raw, &e.Logs)
		case "flows":
			err = json.Unmarshal(raw, &e.Flows)
		case "metricIntervalNanos":
			e.MetricIntervalNanos, err = protoInt64(raw)
		case "traceSampleRatio":
			e.TraceSampleRatio, err = protoFloat(raw)
		case "serviceName":
			err = json.Unmarshal(raw, &e.ServiceName)
		case "resourceAttributes":
			err = json.Unmarshal(raw, &e.ResourceAttributes)
		case "exportTimeoutNanos":
			e.ExportTimeoutNanos, err = protoInt64(raw)
		case "shutdownTimeoutNanos":
			e.ShutdownTimeoutNanos, err = protoInt64(raw)
		case "caCert":
			err = json.Unmarshal(raw, &e.CACert)
		case "clientCert":
			err = json.Unmarshal(raw, &e.ClientCert)
		case "clientKey":
			err = json.Unmarshal(raw, &e.ClientKey)
		case "logLevel":
			e.LogLevel, err = protoInt64(raw)
		case "cardinalityLimit":
			e.CardinalityLimit, err = protoInt64(raw)
		}

		if err != nil {
			return fmt.Errorf("export.%s: %w", name, err)
		}
	}

	return nil
}

// UnmarshalJSON reads a Secret as protojson reads the oneof: one of its two fields, by
// either name, with inline material in either base64 alphabet.
func (s *Secret) UnmarshalJSON(b []byte) error {
	fields, err := protoFields(b, secretNames)
	if err != nil {
		return err
	}

	if len(fields) > 1 {
		return errors.New("gives both inline and path, and is one or the other")
	}

	*s = Secret{}

	if raw, ok := fields["inline"]; ok {
		s.Inline, err = protoBytes(raw)
	}

	if raw, ok := fields["path"]; ok {
		err = json.Unmarshal(raw, &s.Path)
	}

	return err
}

// protoFields reads a JSON object's fields under the names given, refusing one that is
// not among them and one given twice, under either name. A null field is left out, as
// protojson leaves it unset.
func protoFields(b []byte, names map[string]string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(b))

	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}

	fields := map[string]json.RawMessage{}

	if tok == nil {
		return fields, nil
	}

	if tok != json.Delim('{') {
		return nil, fmt.Errorf("want an object, got %s", b)
	}

	seen := map[string]bool{}

	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}

		key, _ := tok.(string)

		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}

		name, ok := names[key]

		switch {
		case !ok:
			return nil, fmt.Errorf("%q is not a field anchord knows", key)
		case seen[name]:
			return nil, fmt.Errorf("%q is given twice", name)
		}

		seen[name] = true

		if string(raw) != "null" {
			fields[name] = raw
		}
	}

	return fields, nil
}

// protoInt64 reads an int64 as protojson does: a number, or a string holding exactly
// one, written with an exponent or without as long as the value is whole.
func protoInt64(raw json.RawMessage) (int64, error) {
	text, err := protoNumber(raw)
	if err != nil {
		return 0, err
	}

	r, ok := new(big.Rat).SetString(text)
	if !ok || !r.IsInt() || !r.Num().IsInt64() {
		return 0, fmt.Errorf("%s is not a whole number that fits in 64 bits", raw)
	}

	return r.Num().Int64(), nil
}

// protoFloat reads a double the same way. protojson also takes "NaN" and the
// infinities, which no fraction is.
func protoFloat(raw json.RawMessage) (float64, error) {
	text, err := protoNumber(raw)
	if err != nil {
		return 0, err
	}

	return strconv.ParseFloat(text, 64)
}

// protoNumber is the JSON number a value holds, unquoted once if it came as a string,
// and refused if what is left is anything but a number.
func protoNumber(raw json.RawMessage) (string, error) {
	text := string(raw)

	var s string
	if json.Unmarshal(raw, &s) == nil {
		text = s
	}

	var n json.Number
	if text == strings.TrimSpace(text) && !strings.HasPrefix(text, `"`) && json.Unmarshal([]byte(text), &n) == nil {
		return n.String(), nil
	}

	return "", fmt.Errorf("%s is not a number", raw)
}

// protoBytes reads bytes as protojson does: standard or URL-safe base64, padded or not.
func protoBytes(raw json.RawMessage) ([]byte, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}

	enc := base64.StdEncoding
	if strings.ContainsAny(s, "-_") {
		enc = base64.URLEncoding
	}

	if len(s)%4 != 0 {
		enc = enc.WithPadding(base64.NoPadding)
	}

	return enc.DecodeString(s)
}
