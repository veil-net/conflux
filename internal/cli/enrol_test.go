package cli

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
)

// guardianDoc is a manifest a self-hosted guardian issues. Kept in step with
// enrol's own fixture and with guardian's docs/contracts/guardian-node.md; the
// fields this package cares about are renewalUrl, renewalAuth and ipv4.
const guardianDoc = `{
  "formatVersion": 1,
  "kind": "anchor",
  "realm": "5c2e9b71aa03d4f6e8",
  "genesis": "0011223344556677",
  "identity": "99887766554433221100ffeeddccbbaa",
  "chain": "Z3VhcmRpYW4tY2hhaW4=",
  "notAfter": "2026-10-13T04:12:00.000Z",
  "taints": [],
  "useExit": false,
  "telemetrySecret": "cafebabe0123",
  "bootstrap": ["genesis-1.example.gov:4700"],
  "renewalUrl": "https://guardian.example.gov/nodes/abc/credential",
  "renewalAuth": "node-secret",
  "renewalSecret": "abc.c2VjcmV0",
  "ipv4": "10.20.0.7/24",
  "issuedAt": "2026-09-13T04:12:00.000Z"
}`

const guardianAPI = "https://guardian.example.gov"

// site sets up an isolated conflux directory and writes a manifest file into it.
func site(t *testing.T, doc string) (paths.Dirs, string) {
	t.Helper()
	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	path := filepath.Join(t.TempDir(), "manifest.b64")
	env := base64.StdEncoding.EncodeToString([]byte(doc))

	if err := os.WriteFile(path, []byte(env+"\n"), 0o600); err != nil {
		t.Fatalf("write the manifest: %v", err)
	}

	return d, path
}

func TestEnrolInstallsWhatItWasGiven(t *testing.T) {
	d, path := site(t, guardianDoc)

	if err := importCredential(d, path, guardianAPI, "", nil); err != nil {
		t.Fatalf("importCredential: %v", err)
	}

	// The identity landed, byte for byte. Re-decoding rather than comparing the
	// file is the point: a manifest conflux cannot read back is one the next boot
	// fails on.
	env, err := config.LoadManifest(d)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}

	got, err := base64.StdEncoding.DecodeString(string(strings.TrimSpace(string(env))))
	if err != nil {
		t.Fatalf("the installed manifest is not base64: %v", err)
	}

	if string(got) != guardianDoc {
		t.Error("the installed manifest is not the document that was handed over")
	}

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.APIBaseURL != guardianAPI {
		t.Errorf("apiBaseUrl = %q, want %q", cfg.APIBaseURL, guardianAPI)
	}

	if cfg.IPv4 != "10.20.0.7/24" {
		t.Errorf("ipv4 = %q, want the address the issuer allocated", cfg.IPv4)
	}
}

// TestEnrolWillNotReplaceAnIdentity is the rule this verb exists to not break.
//
// `up` enrols only when there is no manifest, because a second enrolment is a
// second AnchorID and a second overlay address. A verb that writes manifests would
// be the way around that rule if it did not refuse here.
func TestEnrolWillNotReplaceAnIdentity(t *testing.T) {
	d, path := site(t, guardianDoc)

	if err := importCredential(d, path, guardianAPI, "", nil); err != nil {
		t.Fatalf("the first import: %v", err)
	}

	before, err := config.LoadManifest(d)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}

	err = importCredential(d, path, guardianAPI, "", nil)
	if err == nil {
		t.Fatal("importCredential replaced an existing identity")
	}

	if !strings.Contains(err.Error(), "uninstall") {
		t.Errorf("the refusal should name the way through: %v", err)
	}

	after, err := config.LoadManifest(d)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}

	if string(before) != string(after) {
		t.Error("the refused import changed the manifest anyway")
	}
}

// TestEnrolRefusesBeforeWriting covers every refusal at once, and checks the same
// thing about each: that nothing reached the disk. A verb that writes half of a
// provisioning is worse than one that writes none of it.
func TestEnrolRefusesBeforeWriting(t *testing.T) {
	realmDoc := strings.Replace(guardianDoc, `"kind": "anchor"`, `"kind": "realm"`, 1)
	futureDoc := strings.Replace(guardianDoc, `"formatVersion": 1`, `"formatVersion": 2`, 1)
	unknownAuth := strings.Replace(guardianDoc, `"renewalAuth": "node-secret"`, `"renewalAuth": "mtls"`, 1)
	noRenewal := strings.Replace(guardianDoc,
		`  "renewalUrl": "https://guardian.example.gov/nodes/abc/credential",`+"\n", "", 1)
	badAddress := strings.Replace(guardianDoc, `"ipv4": "10.20.0.7/24"`, `"ipv4": "10.20.0.7"`, 1)

	for name, tc := range map[string]struct {
		doc  string
		api  string
		says string
	}{
		"a realm manifest":            {realmDoc, guardianAPI, "realm"},
		"a format version from later": {futureDoc, guardianAPI, "upgrade conflux"},
		"a renewalAuth we do not do":  {unknownAuth, guardianAPI, "mtls"},
		"no renewalUrl at all":        {noRenewal, guardianAPI, "renewalUrl"},
		"an address that is not one":  {badAddress, guardianAPI, "prefix"},
		"an api naming another host":  {guardianDoc, "https://somewhere.else", "somewhere.else"},
	} {
		t.Run(name, func(t *testing.T) {
			d, path := site(t, tc.doc)

			err := importCredential(d, path, tc.api, "", nil)
			if err == nil {
				t.Fatalf("importCredential accepted %s", name)
			}

			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the refusal does not mention %q: %v", tc.says, err)
			}

			if config.HasManifest(d) {
				t.Error("a refused import wrote the manifest anyway")
			}

			if _, err := config.Load(d); err == nil {
				t.Error("a refused import wrote the configuration anyway")
			}
		})
	}
}

// TestEnrolDerivesTheAPIFromTheManifest. The document names an absolute renewal
// URL because a self-hosted API is wherever its operator put it, so the base is
// already there and making somebody retype it buys a typo rather than a check.
//
// This replaces a test that pinned the opposite. The argument then was that a
// stored field must not decide where a credential is POSTed -- but the same
// document carries the identity seed and the renewal bearer, so anyone able to
// rewrite its renewalUrl already holds everything the redirect would steal. The
// check was defending a boundary that is not there, at the cost of a required flag
// on every enrolment.
func TestEnrolDerivesTheAPIFromTheManifest(t *testing.T) {
	d, path := site(t, guardianDoc)

	if err := importCredential(d, path, "", "", nil); err != nil {
		t.Fatalf("importCredential with no --api: %v", err)
	}

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	if got, want := cfg.APIBaseURL, guardianAPI; got != want {
		t.Errorf("APIBaseURL = %q, want %q read out of the manifest's renewalUrl", got, want)
	}
}

// TestEnrolStillChecksAnApiThatWasGiven. The flag is an override and an assertion
// at once: pass it and the document must agree, so an operator who wants the old
// belt-and-braces check can still have it by naming the host they expect.
func TestEnrolStillChecksAnApiThatWasGiven(t *testing.T) {
	d, path := site(t, guardianDoc)

	if err := importCredential(d, path, "https://elsewhere.example", "", nil); err == nil {
		t.Fatal("importCredential accepted an --api the manifest does not renew against")
	}

	if config.HasManifest(d) {
		t.Error("it wrote the manifest anyway")
	}
}

// TestEnrolLetsTheFlagWin. A person typing an address now is a later decision than
// a document written earlier, so --ipv4 overrides what the issuer allocated.
func TestEnrolLetsTheFlagWin(t *testing.T) {
	d, path := site(t, guardianDoc)

	if err := importCredential(d, path, guardianAPI, "10.99.0.3/24", nil); err != nil {
		t.Fatalf("importCredential: %v", err)
	}

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.IPv4 != "10.99.0.3/24" {
		t.Errorf("ipv4 = %q, want the flag", cfg.IPv4)
	}
}

// TestEnrolTakesTheTaintsTheGuardianChose. The compartment is the guardian's
// decision because it is the one thing in the document that says which machines
// may reach this one, and a fleet whose members each mint their own taint is a
// fleet of one-machine networks. `up` mints when the configuration has none, so
// enrol writing them is what stops that happening per node.
func TestEnrolTakesTheTaintsTheGuardianChose(t *testing.T) {
	doc := strings.Replace(guardianDoc, `"taints": []`, `"taints": ["site-alpha", "tier-2"]`, 1)
	d, path := site(t, doc)

	if err := importCredential(d, path, "", "", nil); err != nil {
		t.Fatalf("importCredential: %v", err)
	}

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got, want := strings.Join(cfg.Taints, ","), "site-alpha,tier-2"; got != want {
		t.Errorf("taints = %q, want %q", got, want)
	}
}

// TestEnrolLetsTheTaintFlagWin, for the same reason --ipv4 wins: a person at the
// terminal is deciding now and the document was written earlier.
func TestEnrolLetsTheTaintFlagWin(t *testing.T) {
	doc := strings.Replace(guardianDoc, `"taints": []`, `"taints": ["site-alpha"]`, 1)
	d, path := site(t, doc)

	if err := importCredential(d, path, "", "", []string{"site-beta"}); err != nil {
		t.Fatalf("importCredential: %v", err)
	}

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got, want := strings.Join(cfg.Taints, ","), "site-beta"; got != want {
		t.Errorf("taints = %q, want the flag %q", got, want)
	}
}

// TestEnrolRefusesATaintItCannotRepresent. Validated at import rather than copied
// through, because the alternative is a machine that enrols cleanly and then fails
// to come up, reporting the problem from anchor instead of from the document that
// caused it.
func TestEnrolRefusesATaintItCannotRepresent(t *testing.T) {
	doc := strings.Replace(guardianDoc, `"taints": []`, `"taints": ["has a space"]`, 1)
	d, path := site(t, doc)

	if err := importCredential(d, path, "", "", nil); err == nil {
		t.Fatal("importCredential accepted a taint conflux cannot carry")
	}

	if config.HasManifest(d) {
		t.Error("it wrote the manifest anyway")
	}
}

// TestEnrolLeavesTaintsAloneWhenNobodySaid. An empty list in the document is the
// alpha shape and means "not my decision", so the configuration keeps none and `up`
// mints one loudly. Choosing a compartment quietly here would be the one thing
// conflux refuses to do anywhere else.
func TestEnrolLeavesTaintsAloneWhenNobodySaid(t *testing.T) {
	d, path := site(t, guardianDoc)

	if err := importCredential(d, path, "", "", nil); err != nil {
		t.Fatalf("importCredential: %v", err)
	}

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Taints) != 0 {
		t.Errorf("taints = %v, want none so that up mints and says so", cfg.Taints)
	}
}

// TestEnrolAcceptsAnAlphaManifest. Nothing about this verb is guardian-only: a
// document from the public realm carries no renewalAuth and no ipv4, and installing
// one by hand -- restoring a machine from a saved manifest, say -- has to work.
func TestEnrolAcceptsAnAlphaManifest(t *testing.T) {
	alpha := `{
  "formatVersion": 1,
  "kind": "anchor",
  "realm": "8f3a1c04be77d2e5aa",
  "identity": "aabbccddeeff00112233445566778899",
  "chain": "Y2hhaW4=",
  "notAfter": "2026-09-13T04:12:00.000Z",
  "renewalUrl": "https://api.veilnet.com.au/ghosts/alpha/renew",
  "renewalAuth": "anchor-id",
  "issuedAt": "2026-09-06T04:12:00.000Z"
}`

	d, path := site(t, alpha)

	if err := importCredential(d, path, "https://api.veilnet.com.au", "", nil); err != nil {
		t.Fatalf("importCredential: %v", err)
	}

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.IPv4 != "" {
		t.Errorf("ipv4 = %q, want none: the alpha realm allocates no address", cfg.IPv4)
	}
}

// exportDoc is a guardian manifest that also tells the node where to report.
const exportDoc = `{
  "formatVersion": 1,
  "kind": "anchor",
  "identity": "99887766554433221100ffeeddccbbaa",
  "chain": "Z3VhcmRpYW4tY2hhaW4=",
  "notAfter": "2026-10-13T04:12:00.000Z",
  "renewalUrl": "https://guardian.example.gov/nodes/abc/credential",
  "renewalAuth": "node-secret",
  "renewalSecret": "abc.c2VjcmV0",
  "export": {
    "enabled": true,
    "endpoint": "guardian.example.gov:4317",
    "metrics": true,
    "headers": {"authorization": "Basic YWJjOnNlY3JldA=="}
  },
  "issuedAt": "2026-09-13T04:12:00.000Z"
}`

// TestEnrolSeedsTheExportBlock. An operator who commissioned fifty nodes in a web
// UI should not then type the same endpoint and fifty different credentials into
// fifty config files by hand.
func TestEnrolSeedsTheExportBlock(t *testing.T) {
	d, path := site(t, exportDoc)

	if err := importCredential(d, path, guardianAPI, "", nil); err != nil {
		t.Fatalf("importCredential: %v", err)
	}

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Export == nil || !cfg.Export.Enabled {
		t.Fatal("the export block did not reach conflux.json")
	}

	if cfg.Export.Endpoint != "guardian.example.gov:4317" {
		t.Errorf("endpoint = %q", cfg.Export.Endpoint)
	}

	if cfg.Export.Headers["authorization"] == "" {
		t.Error("the collector credential did not survive; this node would be refused")
	}
}

// TestEnrolRefusesAnExportBlockThatWouldDoNothing. A block naming no endpoint is a
// machine that starts cleanly and exports nothing, and the symptom arrives weeks
// later as an absence on a dashboard.
func TestEnrolRefusesAnExportBlockThatWouldDoNothing(t *testing.T) {
	for name, broken := range map[string]string{
		"no endpoint": `"enabled": true, "metrics": true`,
		"no signal":   `"enabled": true, "endpoint": "collector:4317"`,
		"a URL":       `"enabled": true, "endpoint": "https://collector:4317", "metrics": true`,
	} {
		t.Run(name, func(t *testing.T) {
			doc := strings.Replace(exportDoc,
				`"enabled": true,
    "endpoint": "guardian.example.gov:4317",
    "metrics": true,
    "headers": {"authorization": "Basic YWJjOnNlY3JldA=="}`, broken, 1)

			d, path := site(t, doc)

			if err := importCredential(d, path, guardianAPI, "", nil); err == nil {
				t.Errorf("importCredential accepted an export block with %s", name)
			} else if !strings.Contains(err.Error(), "export") {
				t.Errorf("the refusal does not say it is about export: %v", err)
			}

			if config.HasManifest(d) {
				t.Error("a refused import wrote the manifest anyway")
			}
		})
	}
}

// TestEnrolDoesNotOverwriteAnExportBlockTheOperatorWrote. Re-import is refused
// anyway, so the only way to arrive here with one set is somebody having written
// it, and a document must not replace that.
func TestEnrolDoesNotOverwriteAnExportBlockTheOperatorWrote(t *testing.T) {
	d, path := site(t, exportDoc)

	mine := &config.Config{Mode: config.ModeTUN, Taints: []string{"site"},
		Export: &config.Export{Enabled: true, Endpoint: "mine:4317", Metrics: true}}
	if err := config.Save(d, mine); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := importCredential(d, path, guardianAPI, "", nil); err != nil {
		t.Fatalf("importCredential: %v", err)
	}

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Export.Endpoint != "mine:4317" {
		t.Errorf("endpoint = %q, want the one the operator wrote", cfg.Export.Endpoint)
	}
}
