package cli

import (
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
)

// guardianDoc is a manifest a self-hosted guardian issues: anchor's format, plus the
// renewal fields and an ipv4. Kept in step with enrol's own fixture; the fields this
// package cares about are renewalUrl, renewalAuth and ipv4.
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

// site sets up an isolated conflux directory and writes a manifest file into it. What
// importCredential tells a person goes nowhere.
func site(t *testing.T, doc string) (paths.Dirs, string) {
	t.Helper()
	t.Setenv("CONFLUX_DIR", t.TempDir())

	out := ui.Out
	ui.Out = io.Discard

	t.Cleanup(func() { ui.Out = out })

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

	if err := importCredential(d, path, guardianAPI, ""); err != nil {
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

	if cfg.OverlayIPv4() != "10.20.0.7/24" {
		t.Errorf("ipv4 = %q, want the address the issuer allocated", cfg.OverlayIPv4())
	}
}

// TestEnrolWillNotReplaceAnIdentity is the rule this verb exists to not break.
//
// `up` enrols only when there is no manifest, because a second enrolment is a
// second AnchorID and a second overlay address. A verb that writes manifests would
// be the way around that rule if it did not refuse here.
func TestEnrolWillNotReplaceAnIdentity(t *testing.T) {
	d, path := site(t, guardianDoc)

	if err := importCredential(d, path, guardianAPI, ""); err != nil {
		t.Fatalf("the first import: %v", err)
	}

	before, err := config.LoadManifest(d)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}

	err = importCredential(d, path, guardianAPI, "")
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
	badAddress := strings.Replace(guardianDoc, `"ipv4": "10.20.0.7/24"`, `"ipv4": "127.0.0.7/8"`, 1)
	lapsedNode := strings.Replace(ghostNodeDoc, `"notAfter": "2126-10-03T11:25:49.000Z"`, `"notAfter": "2026-01-01T00:00:00.000Z"`, 1)

	for name, tc := range map[string]struct {
		doc  string
		api  string
		says string
	}{
		"a realm manifest":                {realmDoc, guardianAPI, "realm"},
		"a format version from later":     {futureDoc, guardianAPI, "upgrade conflux"},
		"a renewalAuth we do not do":      {unknownAuth, guardianAPI, "mtls"},
		"a renewalAuth and no renewalUrl": {noRenewal, guardianAPI, "renewalUrl"},
		"a fixed term already over":       {lapsedNode, "", "expired"},
		"an address anchor refuses":       {badAddress, guardianAPI, "unicast"},
		"an api naming another host":      {guardianDoc, "https://somewhere.else", "somewhere.else"},
	} {
		t.Run(name, func(t *testing.T) {
			d, path := site(t, tc.doc)

			err := importCredential(d, path, tc.api, "")
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

	if err := importCredential(d, path, "", ""); err != nil {
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

	if err := importCredential(d, path, "https://elsewhere.example", ""); err == nil {
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

	if err := importCredential(d, path, guardianAPI, "10.99.0.3/24"); err != nil {
		t.Fatalf("importCredential: %v", err)
	}

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.OverlayIPv4() != "10.99.0.3/24" {
		t.Errorf("ipv4 = %q, want the flag", cfg.OverlayIPv4())
	}
}

// TestEnrolTakesTheTaintsTheGuardianChose. The compartments are the guardian's to
// grant: the credential commits to them, and anchor starts the identity under no
// others. So they are written as the document names them, and every start checks
// conflux.json against it.
func TestEnrolTakesTheTaintsTheGuardianChose(t *testing.T) {
	doc := strings.Replace(guardianDoc, `"taints": []`, `"taints": ["site-alpha", "tier-2"]`, 1)
	d, path := site(t, doc)

	if err := importCredential(d, path, "", ""); err != nil {
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

// TestEnrolHasNoTaintFlag: the taints are the credential's, so there is nothing for a
// flag to overrule, and one that looked like it could would be a machine refused at
// its first start.
func TestEnrolHasNoTaintFlag(t *testing.T) {
	_, path := site(t, guardianDoc)

	if _, errOut, code := capture(t, "enrol", "--manifest", path, "--taint", "site-beta"); code != ExitUsage {
		t.Errorf("exited %d, want %d for a flag enrol does not take:\n%s", code, ExitUsage, errOut)
	}
}

// TestEnrolRefusesATaintItCannotRepresent. Validated at import rather than copied
// through, because the alternative is a machine that enrols cleanly and then fails
// to come up, reporting the problem from anchor instead of from the document that
// caused it.
func TestEnrolRefusesATaintItCannotRepresent(t *testing.T) {
	for _, bad := range []string{`"has a space"`, `"a@b"`, `"a,b"`} {
		doc := strings.Replace(guardianDoc, `"taints": []`, `"taints": [`+bad+`]`, 1)
		d, path := site(t, doc)

		if err := importCredential(d, path, "", ""); err == nil {
			t.Errorf("importCredential accepted the taint %s", bad)
		}

		if config.HasManifest(d) {
			t.Errorf("it wrote the manifest anyway, for %s", bad)
		}
	}
}

// TestEnrolTakesTheIssuersEmptySet. A guardian that grants no taints puts the machine in
// its own realm's default compartment, and conflux.json says so -- whatever an earlier
// `up` asked for, which this credential does not grant.
func TestEnrolTakesTheIssuersEmptySet(t *testing.T) {
	d, path := site(t, guardianDoc)

	if err := config.Save(d, &config.Config{Mode: config.ModeTUN, Taints: []string{"stale"}}); err != nil {
		t.Fatal(err)
	}

	if err := importCredential(d, path, "", ""); err != nil {
		t.Fatalf("importCredential: %v", err)
	}

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Taints) != 0 {
		t.Errorf("taints = %v, want none, as the credential grants", cfg.Taints)
	}
}

// TestEnrolRefusesAnAlphaCredentialInTheCommons. An alpha credential granting no taints
// is the realm's shared compartment, which conflux never puts a machine in -- typically
// one enrolled before alpha granted taints. Nothing is written.
func TestEnrolRefusesAnAlphaCredentialInTheCommons(t *testing.T) {
	d, path := site(t, strings.Replace(alphaDoc, `["brhk-2mq9-tzva-6pjs-k4xe-nw7d-qf"]`, "[]", 1))

	err := importCredential(d, path, "https://api.veilnet.com.au", "")
	if err == nil || !strings.Contains(err.Error(), "shared compartment") {
		t.Fatalf("importCredential = %v, want a refusal naming the shared compartment", err)
	}

	if config.HasManifest(d) {
		t.Error("it wrote the manifest anyway")
	}
}

// TestEnrolAcceptsAnAlphaManifest. Nothing about this verb is guardian-only: a
// document from the public realm carries no renewalAuth and no ipv4, and installing
// one by hand -- restoring a machine from a saved manifest, say -- has to work.
func TestEnrolAcceptsAnAlphaManifest(t *testing.T) {
	d, path := site(t, alphaDoc)

	if err := importCredential(d, path, "https://api.veilnet.com.au", ""); err != nil {
		t.Fatalf("importCredential: %v", err)
	}

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Not even "none": nobody has been asked yet, and the up that follows asks.
	if cfg.IPv4 != nil {
		t.Errorf("ipv4 = %q, want it undecided: the alpha realm allocates no address", *cfg.IPv4)
	}

	if len(cfg.Taints) != 1 || cfg.Taints[0] != "brhk-2mq9-tzva-6pjs-k4xe-nw7d-qf" {
		t.Errorf("taints = %v, want the one the credential grants", cfg.Taints)
	}
}

// alphaDoc is a manifest from the public alpha realm, enrolled in one taint: no
// renewalAuth bearer and no ipv4.
const alphaDoc = `{
  "formatVersion": 1,
  "kind": "anchor",
  "realm": "8f3a1c04be77d2e5aa",
  "genesis": "0011223344556677",
  "identity": "aabbccddeeff00112233445566778899",
  "chain": "Y2hhaW4=",
  "notAfter": "2026-09-13T04:12:00.000Z",
  "taints": ["brhk-2mq9-tzva-6pjs-k4xe-nw7d-qf"],
  "useExit": false,
  "bootstrap": ["genesis.veilnet.com.au:4700"],
  "renewalUrl": "https://api.veilnet.com.au/ghosts/alpha/renew",
  "renewalAuth": "anchor-id",
  "issuedAt": "2026-09-06T04:12:00.000Z"
}`

// exportDoc is a guardian manifest that also tells the node where to report.
const exportDoc = `{
  "formatVersion": 1,
  "kind": "anchor",
  "genesis": "0011223344556677",
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

	if err := importCredential(d, path, guardianAPI, ""); err != nil {
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

			if err := importCredential(d, path, guardianAPI, ""); err == nil {
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

	if err := importCredential(d, path, guardianAPI, ""); err != nil {
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

// ghostNodeDoc is a node traveller commissions in its own beta ghost realm: an exit,
// minted for a century, with no renewal fields at all. Kept in step with enrol's own
// fixture.
const ghostNodeDoc = `{
  "formatVersion": 1,
  "kind": "anchor",
  "realm": "34aa8de090970a18",
  "genesis": "0011223344556677",
  "identity": "b73928c5968473d0112233445566778899aabbccddeeff00112233445566778899",
  "chain": "bm9kZS1jaGFpbg==",
  "notAfter": "2126-10-03T11:25:49.000Z",
  "taints": ["au"],
  "listenPort": 4701,
  "exit": true,
  "telemetrySecret": "ddeafdc272de9e4",
  "bootstrap": ["genesis.veilnet.com.au:4700"],
  "issuedAt": "2026-10-02T11:25:57.587Z"
}`

// TestEnrolInstallsAGhostRealmNode. A credential that names nowhere to renew it is
// fixed-term rather than broken: traveller mints its own nodes for a century and serves
// no node renewal route. It installs with no --api, leaves the configured API alone, and
// takes the issuer's taint -- and not its exit, which conflux serves only when told to.
func TestEnrolInstallsAGhostRealmNode(t *testing.T) {
	d, path := site(t, ghostNodeDoc)

	if err := importCredential(d, path, "", ""); err != nil {
		t.Fatalf("importCredential: %v", err)
	}

	if !config.HasManifest(d) {
		t.Fatal("the credential was not installed")
	}

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.APIBaseURL != "" {
		t.Errorf("apiBaseUrl = %q, want it left alone: nothing renews this credential", cfg.APIBaseURL)
	}

	if len(cfg.Taints) != 1 || cfg.Taints[0] != "au" {
		t.Errorf("taints = %q, want the issuer's [au]", cfg.Taints)
	}

	if cfg.ServeExit {
		t.Error("serveExit was inherited from the document; an exit is conflux's to decide")
	}
}
