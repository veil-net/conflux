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

// TestEnrolDoesNotDeriveTheAPIFromTheManifest. The host check exists because a
// stored field must not decide where a credential is POSTed; reading --api out of
// the document's own renewalUrl would make the two agree by construction and check
// nothing. The verb requires --api, so the mismatch above is reachable at all.
func TestEnrolDoesNotDeriveTheAPIFromTheManifest(t *testing.T) {
	d, path := site(t, guardianDoc)

	if err := importCredential(d, path, "", ""); err == nil {
		t.Fatal("importCredential accepted an empty --api and took the manifest's word for it")
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

	if cfg.IPv4 != "10.99.0.3/24" {
		t.Errorf("ipv4 = %q, want the flag", cfg.IPv4)
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

	if err := importCredential(d, path, "https://api.veilnet.com.au", ""); err != nil {
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
