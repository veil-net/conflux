package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/taint"
	"github.com/veil-net/conflux/internal/ui"
)

// runEnrol installs a credential this machine was given rather than one it drew.
//
// **The only way a self-hosted node is provisioned**, because a guardian serves no
// enrolment endpoint: its operator commissions machines in advance and downloads a
// manifest per machine. That is the opposite of the alpha realm, where anyone may
// POST and get an identity nobody records, and the two are different products
// rather than different settings.
//
// It is not "enrol from a file", and the distinction runs through every refusal
// below. `up` enrols exactly once, when there is no manifest on disk, and never as
// a fallback for anything -- because a second enrolment is a second identity, a
// second AnchorID and a second overlay address, and every peer that knew the first
// is orphaned with nothing said. This verb has to obey the same rule or it becomes
// the way around it.
//
// Hence, in order and all before a byte is written:
//
//   - the document is decoded, so a realm manifest, a future format version or a
//     truncated download fails here rather than at the next boot;
//   - its renewalAuth is resolved, so a scheme this build does not implement is
//     read by the person holding the terminal rather than by a timer months later;
//   - its renewal URL is read, because that is where the API base comes from and a
//     document that cannot say where it renews is one that never will;
//   - an existing manifest is refused outright.
//
// **The three flags are overrides, and the manifest is the source.** A guardian
// document carries the renewal URL, the overlay address and the taints, because a
// guardian knows all three -- it allocated the address out of a range it keeps and
// it decided which compartment the machine belongs in. That is the difference
// between this and the public alpha realm, whose document carries an identity and
// little else. So the ordinary invocation is `conflux enrol --manifest FILE` and
// nothing more, and each flag exists for the case where a person at the terminal
// knows something the issuer did not.
func runEnrol(_ context.Context, args []string) int {
	fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
	fs.SetOutput(ui.Errw)

	var taints repeated

	manifest := fs.String("manifest", "", "the manifest file to install, or - for stdin")
	apiBase := fs.String("api", "",
		"the API that issued it, as a base URL, overriding the one its renewal URL names")
	ipv4 := fs.String("ipv4", "", "overlay IPv4 as a prefix, overriding whatever the manifest allocated")
	fs.Var(&taints, "taint",
		"a compartment label, overriding whatever the manifest carries; repeat for more")

	fs.Usage = func() {
		ui.Printf("conflux enrol — install a credential this machine was given\n\n" +
			"  conflux enrol --manifest FILE [--api URL] [--ipv4 PREFIX] [--taint T]...\n\n" +
			"For a machine commissioned somewhere else: a self-hosted guardian mints the\n" +
			"identity, signs the credential and hands you one file. This installs it, and\n" +
			"then `conflux up` starts from it without enrolling.\n\n" +
			"The file is enough on its own. A guardian document names its own renewal URL,\n" +
			"the overlay address the guardian allocated and the compartment it put this\n" +
			"machine in, so the three flags exist only to overrule one of those from the\n" +
			"terminal. --api is also checked when given: the document must renew against\n" +
			"the same host.\n\n" +
			"It refuses to replace a manifest that already exists. Replacing one is a new\n" +
			"identity and a new overlay address, which orphans every peer this machine has.\n")
	}

	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	if *manifest == "" {
		fs.Usage()

		return ExitUsage
	}

	if err := privcheck.Require("installing a credential", "conflux enrol"); err != nil {
		return fail(fmt.Errorf("%w: %w", errNeedsRoot, err))
	}

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		return fail(err)
	}

	if err := importCredential(d, *manifest, *apiBase, *ipv4, taints); err != nil {
		return fail(err)
	}

	return 0
}

// importCredential is everything runEnrol does once the flags are parsed.
//
// Split out for the same reason `install` is split out of `runInstall`: the verb
// owns the terminal -- flags, privilege, exit codes -- and this owns the decision,
// so the refusals below are reachable from a test rather than only from a root
// shell. Every one of them is a refusal somebody will eventually hit.
func importCredential(d paths.Dirs, manifestPath, apiBase, ipv4Flag string, taintFlag []string) error {
	// First, and before the file is even read. The check is about an identity that
	// already exists, so it must not depend on the new document being any good --
	// otherwise a malformed file reports its own problem and hides this one.
	if config.HasManifest(d) {
		return fmt.Errorf(
			"this machine already has a credential at %s.\n"+
				"  Installing another replaces its identity: a different AnchorID, a different\n"+
				"  overlay address, and every peer that knew the old one left with no way to\n"+
				"  learn the new one. If that is genuinely what you want, `conflux uninstall`\n"+
				"  first and say so deliberately",
			d.ManifestFile())
	}

	env, err := readEnvelope(manifestPath)
	if err != nil {
		return err
	}

	m, err := enrol.Decode(env)
	if err != nil {
		return err
	}

	// Resolved rather than merely present. This is the one moment a person is here
	// to read "upgrade conflux", so the refusal that the renewal path defers lands
	// here instead -- before the machine is configured to depend on it.
	if _, err := m.Auth(); err != nil {
		return err
	}

	base, err := chooseAPIBase(m, apiBase)
	if err != nil {
		return err
	}

	address, err := chooseImportedIPv4(m, ipv4Flag)
	if err != nil {
		return err
	}

	compartments, err := chooseImportedTaints(m, taintFlag)
	if err != nil {
		return err
	}

	cfg, err := loadOrNew(d)
	if err != nil {
		return err
	}

	cfg.APIBaseURL = base
	cfg.IPv4 = address

	// Left alone when the document says nothing, rather than defaulted here. `up`
	// mints a taint for a machine whose configuration has none, and it explains
	// itself while doing it -- so a guardian that ships no taints lands the
	// operator in the one place conflux is loud about instead of in a compartment
	// this verb chose quietly.
	if len(compartments) > 0 {
		cfg.Taints = compartments
	}

	if err := seedExport(cfg, m); err != nil {
		return err
	}

	// **The configuration first, then the manifest, and the order is the recovery
	// story rather than a preference.**
	//
	// Crash between the two this way round and the machine has a config naming a
	// guardian and no identity: `up` finds no manifest, tries to enrol, is refused
	// by an API that serves no such route, and re-running this verb works because
	// HasManifest is still false. Nothing is lost.
	//
	// The other way round is not recoverable. A manifest lands, the config write
	// fails, and the machine now holds an identity it refuses to replace alongside
	// an apiBaseUrl pointing at the public API -- so the first renewal is refused
	// by SameHost, months later, naming two hosts the operator never chose between.
	if err := saveImported(d, cfg, env); err != nil {
		return err
	}

	ui.Printf("credential installed\n")
	ui.Field("from", manifestPath)
	ui.Field("api", base)
	ui.Field("renewal", m.RenewalURL())
	ui.Field("expires", m.NotAfter().Format("2006-01-02 15:04 MST"))

	if address != "" {
		ui.Field("ipv4", address)
	}

	if len(compartments) > 0 {
		ui.Field("taint", strings.Join(compartments, ", "))
	}

	if len(m.Bootstrap()) > 0 {
		ui.Field("bootstrap", strings.Join(m.Bootstrap(), ", "))
	}

	ui.Printf("\nNext: sudo conflux up\n")

	return nil
}

// readEnvelope reads the document, from a file or from stdin.
//
// Stdin is there so a manifest can be piped from wherever it was fetched without
// landing on disk at whatever mode the shell's umask chose. anchorctl spells the
// same thing the same way -- `-manifest -` -- so the two tools do not disagree
// about a convention an operator has already learned.
func readEnvelope(path string) (config.Envelope, error) {
	var (
		b   []byte
		err error
	)

	if path == "-" {
		b, err = io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	} else {
		b, err = os.ReadFile(path)
	}

	if err != nil {
		return nil, fmt.Errorf("read the manifest: %w", err)
	}

	env := config.Envelope(strings.TrimSpace(string(b)))
	if len(env) == 0 {
		return nil, errors.New("the manifest is empty")
	}

	return env, nil
}

// checkRenewalTarget refuses a document that renews somewhere --api does not name.
//
// **--api is required and is deliberately not derived from the manifest.** Reading
// the base URL out of the document's own renewalUrl would make the two agree by
// construction, which is exactly the check being removed: SameHost exists so that a
// field conflux stores and re-reads cannot decide where a credential is POSTed, and
// a check whose other operand comes from the same document checks nothing at all.
func chooseAPIBase(m *enrol.Manifest, flagValue string) (string, error) {
	url := m.RenewalURL()
	if url == "" {
		return "", errors.New(
			"the manifest carries no renewalUrl.\n" +
				"  conflux would fall back to the public alpha realm's renewal route, which a\n" +
				"  self-hosted API does not serve, and there is nothing here to read an API\n" +
				"  base out of. The issuer has to set it")
	}

	if flagValue == "" {
		return enrol.BaseOf(url)
	}

	if err := enrol.SameHost(url, flagValue); err != nil {
		return "", fmt.Errorf("%w.\n"+
			"  --api and the document disagree. Drop the flag to use the host the manifest\n"+
			"  names, or get a manifest issued for the API you meant", err)
	}

	return flagValue, nil
}

// chooseImportedTaints takes the flags if there are any, otherwise whatever the
// issuer put in the document.
//
// Validated either way, and that is the point of not just copying the list
// through: a taint conflux cannot represent is a machine that enrols cleanly and
// then fails to come up, with the reason arriving from anchor rather than from the
// document that caused it.
func chooseImportedTaints(m *enrol.Manifest, flagValues []string) ([]string, error) {
	values := flagValues
	if len(values) == 0 {
		values = m.Taints()
	}

	if len(values) == 0 {
		return nil, nil
	}

	if err := taint.ValidateSet(values); err != nil {
		return nil, fmt.Errorf("the taints for this machine: %w", err)
	}

	return values, nil
}

// chooseImportedIPv4 takes the flag if there is one, otherwise whatever the issuer
// allocated. The flag wins, because a person typing one now is a later decision
// than a document written earlier.
func chooseImportedIPv4(m *enrol.Manifest, flagValue string) (string, error) {
	value := flagValue
	if value == "" {
		value = m.IPv4()
	}

	if value == "" {
		return "", nil
	}

	if _, err := config.ParseOverlayIPv4(value); err != nil {
		return "", err
	}

	return value, nil
}

// seedExport copies the issuer's telemetry block into the configuration, once.
//
// Validated here rather than written and discovered later: a block naming no
// endpoint, or no signal, is a machine that starts cleanly and exports nothing, and
// the symptom of that arrives weeks afterwards as an absence on a dashboard.
//
// An existing block wins. Re-importing is refused anyway, so the only way to reach
// this with one already set is an operator who wrote it themselves -- and a
// document must not overwrite that.
func seedExport(cfg *config.Config, m *enrol.Manifest) error {
	raw := m.Export()
	if len(raw) == 0 || cfg.Export != nil {
		return nil
	}

	var export config.Export
	if err := json.Unmarshal(raw, &export); err != nil {
		return fmt.Errorf("the manifest's export block is not one conflux understands: %w", err)
	}

	if err := export.Validate(); err != nil {
		return fmt.Errorf("the manifest's export block: %w", err)
	}

	cfg.Export = &export

	return nil
}

func saveImported(d paths.Dirs, cfg *config.Config, env config.Envelope) error {
	// Mode is whatever it already was, or TUN for a machine with no configuration
	// yet: this verb installs a credential and does not decide what the machine
	// does with it. `up` and `proxy` still own that, and either of them run after
	// this reads the identity that is there rather than drawing one.
	if cfg.Mode == "" {
		cfg.Mode = config.ModeTUN
	}

	// config.Save and not Validate. Validate refuses an empty taint set, and
	// minting one here would put this machine in a compartment its operator never
	// chose; `up` and `proxy` mint it, along with the mode and everything else they
	// own. What lands here is half a configuration on purpose, and the half that
	// matters is apiBaseUrl.
	if err := config.Save(d, cfg); err != nil {
		return err
	}

	return config.SaveManifest(d, env)
}
