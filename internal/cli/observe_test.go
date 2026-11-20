package cli

import (
	"bytes"
	"encoding/base64"
	"flag"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/ui"
)

// TestObserveRefusesAnchorctlFlags: conflux observe and anchorctl's share a name, and what
// belongs to anchorctl's is answered with where it is, never guessed at -- -stop above all,
// which a person means for the observer running now and not for every boot.
func TestObserveRefusesAnchorctlFlags(t *testing.T) {
	for _, tc := range []struct {
		args []string
		says []string
	}{
		{[]string{"observe", "-start"}, []string{"conflux anchorctl observe -start -manifest FILE", "conflux up --observe"}},
		{[]string{"observe", "-stop"}, []string{"conflux down", "--no-observe", "conflux anchorctl observe -stop"}},
		{[]string{"observe", "-socket", "/run/x.sock"}, []string{"conflux anchorctl observe -socket /run/x.sock"}},
		{[]string{"observe", "--loopback", "-start=true"}, []string{"conflux anchorctl observe -start -manifest FILE"}},
	} {
		_, errOut, code := capture(t, tc.args...)

		if code != ExitUsage {
			t.Errorf("%v exited %d, want %d", tc.args, code, ExitUsage)
		}

		for _, want := range tc.says {
			if !strings.Contains(errOut, want) {
				t.Errorf("%v should say %q; it said:\n%s", tc.args, want, errOut)
			}
		}
	}
}

func TestObserveTakesNoArguments(t *testing.T) {
	_, errOut, code := capture(t, "observe", "now")

	if code != ExitUsage || !strings.Contains(errOut, "takes no arguments") {
		t.Errorf("exited %d, saying:\n%s", code, errOut)
	}
}

// TestObserveIsRefusedWhereThereIsNoCapture: on the BSDs, where anchor has nothing to
// capture with, conflux observe and --observe say so before anything is asked or written; and
// where there is a capture, neither is refused for it.
func TestObserveIsRefusedWhereThereIsNoCapture(t *testing.T) {
	for goos, refused := range map[string]bool{"freebsd": true, "openbsd": true, "linux": false, "darwin": false, "windows": false} {
		t.Run(goos, func(t *testing.T) {
			was, elevated := hostOS, privcheck.Elevated
			hostOS = goos

			// Refused for privilege where there is a capture, whoever runs this: the check under
			// test is the one before it, and nothing past it may touch this host.
			privcheck.Elevated = func() bool { return false }

			t.Cleanup(func() { hostOS, privcheck.Elevated = was, elevated })

			_, errOut, code := capture(t, "observe")

			switch {
			case refused && (code != ExitUsage || !strings.Contains(errOut, "no capture")):
				t.Errorf("conflux observe on %s exited %d, saying: %s; want exit %d for no capture", goos, code, errOut, ExitUsage)
			case !refused && code != ExitDenied:
				t.Errorf("conflux observe on %s exited %d, saying: %s; want the privilege check reached, exit %d", goos, code, errOut, ExitDenied)
			}

			err := chooseObserver(&config.Config{}, observerFlags(t, "--observe"))
			if got := err != nil && strings.Contains(err.Error(), "no capture"); got != refused {
				t.Errorf("--observe on %s: refused for no capture %v, want %v (%v)", goos, got, refused, err)
			}
		})
	}
}

// observerFlags parses args as up's and proxy's observer flags would be.
func observerFlags(t *testing.T, args ...string) *flag.FlagSet {
	t.Helper()

	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})
	registerObserver(fs)

	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}

	return fs
}

// TestTheObserverIsKeptOrReplaced: up and proxy keep the observer they are not told
// about; naming it says what it is now, an option left out being off, as anchorctl's
// -start does; and --no-observe is the way back.
func TestTheObserverIsKeptOrReplaced(t *testing.T) {
	// A platform with a capture, whichever this is: the BSDs' refusal has a test of its own.
	was := hostOS
	hostOS = "linux"

	t.Cleanup(func() { hostOS = was })

	both := &config.Observer{Loopback: true, HideNames: true}

	for name, tc := range map[string]struct {
		have    *config.Observer
		args    []string
		want    *config.Observer
		refused bool
	}{
		"nothing named keeps it":        {have: both, want: both},
		"nothing named keeps it off":    {},
		"--observe turns it on":         {args: []string{"--observe"}, want: &config.Observer{}},
		"--observe replaces options":    {have: both, args: []string{"--observe"}, want: &config.Observer{}},
		"an option implies --observe":   {args: []string{"--observe-loopback"}, want: &config.Observer{Loopback: true}},
		"an option written false":       {args: []string{"--observe-hide-names=false"}, want: &config.Observer{}},
		"--no-observe turns it off":     {have: both, args: []string{"--no-observe"}},
		"--observe=false turns it off":  {have: both, args: []string{"--observe=false"}},
		"--observe=false leaves it off": {args: []string{"--observe=false"}},
		"--no-observe=false keeps it":   {have: both, args: []string{"--no-observe=false"}, want: both},
		"--observe and --no-observe":    {args: []string{"--observe", "--no-observe"}, refused: true},
		"an option and --no-observe":    {args: []string{"--observe-loopback", "--no-observe"}, refused: true},
		"both options":                  {args: []string{"--observe-loopback", "--observe-hide-names"}, want: both},
		"--observe and an option, kept": {have: &config.Observer{HideNames: true}, args: []string{"--observe", "--observe-hide-names"}, want: &config.Observer{HideNames: true}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{Observer: tc.have}

			err := chooseObserver(cfg, observerFlags(t, tc.args...))

			switch {
			case tc.refused:
				if err == nil {
					t.Fatal("accepted")
				}
			case err != nil:
				t.Fatalf("refused: %v", err)
			case (cfg.Observer == nil) != (tc.want == nil) || (cfg.Observer != nil && *cfg.Observer != *tc.want):
				t.Errorf("observer %+v, want %+v", cfg.Observer, tc.want)
			}
		})
	}
}

// TestExportPointsTheCollectorAndKeepsTheRest: --export names where the records and the
// telemetry go and turns flows and metrics on, and keeps what conflux.json says besides --
// headers and TLS above all, which are credentials no command line takes.
func TestExportPointsTheCollectorAndKeepsTheRest(t *testing.T) {
	have := &config.Export{
		Headers: map[string]string{"authorization": "Basic x"},
		CACert:  &config.Secret{Path: "/etc/ssl/collector.pem"},
		Logs:    true,
	}

	cfg := &config.Config{Export: have}
	if err := chooseObserver(cfg, observerFlags(t, "--export", "collector.example:4317")); err != nil {
		t.Fatal(err)
	}

	e := cfg.Export
	if !e.Enabled || e.Endpoint != "collector.example:4317" || !e.Flows || !e.Metrics || !e.Logs || e.Insecure {
		t.Errorf("export %+v", e)
	}

	if e.Headers["authorization"] != "Basic x" || e.CACert == nil || e.CACert.Path != "/etc/ssl/collector.pem" {
		t.Errorf("the headers or TLS were lost: %+v", e)
	}

	if have.Endpoint != "" {
		t.Error("the configuration's own block was changed in place")
	}

	cfg = &config.Config{}
	if err := chooseObserver(cfg, observerFlags(t, "--export", "127.0.0.1:4317", "--export-insecure")); err != nil {
		t.Fatal(err)
	}

	if !cfg.Export.Insecure || !cfg.Exports() {
		t.Errorf("--export-insecure: %+v", cfg.Export)
	}

	if err := chooseObserver(&config.Config{}, observerFlags(t, "--export-insecure")); err == nil {
		t.Error("--export-insecure with no --export was accepted")
	}

	cfg = &config.Config{}
	if err := chooseObserver(cfg, observerFlags(t)); err != nil || cfg.Export != nil {
		t.Errorf("no --export, and the export became %+v (%v)", cfg.Export, err)
	}
}

// TestRecordsSayWhereTheyGo: a machine that observes is told where each record goes, and,
// with no collector, that they stay in the daemon and how to send them.
func TestRecordsSayWhereTheyGo(t *testing.T) {
	local := recordsNote(&config.Config{Observer: &config.Observer{}})
	if !strings.Contains(local, "inventory") || !strings.Contains(local, "--export HOST:PORT") {
		t.Errorf("with no export: %q", local)
	}

	sent := recordsNote(&config.Config{Observer: &config.Observer{},
		Export: &config.Export{Enabled: true, Endpoint: "c:4317", Flows: true}})
	if !strings.Contains(sent, "c:4317") || !strings.Contains(sent, "as it is made") {
		t.Errorf("with an export: %q", sent)
	}

	// An export without flows sends no records.
	if n := recordsNote(&config.Config{Observer: &config.Observer{},
		Export: &config.Export{Enabled: true, Endpoint: "c:4317", Metrics: true}}); n != local {
		t.Errorf("an export without flows: %q", n)
	}
}

// TestSwitchingAnAnchorToObservingIsConfirmed: off a terminal, only --yes stops an anchor,
// so a script that meant anchorctl's report does not.
func TestSwitchingAnAnchorToObservingIsConfirmed(t *testing.T) {
	if ui.IsTerminal() {
		t.Skip("this test's stdin is a terminal")
	}

	var errBuf bytes.Buffer

	old := ui.Errw
	ui.Errw = &errBuf

	t.Cleanup(func() { ui.Errw = old })

	if confirmObserving(config.ModeTUN, false) {
		t.Fatal("an anchor was stopped with nobody asked")
	}

	for _, want := range []string{"--yes", "conflux up --observe", "conflux anchorctl observe", "identity"} {
		if !strings.Contains(errBuf.String(), want) {
			t.Errorf("the refusal should say %q; it said:\n%s", want, errBuf.String())
		}
	}

	if !confirmObserving(config.ModeTUN, true) {
		t.Error("--yes did not say so")
	}
}

// rootOnLinux runs conflux observe, for the rest of the test, as root on a host with a capture,
// whoever runs the test on whichever host.
func rootOnLinux(t *testing.T) {
	t.Helper()

	was, elevated := hostOS, privcheck.Elevated
	hostOS, privcheck.Elevated = "linux", func() bool { return true }

	t.Cleanup(func() { hostOS, privcheck.Elevated = was, elevated })
}

// TestObserveChecksTheTaintBeforeItAsks: switching an anchor to observing is confirmed, and a
// --taint the held credential does not grant is refused before that, with nothing asked and
// nothing changed: an answer given only to be told a flag was wrong is an answer given twice.
func TestObserveChecksTheTaintBeforeItAsks(t *testing.T) {
	if ui.IsTerminal() {
		t.Skip("this test's stdin is a terminal")
	}

	rootOnLinux(t)

	d := pathstest.Dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeTUN, Taints: []string{"brhk-2mq9-tzva-6pjs-k4xe-nw7d-qf"}}); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveManifest(d, config.Envelope(base64.StdEncoding.EncodeToString([]byte(alphaDoc)))); err != nil {
		t.Fatal(err)
	}

	mgr := &fakeManager{d: d, restartErr: errStartsNothing}
	standInService(t, mgr)

	_, errOut, code := capture(t, "observe", "--taint", "other")

	if code != ExitError || !strings.Contains(errOut, `configured for the taint "other"`) {
		t.Errorf("conflux observe --taint other exited %d, saying:\n%s\nwant the taint refused", code, errOut)
	}

	if strings.Contains(errOut, "Observing alone stops it") {
		t.Errorf("conflux observe asked to stop the anchor before refusing the taint:\n%s", errOut)
	}

	if cfg, err := config.Load(d); err != nil || cfg.Mode != config.ModeTUN || len(mgr.installs) > 0 {
		t.Errorf("a refused observe changed something: %+v (%v), registered %d times", cfg, err, len(mgr.installs))
	}
}

// TestObservingAgainAsksNothing: a machine that already observes runs no anchor, so conflux
// observe run again stops none and asks nothing -- off a terminal, without --yes -- and goes
// on to start the observer as it is told to now.
func TestObservingAgainAsksNothing(t *testing.T) {
	if ui.IsTerminal() {
		t.Skip("this test's stdin is a terminal")
	}

	rootOnLinux(t)

	d := pathstest.Dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeObserve, Observer: &config.Observer{},
		Taints: []string{"brhk-2mq9-tzva-6pjs-k4xe-nw7d-qf"}}); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveManifest(d, config.Envelope(base64.StdEncoding.EncodeToString([]byte(alphaDoc)))); err != nil {
		t.Fatal(err)
	}

	standInService(t, &fakeManager{d: d, restartErr: errStartsNothing})

	_, errOut, code := capture(t, "observe", "--loopback")

	if code != ExitError || !strings.Contains(errOut, errStartsNothing.Error()) {
		t.Errorf("conflux observe on a machine observing exited %d, saying:\n%s\nwant the stand-in's Restart refused", code, errOut)
	}

	if strings.Contains(errOut, "Observing alone stops it") {
		t.Errorf("conflux observe asked to stop an anchor on a machine that runs none:\n%s", errOut)
	}

	if cfg, err := config.Load(d); err != nil || cfg.Observer == nil || !cfg.Observer.Loopback {
		t.Errorf("conflux observe --loopback saved %+v (%v), want the loopback observed", cfg, err)
	}
}

// TestObserveAsksBeforeItMints: a machine running an anchor with no credential and no taint
// configured has one minted for it by observe, and printed to be shared; asked to stop the
// anchor first, a "no" -- off a terminal, no --yes -- leaves nothing minted, printed or saved.
// A proxy machine's specs are dropped before the minted taint's configuration is checked.
func TestObserveAsksBeforeItMints(t *testing.T) {
	if ui.IsTerminal() {
		t.Skip("this test's stdin is a terminal")
	}

	rootOnLinux(t)

	for name, have := range map[string]*config.Config{
		"tun":   {Mode: config.ModeTUN},
		"proxy": {Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"}},
	} {
		t.Run(name, func(t *testing.T) {
			d := pathstest.Dirs(t)

			if err := config.Save(d, have); err != nil {
				t.Fatal(err)
			}

			mgr := &fakeManager{d: d, restartErr: errStartsNothing}
			standInService(t, mgr)

			out, errOut, code := capture(t, "observe")

			if code != ExitUsage || !strings.Contains(errOut, "Observing alone stops it") {
				t.Errorf("conflux observe exited %d, saying:\n%s\nwant the switch refused without --yes", code, errOut)
			}

			if strings.Contains(out, "Minted") {
				t.Errorf("a taint was minted and printed before the switch was refused:\n%s", out)
			}

			if cfg, err := config.Load(d); err != nil || cfg.Mode != have.Mode || len(cfg.Taints) > 0 || len(mgr.installs) > 0 {
				t.Errorf("a refused observe changed something: %+v (%v), registered %d times", cfg, err, len(mgr.installs))
			}

			// Said yes to, the taint is minted, and the proxy specs gone before it is checked.
			if _, errOut, code := capture(t, "observe", "--yes"); code != ExitError || !strings.Contains(errOut, errStartsNothing.Error()) {
				t.Errorf("conflux observe --yes exited %d, saying:\n%s\nwant the stand-in's Restart refused", code, errOut)
			}

			if cfg, err := config.Load(d); err != nil || cfg.Mode != config.ModeObserve || len(cfg.Taints) != 1 || len(cfg.Proxies) > 0 {
				t.Errorf("conflux observe --yes saved %+v (%v), want observing in one minted taint", cfg, err)
			}
		})
	}
}

// TestProxyTakesTheObserverFlags: conflux proxy's specs and flags come in any order, and
// --export takes a value while the observer's switches do not.
func TestProxyTakesTheObserverFlags(t *testing.T) {
	args := []string{"--export", "c:4317", "8080=127.0.0.1:3000", "--observe-loopback", "53/udp=127.0.0.1:53"}

	specs, flags, hint := newProxyFlags().split(args)
	if hint != "" {
		t.Fatalf("%q is not one of conflux proxy's", hint)
	}

	if want := []string{"8080=127.0.0.1:3000", "53/udp=127.0.0.1:53"}; !slices.Equal(specs, want) {
		t.Errorf("specs %v, want %v", specs, want)
	}

	if want := []string{"--export", "c:4317", "--observe-loopback"}; !slices.Equal(flags, want) {
		t.Errorf("flags %v, want %v", flags, want)
	}
}

// TestALapsedObserverPointsAtConfluxRenew: anchor's note names anchorctl's way to renew a lapsed
// observer credential, a file somebody holds; conflux renews the machine's own, and its command
// is the one shown.
func TestALapsedObserverPointsAtConfluxRenew(t *testing.T) {
	var out bytes.Buffer

	old := ui.Out
	ui.Out = &out

	t.Cleanup(func() { ui.Out = old })

	reportObserver(&config.Config{Observer: &config.Observer{}}, anchorctl.Observer{Running: true,
		Note: `af_packet, 2 flows held, 32 packets taken; credential lapsed at 2026-11-02T04:16:00Z; ` +
			`nothing observed is exported until "anchorctl observe -cred FILE" renews it`})

	if said := out.String(); !strings.Contains(said, `"conflux renew" renews it`) || strings.Contains(said, "anchorctl observe -cred") {
		t.Errorf("a lapsed observer is reported as:\n%s", said)
	}
}

// TestObserveEnrolsAsUpDoes: the observer runs under the machine's own credential, so conflux
// observe takes up's enrolment flags -- the API, and the taints, repeated -- for the machine
// it enrols when it holds none, and keeps them in conflux.json for the supervisor, which
// enrols.
func TestObserveEnrolsAsUpDoes(t *testing.T) {
	rootOnLinux(t)

	d := pathstest.Dirs(t)
	standInService(t, &fakeManager{d: d, restartErr: errStartsNothing})

	const api = "https://api-dev.veilnet.com.au"

	if _, errOut, code := capture(t, "observe", "--taint", "office", "--taint", "lab", "--api", api); code != ExitError ||
		!strings.Contains(errOut, errStartsNothing.Error()) {
		t.Fatalf("conflux observe exited %d, saying:\n%s\nwant the stand-in's Restart refused", code, errOut)
	}

	cfg, err := config.Load(d)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(cfg.Taints, []string{"office", "lab"}) {
		t.Errorf("conflux.json asks for taints %q, want the two given", cfg.Taints)
	}

	if cfg.APIBaseURL != api {
		t.Errorf("conflux.json names the API %q, want %q", cfg.APIBaseURL, api)
	}
}

// TestStatusReportsTheObserversCredential: a machine that only observes runs under its
// credential, and status reports it as it reports an anchor's -- until when it is valid, and
// the identity it runs as -- rather than as one kept for the next anchor.
func TestStatusReportsTheObserversCredential(t *testing.T) {
	d := pathstest.Dirs(t)

	if err := config.SaveManifest(d, config.Envelope(base64.StdEncoding.EncodeToString([]byte(alphaDoc)))); err != nil {
		t.Fatal(err)
	}

	const id = "anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq"

	notAfter := time.Now().Add(20 * 24 * time.Hour).UTC().Truncate(time.Second)
	cfg := &config.Config{Mode: config.ModeObserve, Observer: &config.Observer{}, Taints: []string{"brhk-2mq9-tzva-6pjs-k4xe-nw7d-qf"}}

	var out bytes.Buffer

	old := ui.Out
	ui.Out = &out

	t.Cleanup(func() { ui.Out = old })

	reportCredential(d, cfg, &config.State{AnchorID: id, NotAfter: notAfter})

	said := out.String()
	for _, want := range []string{"identity", id, "valid until " + notAfter.Format(time.RFC3339)} {
		if !strings.Contains(said, want) {
			t.Errorf("status should say %q; it said:\n%s", want, said)
		}
	}

	if strings.Contains(said, "kept for the next") {
		t.Errorf("status reports the observer's credential as kept for an anchor:\n%s", said)
	}
}
