package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/ui"
)

// quiet captures what the prompt writes and, by default, hands it /dev/null to read
// from. A test that reaches the prompt without meaning to then fails with the
// refusal rather than waiting for an answer that is not coming.
func quiet(t *testing.T) *bytes.Buffer {
	t.Helper()

	var out bytes.Buffer

	oldOut, oldErr := ui.Out, ui.Errw
	ui.Out, ui.Errw = &out, &out

	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}

	ui.SetIn(null)

	t.Cleanup(func() {
		ui.Out, ui.Errw = oldOut, oldErr

		ui.SetIn(os.Stdin)
		null.Close()
	})

	return &out
}

// TestChooseIPv4RefusesRatherThanAnswerForItself is the regression test for a
// machine that came up without the address nobody was asked for.
//
// /dev/null is a character device, so the old terminal check called it a person: up
// printed the question into it, read the end-of-file that came back, and carried on
// IPv6-only without a word. That is the stdin of every service, cron job,
// cloud-init run and `ssh host 'conflux up'` there is.
func TestChooseIPv4RefusesRatherThanAnswerForItself(t *testing.T) {
	out := quiet(t)

	got, err := chooseIPv4(&config.Config{}, "", false, false)
	if err == nil {
		t.Fatalf("chooseIPv4() with %s for stdin = %q, nil; want a refusal", os.DevNull, got)
	}

	if !strings.Contains(err.Error(), "--ipv4") || !strings.Contains(err.Error(), "--no-ipv4") {
		t.Errorf("chooseIPv4() error = %q, want both flags named", err)
	}

	if out.Len() != 0 {
		t.Errorf("asked a question nobody could answer: %q", out.String())
	}
}

// TestPromptIPv4EndOfInputIsNotAnAnswer is the same rule one layer down, for a
// terminal that goes away mid-question: a closed session, or a Ctrl-D.
//
// Blank is an answer and says what it means. End of input is the absence of one,
// and an overlay address is not conflux's to pick.
func TestPromptIPv4EndOfInputIsNotAnAnswer(t *testing.T) {
	quiet(t)
	ui.SetIn(strings.NewReader(""))

	if got, err := promptIPv4(); err == nil {
		t.Fatalf("promptIPv4() on empty input = %q, nil; want a refusal", got)
	}
}

// TestPromptIPv4BlankIsIPv6Only: the one silent answer, typed on purpose by
// somebody who was shown what blank means.
func TestPromptIPv4BlankIsIPv6Only(t *testing.T) {
	out := quiet(t)
	ui.SetIn(strings.NewReader("\n"))

	got, err := promptIPv4()
	if err != nil || got != "" {
		t.Fatalf("promptIPv4() on a blank line = %q, %v; want %q, nil", got, err, "")
	}

	if !strings.Contains(out.String(), "IPv6-only") {
		t.Errorf("a blank answer went unacknowledged: %q", out.String())
	}
}

// TestPromptIPv4RetriesAfterAMalformedAnswer: the correction is read, not lost with
// whatever the last reader had already buffered behind it.
func TestPromptIPv4RetriesAfterAMalformedAnswer(t *testing.T) {
	out := quiet(t)
	ui.SetIn(strings.NewReader("10.128.0.7\n10.128.0.7/24\n"))

	got, err := promptIPv4()
	if err != nil || got != "10.128.0.7/24" {
		t.Fatalf("promptIPv4() = %q, %v; want %q, nil", got, err, "10.128.0.7/24")
	}

	if !strings.Contains(out.String(), "is an address without a prefix length") {
		t.Errorf("the malformed answer was not explained: %q", out.String())
	}
}

// TestIPv4FlagsContradict: --uplink, --peers, --taint and --port all refuse their
// own negation rather than picking a winner, and this is the pair where picking one
// would drop an address somebody typed.
func TestIPv4FlagsContradict(t *testing.T) {
	quiet(t)

	if got, err := chooseIPv4(&config.Config{}, "10.128.0.7/24", true, false); err == nil {
		t.Fatalf("chooseIPv4() with both flags = %q, nil; want a refusal", got)
	}
}

// TestChooseIPv4WithoutAPrompt covers every path that has its answer already: the
// prompt is for a machine being set up, not for one being re-run.
func TestChooseIPv4WithoutAPrompt(t *testing.T) {
	quiet(t)

	for name, c := range map[string]struct {
		cfg       config.Config
		flag      string
		none      bool
		alreadyUp bool
		want      string
		wrong     bool
	}{
		"the flag decides":               {flag: "10.128.0.7/24", want: "10.128.0.7/24"},
		"a configured address is kept":   {cfg: config.Config{IPv4: "10.128.0.9/24"}, want: "10.128.0.9/24"},
		"the flag overrides what is set": {cfg: config.Config{IPv4: "10.128.0.9/24"}, flag: "10.128.0.7/24", want: "10.128.0.7/24"},
		"--no-ipv4 clears what is set":   {cfg: config.Config{IPv4: "10.128.0.9/24"}, none: true, want: ""},
		"--no-ipv4 on a fresh machine":   {none: true, want: ""},
		"an IPv6-only machine re-run":    {alreadyUp: true, want: ""},
		"a bare address is refused":      {flag: "10.128.0.7", wrong: true},
		"a network address is refused":   {flag: "10.128.0.0/24", wrong: true},
		"the prefix has to be there":     {flag: "not an address", wrong: true},
	} {
		cfg := c.cfg

		got, err := chooseIPv4(&cfg, c.flag, c.none, c.alreadyUp)

		switch {
		case c.wrong && err == nil:
			t.Errorf("%s: chooseIPv4() = %q, nil; want a refusal", name, got)
		case !c.wrong && err != nil:
			t.Errorf("%s: chooseIPv4() = error %v", name, err)
		case !c.wrong && got != c.want:
			t.Errorf("%s: chooseIPv4() = %q, want %q", name, got, c.want)
		}
	}
}

// TestChooseIPv4AsksAMachineThatHasNeverAnswered is the other side of the rule that
// keeps an IPv6-only machine IPv6-only: an empty address is an answer only where
// there was a question.
//
// A proxy machine has no interface to put an address on, so it was never asked --
// converting it with `conflux up` is the first time the question arises, and it is
// asked rather than answered with the silence of a field that could not have been
// filled in.
func TestChooseIPv4AsksAMachineThatHasNeverAnswered(t *testing.T) {
	quiet(t)

	cfg := config.Config{Mode: config.ModeTUN, Taints: []string{"a-b-c-d"}}

	if got, err := chooseIPv4(&cfg, "", false, false); err == nil {
		t.Fatalf("chooseIPv4() converting a proxy machine = %q, nil; want the question asked", got)
	}
}
