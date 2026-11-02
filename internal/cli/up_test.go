package cli

import (
	"bytes"
	"flag"
	"testing"

	"github.com/veil-net/conflux/internal/config"
)

// TestABooleanWrittenFalseIsItsNegation: the toggles are read by whether they were written,
// so --x=false must count as --no-x, never as --x. A script templating --serve-exit=$X with
// X=false would otherwise make the host an exit, the one setting conflux works hardest never
// to turn on by accident.
func TestABooleanWrittenFalseIsItsNegation(t *testing.T) {
	on := &config.Config{ServeExit: true, UseExit: true, LowLatency: true, Port: 4242}

	for name, tc := range map[string]struct {
		have    *config.Config
		args    []string
		want    config.Config
		refused bool
	}{
		"--serve-exit=false leaves it off":     {have: &config.Config{}, args: []string{"--serve-exit=false"}},
		"--serve-exit=false turns it off":      {have: on, args: []string{"--serve-exit=false"}, want: config.Config{UseExit: true, LowLatency: true, Port: 4242}},
		"--use-exit=false turns it off":        {have: on, args: []string{"--use-exit=false"}, want: config.Config{ServeExit: true, LowLatency: true, Port: 4242}},
		"--low-latency=false turns it off":     {have: on, args: []string{"--low-latency=false"}, want: config.Config{ServeExit: true, UseExit: true, Port: 4242}},
		"--no-port=false keeps the port":       {have: on, args: []string{"--no-port=false"}, want: *on},
		"--no-serve-exit=false keeps it":       {have: on, args: []string{"--no-serve-exit=false"}, want: *on},
		"--no-serve-exit=false names nothing":  {have: &config.Config{}, args: []string{"--no-serve-exit=false"}},
		"--serve-exit=true turns it on":        {have: &config.Config{}, args: []string{"--serve-exit=true"}, want: config.Config{ServeExit: true}},
		"--serve-exit and --serve-exit=false":  {have: &config.Config{}, args: []string{"--serve-exit", "--serve-exit=false"}},
		"--serve-exit=false and --serve-exit":  {have: &config.Config{}, args: []string{"--serve-exit=false", "--serve-exit"}, want: config.Config{ServeExit: true}},
		"--serve-exit and --no-serve-exit":     {have: &config.Config{}, args: []string{"--serve-exit", "--no-serve-exit"}, refused: true},
		"--use-exit=false and --no-use-exit":   {have: on, args: []string{"--use-exit=false", "--no-use-exit"}, want: config.Config{ServeExit: true, LowLatency: true, Port: 4242}},
		"--low-latency=true and --no-low-...":  {have: &config.Config{}, args: []string{"--low-latency=true", "--no-low-latency"}, refused: true},
		"nothing written keeps every setting":  {have: on, want: *on},
		"--no-low-latency=false and --low-...": {have: &config.Config{}, args: []string{"--no-low-latency=false", "--low-latency"}, want: config.Config{LowLatency: true}},
	} {
		t.Run(name, func(t *testing.T) {
			fs := flag.NewFlagSet("up", flag.ContinueOnError)
			fs.SetOutput(&bytes.Buffer{})

			port := fs.Uint("port", 0, "")
			lan := fs.String("lan-discovery", "auto", "")

			fs.Bool("no-port", false, "")
			fs.Bool("low-latency", false, "")
			fs.Bool("no-low-latency", false, "")
			registerExits(fs)

			if err := fs.Parse(tc.args); err != nil {
				t.Fatalf("parse %v: %v", tc.args, err)
			}

			cfg := *tc.have

			err := chooseTuning(&cfg, typedFlags(fs), *port, *lan)

			switch {
			case tc.refused:
				if err == nil {
					t.Fatal("accepted")
				}
			case err != nil:
				t.Fatalf("refused: %v", err)
			case cfg.ServeExit != tc.want.ServeExit || cfg.UseExit != tc.want.UseExit ||
				cfg.LowLatency != tc.want.LowLatency || cfg.Port != tc.want.Port:
				t.Errorf("serve-exit %v use-exit %v low-latency %v port %d; want %v %v %v %d",
					cfg.ServeExit, cfg.UseExit, cfg.LowLatency, cfg.Port,
					tc.want.ServeExit, tc.want.UseExit, tc.want.LowLatency, tc.want.Port)
			}
		})
	}
}
