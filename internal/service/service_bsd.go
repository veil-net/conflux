//go:build freebsd || openbsd

package service

import "fmt"

// The BSDs get no boot integration yet, and saying so plainly is better than a
// half-working one. Everything else works: pass-through, up, proxy, down and the
// supervisor in the foreground.
type unsupported struct{}

func newManager() (Manager, error) { return unsupported{}, nil }

func (unsupported) Name() string { return "conflux" }

func (unsupported) Install(exe string, args ...string) error {
	argv := exe
	for _, a := range args {
		argv += " " + a
	}

	return fmt.Errorf("%w.\n"+
		"  Register this with your init system by hand; the command to run is:\n"+
		"    %s\n"+
		"  On FreeBSD that is an rc.d script plus `sysrc conflux_enable=YES`;\n"+
		"  on OpenBSD, /etc/rc.d/conflux plus `rcctl enable conflux`.",
		ErrUnsupported, argv)
}

func (unsupported) Remove() error  { return nil }
func (unsupported) Start() error   { return ErrUnsupported }
func (unsupported) Stop() error    { return ErrUnsupported }
func (unsupported) Restart() error { return ErrUnsupported }

func (unsupported) Installed() (bool, error) { return false, nil }
func (unsupported) Running() (bool, error)   { return false, nil }

func (unsupported) Describe() string { return "no boot-service integration on this platform" }
