//go:build linux

package libexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/veil-net/conflux/anchor"
)

// InMemory is this build's pair in sealed memory files, for an ephemeral run, which puts no
// binary on disk. Each is run by its /proc/self/fd name, which names the file in whichever
// process opens it: conflux, or a child between fork and exec, after the drop to another
// account as well, since a process may always read its own descriptors. The descriptors are
// close-on-exec, so nothing conflux starts inherits them -- the kernel opens the file it is
// to run before it closes them -- and held for as long as this process runs, made once.
//
// ErrNoMemoryExec where the kernel will not run one: vm.memfd_noexec=2, or a policy --
// SELinux's among them -- that refuses it, or no /proc.
func InMemory() (*Tools, error) {
	ctl, err := memAnchorctl()
	if err != nil {
		return nil, err
	}

	d, err := memAnchord()
	if err != nil {
		return nil, err
	}

	return &Tools{Anchord: d, Anchorctl: ctl, SetID: anchor.SetID()}, nil
}

// AnchorctlInMemory is InMemory's anchorctl alone, for what only asks: a reader of an
// ephemeral run, and help.
func AnchorctlInMemory() (*Tools, error) {
	ctl, err := memAnchorctl()
	if err != nil {
		return nil, err
	}

	return &Tools{Anchorctl: ctl, SetID: anchor.SetID()}, nil
}

var (
	memAnchorctl = sync.OnceValues(func() (string, error) {
		path, err := memfd("anchorctl", anchor.Anchorctl())
		if err != nil {
			return "", err
		}

		// Run once, as an extraction is: what refuses to run it says so here, and the caller
		// puts the pair on disk instead, rather than finding out at anchord's start.
		ctx, cancel := context.WithTimeout(context.Background(), smokeTimeout)
		defer cancel()

		if out, err := exec.CommandContext(ctx, path, "help").CombinedOutput(); err != nil {
			return "", fmt.Errorf("%w: anchorctl from memory: %v %s", ErrNoMemoryExec, err, strings.TrimSpace(string(out)))
		}

		return path, nil
	})

	memAnchord = sync.OnceValues(func() (string, error) { return memfd("anchord", anchor.Anchord()) })

	// held keeps every memory file's *os.File reachable, so no finalizer closes a descriptor a
	// path names.
	held []*os.File
)

// memfd is a sealed, executable memory file holding content, by the name a process sees it at.
func memfd(name string, content []byte) (string, error) {
	if !anchor.Supported {
		return "", fmt.Errorf("%w: this build carries no anchor binaries", ErrNoMemoryExec)
	}

	const flags = unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING

	// MFD_EXEC asks for an executable one where vm.memfd_noexec makes them sealed against it by
	// default; a kernel before 6.3 does not know it, and runs every memory file.
	fd, err := unix.MemfdCreate(name, flags|unix.MFD_EXEC)
	if errors.Is(err, unix.EINVAL) {
		fd, err = unix.MemfdCreate(name, flags)
	}

	if err != nil {
		return "", fmt.Errorf("%w: memfd_create: %v", ErrNoMemoryExec, err)
	}

	f := os.NewFile(uintptr(fd), name)

	prefault(content)

	if _, err := f.Write(content); err != nil {
		_ = f.Close()

		return "", fmt.Errorf("write %s into memory: %w", name, err)
	}

	const seals = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		_ = f.Close()

		return "", fmt.Errorf("seal %s in memory: %w", name, err)
	}

	held = append(held, f)

	return "/proc/self/fd/" + strconv.Itoa(fd), nil
}
