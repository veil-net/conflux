//go:build !windows

package wintun

import (
	"context"

	"github.com/veil-net/conflux/internal/paths"
)

// Ensure is a no-op everywhere but Windows. Linux has tun in the kernel, macOS has
// utun, and the BSDs have tun devices; none of them needs a driver fetched.
func Ensure(context.Context, paths.Dirs) error { return nil }
