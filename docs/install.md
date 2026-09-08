# Installing

## Get a binary

Download the artifact for your platform from the releases page, verify it against
`SHA256SUMS`, and put it somewhere that survives a reboot.

```console
$ sha256sum -c SHA256SUMS --ignore-missing
conflux-linux-amd64: OK
$ sudo install -m 0755 conflux-linux-amd64 /usr/local/bin/conflux
$ conflux version
```

**Install it before registering the service.** The unit records the path it was
installed from, so a boot service pointed at `~/Downloads/conflux` breaks the day that
file is cleaned up or the home directory is not mounted at boot. conflux warns when it
notices this, but the fix is to move the binary first.

Seven platforms are built: linux/amd64, linux/arm64, darwin/arm64, windows/amd64,
windows/arm64, freebsd/amd64, openbsd/amd64. Each is about 45–50 MB, because each
carries the `anchord` and `anchorctl` for its own platform inside it.

## Linux

Nothing else is needed. TUN is in the kernel, and `conflux up` asks for it through the
service's `CAP_NET_ADMIN`.

On a host with SELinux enforcing, the extracted binaries under `/var/lib/conflux/bin`
may be labelled `var_lib_t` and refused execution. conflux detects this and prints the
`semanage`/`restorecon` commands; see [troubleshooting.md](troubleshooting.md).

## macOS

**Apple Silicon only.** `darwin/arm64` is the one Mac artifact; there is no Intel
build, because no runner executes Intel macOS code and an untested artifact is worse
than an absent one. CI tests against the current macOS release, so that is the version
the build is known to work on.

`utun` is in the kernel and a root LaunchDaemon can open it, so there is no driver to
install.

If macOS refuses to run a downloaded binary, clear the quarantine attribute:

```console
$ xattr -d com.apple.quarantine conflux-darwin-arm64
```

Signed and notarised builds are published where the signing secrets are configured; an
unsigned one needs the line above.

## Windows

Run PowerShell as Administrator. TUN mode additionally needs `wintun.dll`, which
conflux downloads and verifies on the first `conflux up` — see
[windows.md](windows.md). `conflux proxy` needs no driver at all.

## FreeBSD and OpenBSD

`up`, `proxy`, `down`, `status` and pass-through all work. There is no boot-service
integration; `conflux install` says so and names `conflux serve` as the command to
register with your init system. See [service.md](service.md).

## Upgrading in place

Replace the binary and re-register:

```console
$ sudo install -m 0755 conflux-linux-amd64 /usr/local/bin/conflux
$ sudo conflux start
```

The new binary carries a different anchor pair, which extracts into its own directory
rather than over the one the running daemon has open, and `conflux start` restarts the
service onto it. Nothing is re-enrolled and the identity is untouched.

Until you run `conflux start`, `conflux status` reports:

```
  binaries     stale — conflux was upgraded; run "conflux start" to restart onto the new anchor
```

## Removing

```console
$ sudo conflux uninstall
$ sudo rm /usr/local/bin/conflux
```

`uninstall` removes the boot service, the configuration and the identity. There is no
other copy of the identity anywhere, so it asks first — see
[credentials.md](credentials.md).
