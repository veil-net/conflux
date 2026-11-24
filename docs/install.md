# Installing

## Get a binary

### With the install script

```console
$ curl -fsSL https://raw.githubusercontent.com/veil-net/conflux/HEAD/install.sh | sh
```

On Windows, in 64-bit PowerShell as Administrator:

```powershell
irm https://raw.githubusercontent.com/veil-net/conflux/HEAD/install.ps1 | iex
```

`install.sh` picks the build for this machine from the `latest` release (`uname`, and on
a Mac the processor rather than the shell, so a shell under Rosetta still gets the
Apple-silicon build). It checks the download against the release's `SHA256SUMS`, runs it
once for its `version`, and only then renames it into place as `/usr/local/bin/conflux`,
through `sudo` (or `doas`) unless it runs as root. Where root's PATH under `sudo` does not find
it — it leaves `/usr/local/bin` out, as `secure_path` does on Fedora and RHEL, or finds another
conflux first — it also links `/usr/bin/conflux` to it, so `sudo conflux` runs it, and keeps the
link only where root's PATH, asked again with the link in place, finds it there. Making the
link, asking and taking it back are one call to `sudo` (or `doas`), so one that asks for the
password at every call, as `doas` without `persist` does, asks once for them. Where root's PATH,
asked again with the link in place, still finds another conflux, the link is never reached:
none is left, one an earlier run
made included, and the other is named, to be removed before `install.sh` is run again, or
conflux typed by its full path under `sudo`. A `/usr/bin/conflux` that is not its link is left
alone, and said: where root's PATH finds that file in conflux's place, or another conflux first,
that one is to be removed before `install.sh` is run again, and where it finds none, that file
is to be removed the same way, or conflux typed by its full path. Run again, it decides afresh: it links conflux where root's PATH then
needs the link, and makes none where that PATH finds conflux without one. Root's PATH is asked
whether the run installs conflux or finds the release's already in place: where `sudo` (or
`doas`) cannot answer without a password, as when nothing has asked for one yet, the script says
so and asks for it, on the terminal, as the install itself does, so `curl … | sh` works too;
where it cannot be asked even so, the password refused or no terminal to type it at, it says to
run the script as root to link conflux. What it cannot have removed, the password refused — an
earlier run's link, or a download it did not put in place — it says, and leaves. It names with
that link the conflux root's PATH finds, where it finds one, to be removed before `install.sh` is
run again. `install.ps1` does the same into
`C:\Program Files\conflux` and adds that to the machine's PATH. `conflux update` run where neither has installed conflux puts
it there the same way, the link or the PATH entry with it. The place is fixed, so that a
terminal finds conflux by name, `conflux update` knows what to replace and `conflux uninstall`
what to remove. Each installs the binary and nothing else: no boot service, no enrolment, no
network joined, until you run `conflux up`. Run again, each replaces an older conflux and
leaves the release's own alone.

One setting, given to `sh` rather than `curl`:

```console
$ curl -fsSL https://raw.githubusercontent.com/veil-net/conflux/HEAD/install.sh | CONFLUX_VERSION=1.0.0 sh
```

`CONFLUX_VERSION` names a release tag rather than `latest`. On Windows it is
`$env:CONFLUX_VERSION`, set before the `irm`.

`CONFLUX_VERSION=dev-latest` installs the newest dev build: the pre-release every merge into
conflux's `dev` replaces, with anchor's own dev build inside it, for trying what the next
release holds before it is released. Nothing installs it unless asked to by name. Its anchor is
pinned to the dev tree, which only `https://api-dev.veilnet.com.au` enrols in, so it is brought
up with `--api https://api-dev.veilnet.com.au`. `conflux update --dev` replaces it with the
newest dev build, once asked at a terminal; `conflux update` replaces it with the `latest`
release, whatever is installed ([commands.md](commands.md#conflux-update)).

The BSDs have no `curl` in the base system, and the script uses whatever downloader it
finds, so it can be fetched with theirs:

```console
$ fetch -qo - https://raw.githubusercontent.com/veil-net/conflux/HEAD/install.sh | sh      # FreeBSD
$ ftp -MVo - https://raw.githubusercontent.com/veil-net/conflux/HEAD/install.sh | sh      # OpenBSD
```

### By hand

Download the artifact for your platform from the releases page, verify it against
`SHA256SUMS`, and put it where the install script would: `/usr/local/bin/conflux`, or
`C:\Program Files\conflux\conflux.exe` on Windows. That is the file `conflux update`
replaces and `conflux uninstall` removes.

```console
$ sha256sum -c SHA256SUMS --ignore-missing
conflux-linux-amd64: OK
$ sudo install -m 0755 conflux-linux-amd64 /usr/local/bin/conflux
$ conflux version
```

**The boot service runs its own copy.** It runs as root, so the file it starts has to
be one only root can change: a service pointed at `~/Downloads/conflux` or
`C:\tools\conflux.exe` is one any program running as that user could swap for its own.
So `up`, `proxy`, `install`, `start` and `update` copy the conflux they were run as into
conflux's own directory — `/var/lib/.conflux/conflux` on Linux, `/var/db/.conflux/conflux` on the BSDs,
`/Library/Application Support/.conflux/conflux` on macOS,
`%ProgramData%\.conflux\conflux.exe` on Windows — and register that. `uninstall` removes
both: the copy, and the conflux you type.

Seven platforms are built: linux/amd64, linux/arm64, darwin/arm64, windows/amd64,
windows/arm64, freebsd/amd64, openbsd/amd64. Each is about 60 MB, because each
carries the `anchord` and `anchorctl` for its own platform inside it.

## Linux

Nothing else is needed. TUN is in the kernel, and `anchord` gets the `CAP_NET_ADMIN` it
needs for one from the supervisor, as an account of its own — see
[security.md](security.md#what-anchord-runs-as). That account, `conflux`, is made with
`useradd` (or busybox's `adduser`) the first time it is needed, and removed by
`conflux uninstall`.

On a host with SELinux enforcing, the extracted binaries under `/var/lib/.conflux/bin`
may be labelled `var_lib_t` and refused execution. conflux detects this and prints the
`semanage`/`restorecon` commands; see [troubleshooting.md](troubleshooting.md).

## macOS

**Apple Silicon only.** `darwin/arm64` is the one Mac artifact; there is no Intel
build, because no runner executes Intel macOS code and an untested artifact is worse
than an absent one. CI tests against the current macOS release, so that is the version
the build is known to work on.

`utun` is in the kernel and a root LaunchDaemon can open it, so there is no driver to
install.

Releases are not notarised, so macOS refuses to run one a browser downloaded until the
quarantine attribute is cleared. The install script downloads with `curl`, which sets no
such attribute, so this is only for a download by hand:

```console
$ xattr -d com.apple.quarantine conflux-darwin-arm64
```

## Windows

Run PowerShell as Administrator, for `install.ps1` and for conflux itself. `install.ps1` wants
64-bit PowerShell: a 32-bit one on 64-bit Windows, Windows PowerShell (x86), is given
`Program Files (x86)` for Program Files, where `conflux update` and `conflux uninstall` never
look, so the script refuses it before it downloads anything. TUN mode
additionally needs `wintun.dll`, which conflux downloads and verifies when it is first
needed — see [windows.md](windows.md). `conflux proxy` needs no driver at all.

## FreeBSD and OpenBSD

Everything works as on Linux, and the boot service is an rc script: `sysrc`-enabled
under `daemon(8)` on FreeBSD, `rcctl`-enabled on OpenBSD. See [service.md](service.md).

## Upgrading in place

```console
$ sudo conflux update
```

`update` replaces the installed conflux with the newest release, `latest`, or with `--dev`,
once asked at a terminal, the newest dev build, `dev-latest`, verified the same way, and moves
the boot service onto it: a running anchor is restarted on the new conflux, and a stopped one
starts on it next time. See [commands.md](commands.md#conflux-update).
Running the install script again, or replacing the binary by hand, replaces the binary
and leaves the service on the old one; restart it onto the new one:

```console
$ sudo install -m 0755 conflux-linux-amd64 /usr/local/bin/conflux
$ sudo conflux start
```

The new binary carries a different anchor pair, which extracts into its own directory
rather than over the one the running daemon has open, and `conflux start` copies it to
where the service runs it from and restarts the service onto it. Nothing is re-enrolled and the identity is untouched.

Until you run `conflux start`, `conflux status` reports:

```
  binaries     stale — conflux was upgraded; run "conflux start" to restart onto the new anchor
```

## Removing

```console
$ sudo conflux uninstall
```

`uninstall` removes the boot service, conflux's whole directory — the configuration and
the identity with it — the accounts `anchord` ran as, and conflux itself from where the
installer put it: nothing of conflux is left on the machine. See
[commands.md](commands.md#conflux-uninstall) for the whole list. There is no other copy of the
identity anywhere, so it asks first — see
[credentials.md](credentials.md).
