#!/bin/sh
# Install conflux: this machine's binary from a conflux release, checked against the release's
# SHA256SUMS, as /usr/local/bin/conflux, where a terminal finds it.
#
#   curl -fsSL https://raw.githubusercontent.com/veil-net/conflux/HEAD/install.sh | sh
#
# It installs the binary and nothing else. No boot service, no enrolment, no network joined:
# that is `sudo conflux up`, which is yours to run. Run again, it replaces an older conflux with
# the release's; `conflux update` does the same, and moves a running anchor onto it as well.
# `conflux uninstall` removes it again, with everything else conflux put on the machine.
#
# Where root's PATH under sudo leaves /usr/local/bin out (sudo's secure_path on Fedora and
# RHEL), /usr/bin/conflux is linked to it, so `sudo conflux` finds it too.
#
# One setting, given to sh rather than curl (`curl -fsSL … | CONFLUX_VERSION=1.0.0 sh`):
#
#   CONFLUX_VERSION      a release tag, such as 1.0.0, rather than latest
#
# POSIX sh, for macOS and the BSDs as well as Linux. Everything is in functions the last line
# calls, so a download cut short runs nothing.
set -eu

REPO=veil-net/conflux

say() { printf '%s\n' "$@"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

# platform sets os and arch to the names `make dist` gives this machine's build.
platform() {
  case $(uname -s) in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    FreeBSD) os=freebsd ;;
    OpenBSD) os=openbsd ;;
    MINGW* | MSYS* | CYGWIN*)
      die "this is Windows. In PowerShell, as Administrator:
  irm https://raw.githubusercontent.com/$REPO/HEAD/install.ps1 | iex" ;;
    *) die "conflux has no build for $(uname -s)" ;;
  esac

  case $(uname -m) in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) die "conflux has no build for $(uname -m) processors" ;;
  esac

  # A shell under Rosetta reports x86_64 on Apple silicon, where the arm64 build runs natively.
  if [ "$os" = darwin ] && [ "$arch" = amd64 ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ]; then
    arch=arm64
  fi
}

# download fetches the URL $1 into the file $2 with whichever client this system has: curl or
# wget, or the base system's own on the BSDs.
download() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  elif [ "$os" = freebsd ]; then
    fetch -q -o "$2" "$1"
  elif [ "$os" = openbsd ]; then
    ftp -MV -o "$2" "$1"
  else
    die "there is no curl or wget here to download with"
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  elif command -v sha256 >/dev/null 2>&1; then
    sha256 -q "$1"
  else
    die "there is no sha256sum, shasum or sha256 here to check the download with"
  fi
}

# elevator names what runs a command as root here, sudo or doas, and nothing for root itself.
elevator() {
  if [ "$(id -u)" = 0 ]; then
    return 0
  elif [ "$os" = openbsd ] && command -v doas >/dev/null 2>&1; then
    echo doas
  elif command -v sudo >/dev/null 2>&1; then
    echo sudo
  elif command -v doas >/dev/null 2>&1; then
    echo doas
  fi
}

# asroot runs a command as root: through sudo or doas, or directly when this is root already.
asroot() {
  if [ -n "$as" ]; then "$as" "$@"; else "$@"; fi
}

# firstline prints the first line of what conflux at $1 says to `version`.
firstline() {
  "$1" version </dev/null 2>/dev/null | sed -n 1p
}

# rootpath prints where root, as `sudo` or `doas` runs it, finds conflux: sudo's secure_path, not
# this shell's PATH, is what `sudo conflux` searches. As root already -- `curl … | sudo sh`
# included -- this shell's PATH is root's. It fails, printing nothing, when root cannot be asked
# without a password, which only the run that installed conflux has given.
rootpath() {
  if [ -z "$as" ]; then
    command -v conflux 2>/dev/null || true
    return 0
  fi

  "$as" -n true 2>/dev/null || return 1
  "$as" -n sh -c 'command -v conflux' 2>/dev/null || true
}

# link makes /usr/bin/conflux a link to $exe where root's PATH would not find $exe, and leaves
# a /usr/bin/conflux that is not that link alone. A /usr/bin that cannot be written -- macOS's --
# is said, and not a failure: conflux is installed all the same.
link() {
  found=$(rootpath) || return 0
  [ "$found" = "$exe" ] && return 0

  if [ -e "$sudolink" ] || [ -L "$sudolink" ]; then
    [ "$(readlink "$sudolink" 2>/dev/null)" = "$exe" ] && return 0
    say "" "$sudolink is not conflux's, so root's PATH, which leaves $dir out, finds that one first."
    return 0
  fi

  if asroot ln -s "$exe" "$sudolink" 2>/dev/null; then
    say "Linked $sudolink to it, since root's PATH leaves $dir out."
  else
    say "" "Root's PATH leaves $dir out, so type $exe by its full path under sudo."
  fi
}

# next_steps says what to run now: through $as, the sudo or doas that put conflux in place.
next_steps() {
  run=$as

  # Run as root by sudo or doas, as `curl … | sudo sh` does: whoever asked still needs it.
  if [ -z "$run" ]; then
    if [ -n "${SUDO_USER:-}" ]; then run=sudo; elif [ -n "${DOAS_USER:-}" ]; then run=doas; fi
  fi

  run=${run:+$run }conflux

  found=$(command -v conflux 2>/dev/null) || found=""
  if [ -n "$found" ] && [ "$found" != "$exe" ] && [ "$found" != "$sudolink" ]; then
    say "" "Your PATH finds another conflux first, at $found. This one is $exe."
  fi

  if [ -n "$old" ]; then
    say "" "It replaced $old. If this machine already runs an anchor, '$run start' moves it onto this one."
  fi

  say "" \
    "Nothing has been started. To put this machine on a VeilNet network, start a network," \
    "which prints the taint other machines join it with:" \
    "" \
    "  $run up" \
    "" \
    "or join the network a taint names:" \
    "" \
    "  $run up --taint TAINT" \
    "" \
    "See https://github.com/$REPO for the rest."
}

main() {
  platform

  tag=${CONFLUX_VERSION:-latest}
  dir=/usr/local/bin
  exe=$dir/conflux
  sudolink=/usr/bin/conflux
  asset=conflux-$os-$arch
  base=https://github.com/$REPO/releases/download/$tag

  tmp=$(mktemp -d "${TMPDIR:-/tmp}/conflux-install.XXXXXX") || die "could not make a temporary directory"
  # And the copy beside the destination, if one was interrupted before it was renamed into place.
  new=
  trap 'rm -rf "$tmp"; if [ -n "$new" ] && [ -e "$new" ]; then asroot rm -f "$new"; fi' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  download "$base/SHA256SUMS" "$tmp/SHA256SUMS" ||
    die "could not download $base/SHA256SUMS; is $tag a conflux release?"

  want=$(awk -v f="$asset" '$2 == f { print $1 }' "$tmp/SHA256SUMS")
  if [ -z "$want" ]; then
    die "conflux $tag has no build for $os/$arch, only for $(awk '{
      n = $2; sub(/^conflux-/, "", n); sub(/\.exe$/, "", n); sub(/-/, "/", n)
      printf "%s%s", s, n; s = ", " }' "$tmp/SHA256SUMS")"
  fi

  # Root, through sudo or doas, unless this is root: /usr/local/bin is root's.
  as=""
  if [ "$(id -u)" != 0 ]; then
    as=$(elevator)
    [ -n "$as" ] || die "conflux goes in $dir, which is root's, and there is no sudo or doas here: run this as root"
  fi

  old=""
  if [ -f "$exe" ]; then
    have=$(sha256 "$exe") || exit 1
    if [ "$have" = "$want" ]; then
      say "$exe is already the $tag release's conflux: $(firstline "$exe")"
      link
      next_steps
      return 0
    fi
    old=$(firstline "$exe") || old=""
  fi

  say "Downloading $asset from conflux's $tag release"
  download "$base/$asset" "$tmp/conflux" || die "could not download $base/$asset"

  got=$(sha256 "$tmp/conflux") || exit 1
  [ "$got" = "$want" ] || die "$asset's SHA-256 is $got, and SHA256SUMS says $want, so nothing was installed"

  [ -z "$as" ] || say "$dir is root's, so $as puts conflux there."

  # Beside its destination and renamed over it, so a conflux running from there keeps its file,
  # and run once before it replaces anything: the digest says these are the release's bytes,
  # this says they are a conflux that starts on this machine.
  new=$dir/.conflux.new
  asroot mkdir -p "$dir"
  asroot cp "$tmp/conflux" "$new"
  asroot chmod 0755 "$new"

  if ! now=$("$new" version </dev/null 2>&1) || [ "${now#conflux }" = "$now" ]; then
    asroot rm -f "$new"
    die "the downloaded conflux does not run on this machine, so nothing was installed: $(printf '%s\n' "$now" | sed -n 1p)"
  fi

  asroot mv -f "$new" "$exe"

  say "Installed $exe: $(printf '%s\n' "$now" | sed -n 1p)."
  link
  next_steps
}

main "$@"
