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
# RHEL), /usr/bin/conflux is linked to it, so `sudo conflux` finds it too. Where root's PATH,
# asked again with the link in place, still finds another conflux, the link is never reached:
# none is left, one made before included, and the other is named, to be removed before this
# script is run again.
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
      die "this is Windows. In 64-bit PowerShell, as Administrator:
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

# digest prints the SHA-256 of the file $1 with whichever tool this system has: sha256sum,
# shasum, or OpenBSD's sha256 -- never a function of that name, which `sha256 -q` here would call
# again rather than the tool.
digest() {
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

# rootpath sets found to where root, as `sudo` or `doas` runs it, finds conflux, or to nothing:
# sudo's secure_path, not this shell's PATH, is what `sudo conflux` searches. As root already --
# `curl … | sudo sh` included -- this shell's PATH is root's. Root is asked without a password
# first, which a run that has given one already holds, then, said first, through asroot, which
# asks for the password as the install step does: sudo and doas read it from the terminal, not
# stdin, so `curl … | sh` can type it too. It fails when root cannot be asked even so: the
# password refused, or no terminal to type it at.
rootpath() {
  if [ -z "$as" ]; then
    found=$(command -v conflux 2>/dev/null) || found=""
    return 0
  fi

  found=$("$as" -n sh -c 'command -v conflux || :' 2>/dev/null) && return 0

  say "$as is asked for root's PATH, to see whether '$as conflux' finds $exe."
  found=$(asroot sh -c 'command -v conflux || :')
}

# link makes /usr/bin/conflux a link to $exe where root's PATH would not find $exe, and keeps it
# only where root's PATH, asked again, finds $exe through it: a link it does not find $exe
# through, made now or by a run before, does nothing, so it goes and what root's PATH finds
# instead is named. The link is made, root's PATH asked with it in place, and the link taken
# back in one call as root, so a sudo or doas that asks for the password at every call asks
# once for all three. Each is compared as a file (-ef), through any link, never by how it is
# spelled. A /usr/bin/conflux that is not that link is left alone. A /usr/bin that cannot be
# written -- macOS's -- is said, and not a failure: conflux is installed all the same, as it is
# where root's PATH cannot be asked at all, or a link a run before made cannot be taken back,
# each of which is said too, rather than nothing. That link is said with the conflux root's PATH
# finds, where it finds one, to be removed before this script is run again.
link() {
  if ! rootpath; then
    say "" "Could not ask $as for root's PATH: run the installer as root to link conflux for sudo, or type $exe by its full path under sudo."
    return 0
  fi

  [ -n "$found" ] && [ "$found" -ef "$exe" ] && return 0

  if [ -L "$sudolink" ] && [ "$(readlink "$sudolink")" = "$exe" ]; then
    # A run before made it, and root's PATH, just asked, does not find $exe through it.
    if ! asroot rm -f "$sudolink"; then
      if [ -n "$found" ]; then
        say "" "Could not remove $sudolink, which root's PATH does not find $exe through, since it finds $found instead: remove $found and run the installer again, or type $exe by its full path under sudo."
      else
        say "" "Could not remove $sudolink, which root's PATH does not find $exe through: type $exe by its full path under sudo."
      fi
      return 0
    fi
  else
    # Why root's PATH does not find $exe: it leaves $dir out, or it finds another conflux first.
    why="root's PATH leaves $dir out"
    [ -n "$found" ] && why="root's PATH finds $found first"

    if [ -e "$sudolink" ] || [ -L "$sudolink" ]; then
      notours
      return 0
    fi

    # shellcheck disable=SC2016 # $1, $2 and $f are the root shell's own
    if ! found=$(asroot sh -c 'ln -s "$1" "$2" 2>/dev/null || exit 1
        f=$(command -v conflux) || f=""
        { [ -n "$f" ] && [ "$f" -ef "$1" ]; } || rm -f "$2"
        printf "%s\n" "$f"' sh "$exe" "$sudolink"); then
      say "" "Since $why, type $exe by its full path under sudo."
      return 0
    fi

    if [ -n "$found" ] && [ "$found" -ef "$exe" ]; then
      say "Linked $sudolink to it, since $why."
      return 0
    fi
  fi

  missed
}

# missed says why root's PATH, which finds $found, does not find $exe through $sudolink, the link
# to it: another conflux found in its place, to be removed before this script is run
# again, which decides afresh, linking $exe where root's PATH then needs the link and making none
# where it finds $exe without one; or, finding none, that directory left out, where only $exe's
# full path helps.
missed() {
  if [ -n "$found" ]; then
    say "" "Root's PATH finds $found instead: remove it and run the installer again, or type $exe by its full path under sudo."
  else
    say "" "Root's PATH leaves ${sudolink%/*} out too: type $exe by its full path under sudo."
  fi
}

# notours says that $sudolink is a file conflux did not make, and why root's PATH does not find
# $exe: where what it finds is that file -- through the link's own directory, however spelled,
# as a merged /bin is /usr/bin -- or another conflux first, that it is to be removed before this
# script is run again, which decides afresh, as missed says; where it finds none, $why, and the
# file to be removed before a run again the same way, or $exe's full path.
notours() {
  if [ -n "$found" ] && [ "${found%/*}" -ef "${sudolink%/*}" ]; then
    say "" "$sudolink is not conflux's, and root's PATH finds it rather than $exe: remove it and run the installer again, or type $exe by its full path under sudo."
  else
    say "" "$sudolink is not conflux's, and $why: remove it and run the installer again, or type $exe by its full path under sudo."
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

# cleanup, on the way out, removes the temporary directory and the copy beside the destination
# where one was left before it was renamed into place: not a conflux that runs here, or the run
# interrupted or refused a step. A copy root cannot be asked to remove is said, and the exit
# stays the one the script was leaving with.
cleanup() {
  rm -rf "$tmp"
  if [ -n "$new" ] && [ -e "$new" ]; then
    asroot rm -f "$new" || say "Could not remove $new: remove it as root." >&2
  fi
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
  new=
  trap cleanup EXIT
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
    have=$(digest "$exe") || exit 1
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

  got=$(digest "$tmp/conflux") || exit 1
  [ "$got" = "$want" ] || die "$asset's SHA-256 is $got, and SHA256SUMS says $want, so nothing was installed"

  [ -z "$as" ] || say "$dir is root's, so $as puts conflux there."

  # Beside its destination and renamed over it, so a conflux running from there keeps its file,
  # and run once before it replaces anything: the digest says these are the release's bytes,
  # this says they are a conflux that starts on this machine.
  new=$dir/.conflux.new
  asroot mkdir -p "$dir"
  asroot cp "$tmp/conflux" "$new"
  asroot chmod 0755 "$new"

  # cleanup removes the copy, once this is said.
  if ! now=$("$new" version </dev/null 2>&1) || [ "${now#conflux }" = "$now" ]; then
    die "the downloaded conflux does not run on this machine, so nothing was installed: $(printf '%s\n' "$now" | sed -n 1p)"
  fi

  asroot mv -f "$new" "$exe"

  say "Installed $exe: $(printf '%s\n' "$now" | sed -n 1p)."
  link
  next_steps
}

main "$@"
