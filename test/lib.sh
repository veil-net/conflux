# shellcheck shell=bash
# What the container suites share, sourced by test/service.sh and test/integration.sh: the
# heading each step prints, the container that boots systemd, and the reader of what its
# anchord runs with.

IMAGE=${IMAGE:-conflux-systemd-test}

# say prints a step's heading.
say() { printf '\n== %s\n' "$*"; }

# boot starts container NODE from $IMAGE, as both suites run it -- privileged, with the host's
# cgroups and its TUN device, which systemd as PID 1 and an anchor's interface need -- and gives
# systemd LOOKS looks, a second apart, to say it is running: 40 unless given. It fails, saying
# so, if systemd never does.
boot() { # NODE [LOOKS]
  docker rm -f "$1" >/dev/null 2>&1 || true
  docker run -d --name "$1" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --device /dev/net/tun "$IMAGE" >/dev/null
  for _ in $(seq "${2:-40}"); do
    [ "$(docker exec "$1" systemctl is-system-running 2>/dev/null)" = running ] && return 0
    sleep 1
  done
  echo "$1: systemd did not come up" >&2
  return 1
}

# creds is the uid, effective capabilities, no_new_privs and supplementary groups of the anchord
# running on container NODE from an executable matching PATTERN, a case pattern -- the installed
# conflux's pair unless given -- on one line: uid=U caps=C nnp=N groups=G,G. It fails when no
# such anchord runs.
creds() { # NODE [PATTERN]
  # shellcheck disable=SC2016 # expanded in the container, by its sh and awk
  docker exec "$1" sh -c '
    for p in /proc/[0-9]*; do
      case "$(readlink "$p/exe" 2>/dev/null)" in
        $0)
          exec awk '\''/^Uid:/ { u = $2 } /^CapEff:/ { c = $2 } /^NoNewPrivs:/ { n = $2 }
            /^Groups:/ { for (i = 2; i <= NF; i++) g = g (g ? "," : "") $i }
            END { printf "uid=%s caps=%s nnp=%s groups=%s\n", u, c, n, g }'\'' "$p/status" ;;
      esac
    done
    exit 1' "${2:-/var/lib/.conflux/bin/*/anchord}"
}
