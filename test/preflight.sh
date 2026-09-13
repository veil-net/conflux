#!/usr/bin/env bash
# What the machine has to give the container suites, said before anything is built.
#
# All four of these are properties of the runner rather than of this repository, and
# every one of them fails later and less legibly than it does here: no IPv6 arrives as
# a ping assertion eleven minutes in, no /dev/net/tun as an anchor that will not come
# up, no cgroup v2 as a container whose systemd never reaches "running". Printing them
# on a green run is the point as much as failing on a red one -- a suite that needs a
# privileged container should say what it was given.
set -euo pipefail

fail=0
note() { printf '  %-12s %s\n' "$1" "$2"; }
bad() { echo "::error::$1" >&2; fail=1; }

echo "what this runner gives the suite:"

if docker info >/dev/null 2>&1; then
  note docker "$(docker --version 2>&1)"
else
  bad "the Docker daemon does not answer; every suite here runs in containers"
fi

if [ -c /dev/net/tun ]; then
  note tun "/dev/net/tun present"
else
  bad "no /dev/net/tun; conflux up brings up a TUN interface and cannot without it"
fi

# A writable host cgroup mount is what lets systemd run as PID 1 in a container. The
# version is reported and not required: the image was measured booting in two seconds
# on a v1 host, so failing v1 here would reject a machine the suite works on. What
# cannot be worked around is the mount not being there at all.
if [ -d /sys/fs/cgroup ]; then
  if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    note cgroups "v2 (unified)"
  else
    note cgroups "v1 -- workable; the suite mounts it into the container either way"
  fi
else
  bad "no /sys/fs/cgroup to bind-mount; the test image boots systemd as PID 1 and needs it"
fi

# Every overlay address is an IPv6 ULA, and integration.sh pings one directly. A
# kernel without IPv6 brings the anchor up and fails the assertion much later.
if [ -e /proc/net/if_inet6 ]; then
  note ipv6 "present ($(wc -l < /proc/net/if_inet6) addresses on the host)"
else
  bad "this runner has no IPv6; every overlay address is an IPv6 ULA"
fi

# Not a requirement, only worth knowing: enrolment is an ordinary HTTPS POST, and a
# machine that cannot reach the API fails at the first `conflux up` rather than here.
if curl -fsS -o /dev/null --max-time 10 https://api.veilnet.com.au/docs 2>/dev/null; then
  note api "api.veilnet.com.au reachable"
else
  note api "api.veilnet.com.au NOT reachable -- enrolment will fail"
fi

exit $fail
