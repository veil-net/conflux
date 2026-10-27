# A container that boots systemd, so the boot service can actually be tested.
#
# This is the only way to exercise the part of conflux that matters most and is
# hardest to check: that a machine which was up before is up again afterwards, with
# nothing typed. Restarting the container is the reboot.
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv ca-certificates iproute2 iputils-ping dbus \
    && rm -rf /var/lib/apt/lists/* \
    # A container needs none of these, and several of them fail noisily without a
    # real machine underneath.
    && find /etc/systemd/system /lib/systemd/system \
        -path '*.wants/*' \
        \( -name '*getty*' -o -name '*udev*' -o -name '*console*' \
           -o -name 'systemd-timesyncd*' -o -name 'systemd-logind*' \
           -o -name 'systemd-modules-load*' \) \
        -exec rm -f {} \; \
    && rm -f /lib/systemd/system/multi-user.target.wants/* \
    && ln -sf /lib/systemd/system/dbus.service /etc/systemd/system/multi-user.target.wants/dbus.service

# /dev/net/tun as a stock host's udev leaves it, whatever the runner's own is: anchord makes
# a TUN as conflux's own account with CAP_NET_ADMIN, and only root can open a device of
# root's. At every boot, so a restarted container -- the reboot -- keeps it.
RUN printf 'z /dev/net/tun 0666 root root -\n' > /etc/tmpfiles.d/tun.conf

COPY conflux /usr/local/bin/conflux

STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
