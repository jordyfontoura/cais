# Disposable systemd host with a real Caddy and PostgreSQL for tools/verify_integrations.py.
FROM debian:13
ENV container=docker
RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus openssh-server openssh-client sudo python3 passwd \
        util-linux curl ca-certificates caddy jq postgresql procps \
    && rm -rf /var/lib/apt/lists/* \
    && systemctl enable ssh caddy postgresql \
    && useradd -m -s /bin/bash alice \
    && useradd -m -s /bin/bash dev
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
