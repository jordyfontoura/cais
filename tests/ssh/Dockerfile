FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server python3 python3-jsonschema \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/ssh/ssh_host_* \
    && useradd --create-home --gid operator --password '*' operator \
    && useradd --create-home --password '*' outsider
COPY tests/ssh/entrypoint.sh /entrypoint.sh
COPY tests/ssh/fake_peer.py /fake_peer.py
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
