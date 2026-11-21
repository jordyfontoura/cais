#!/bin/sh
# Administrator steps for the disposable fixture. Runs as root inside the container.
set -eu

install -d -o root -g root -m 0755 /usr/local/libexec/cais /etc/cais
install -o root -g root -m 0755 /fixture/bin/cais-server /usr/local/bin/cais-server
install -o root -g root -m 0755 /fixture/bin/cais-broker /usr/local/libexec/cais/cais-broker
install -o root -g root -m 0755 /fixture/bin/cais /usr/local/bin/cais

# A stand-in identity provider for the forward-auth contract; see authgate.py.
install -o root -g root -m 0755 /fixture/authgate.py /usr/local/libexec/fixture-authgate.py
cat > /etc/systemd/system/fixture-authgate.service <<'EOF'
[Service]
User=nobody
ExecStart=/usr/bin/python3 /usr/local/libexec/fixture-authgate.py
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now fixture-authgate.service

# The administrator's own proxy configuration: one unrelated site, the login site, one
# access snippet and a single import line for the directory Cais manages.
cat > /etc/caddy/Caddyfile <<'EOF'
{
	local_certs
	skip_install_trust
}
(sso) {
	forward_auth 127.0.0.1:9091 {
		uri /verify
		copy_headers Remote-User
	}
}
login.example.org {
	reverse_proxy 127.0.0.1:9091
}
legacy.example.org {
	respond "legacy"
}
import /etc/caddy/cais/*.caddy
EOF

# A stand-in backup tool: it reports coverage from a marker the test controls.
cat > /usr/local/libexec/cais-backup-check <<'EOF'
#!/bin/sh
state=$(cat "/var/lib/fixture-backup/$1" 2>/dev/null || echo missing)
case "$state" in
	covered) echo 1700000000; exit 0 ;;
	missing) exit 3 ;;
	*) exit 1 ;;
esac
EOF
chmod 0755 /usr/local/libexec/cais-backup-check
install -d -m 0755 /var/lib/fixture-backup

cat > /etc/cais/server.json <<'EOF'
{
  "schema_version": 1,
  "host": {
    "paths": {
      "apps": "/srv/cais-apps",
      "state": "/var/lib/cais",
      "config": "/etc/cais-apps",
      "data": "/var/lib/cais-data"
    },
    "runtimes": { "python": "/usr/bin/python3" },
    "postgres": {},
    "caddy": {},
    "backup": { "check": "/usr/local/libexec/cais-backup-check" },
    "catalog": {}
  },
  "operators": {
    "alice": {
      "create": true,
      "database": true,
      "domain_suffixes": ["example.org"],
      "access_profiles": ["open", "members"],
      "backup": true
    }
  },
  "projects": {},
  "access_profiles": {
    "open": { "kind": "public" },
    "members": { "kind": "private", "provider": "sso", "snippet": "sso" },
    "unwired": { "kind": "private", "provider": "sso" }
  }
}
EOF
chmod 0644 /etc/cais/server.json
/usr/local/libexec/cais/cais-broker --init
systemctl reload caddy

# The one manual PostgreSQL step: include the Cais rules first in the cluster's HBA file.
hba=$(ls /etc/postgresql/*/main/pg_hba.conf)
sed -i '1i include_dir /etc/cais/postgres-hba' "$hba"
systemctl reload 'postgresql@*'

# The developer account holds synthetic operator and deployment keys.
su dev -c 'mkdir -p ~/keys && ssh-keygen -q -t ed25519 -N "" -f ~/keys/operator && ssh-keygen -q -t ed25519 -N "" -f ~/keys/deploy'
install -d -o alice -g alice -m 0700 /home/alice/.ssh
install -o alice -g alice -m 0600 /home/dev/keys/operator.pub /home/alice/.ssh/authorized_keys
printf '127.0.0.1 %s\n' "$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)" > /home/dev/known_hosts
chown dev:dev /home/dev/known_hosts
