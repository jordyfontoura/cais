#!/bin/sh
set -eu
install -d -m 755 /run/sshd /etc/cais
install -m 644 /case/server.json /etc/cais/server.json
install -m 755 /build/cais-server /usr/local/bin/cais-server
install -m 755 /build/cais /usr/local/bin/cais
install -m 600 /case/client_key /run/cais-test-key
for account in operator outsider; do
  install -d -m 700 -o "$account" -g "$account" "/home/$account/.ssh"
  install -m 600 -o "$account" -g "$account" /case/client_key.pub "/home/$account/.ssh/authorized_keys"
done
for mode in polluted incompatible truncated mismatch failed-exit timeout trailing terminal terminal-error private-ok private-zero private-large private-truncated private-mismatch private-error private-failed-exit private-trailing; do
  install -m 755 /fake_peer.py "/usr/local/bin/cais-fake-$mode"
done
install -d -m 755 /run/cais-policy-tests
for mode in good operator writable owner parent-owner sticky; do
  install -d -m 755 "/run/cais-policy-tests/$mode"
  install -m 644 /case/server.json "/run/cais-policy-tests/$mode/policy.json"
done
chown operator /run/cais-policy-tests/operator/policy.json
chown outsider /run/cais-policy-tests/owner/policy.json
chown outsider /run/cais-policy-tests/parent-owner
chmod 775 /run/cais-policy-tests/writable
chmod 1777 /run/cais-policy-tests/sticky
ln -s good /run/cais-policy-tests/link
for mode in good operator writable owner parent-owner sticky link; do
  cat >"/usr/local/bin/cais-policy-$mode" <<EOF
#!/bin/sh
exec /usr/local/bin/cais-server --config /run/cais-policy-tests/$mode/policy.json
EOF
  chmod 755 "/usr/local/bin/cais-policy-$mode"
done
ssh-keygen -A >/dev/null 2>&1
cat >/etc/ssh/sshd_config <<'EOF'
Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM no
PubkeyAuthentication yes
StrictModes yes
AllowUsers operator outsider
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTTY no
AcceptEnv LANG
PidFile /run/sshd-test.pid
LogLevel ERROR
EOF
exec /usr/sbin/sshd -D -e
