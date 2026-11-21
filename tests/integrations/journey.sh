#!/bin/bash
# Developer journey for the disposable fixture. Runs as the unprivileged `dev` account;
# `sudo` here stands for separate administrator actions and observations.
set -euo pipefail
cd "$HOME"
CA="$HOME/ca.crt"
JAR="$HOME/cookies.txt"
CONFIG="$HOME/client.json"
BROKER=/usr/local/libexec/cais/cais-broker

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }
expect() { [ "$2" = "$3" ] && pass "$1" || fail "$1 (expected '$3', got '$2')"; }

cat > "$CONFIG" <<EOF
{ "schema_version": 1, "targets": {
  "operator": { "ssh": "alice@127.0.0.1", "server_path": "/usr/local/bin/cais-server",
    "known_hosts": "./known_hosts", "identity_file": "./keys/operator" } } }
EOF
add_deploy_target() { # name user
  jq --arg n "$1" --arg u "$2" '.targets[$n] = (.targets.operator | .ssh = ($u + "@127.0.0.1") | .identity_file = "./keys/deploy")' "$CONFIG" > "$CONFIG.new"
  mv "$CONFIG.new" "$CONFIG"
}
op() { cais "$@" --target operator --config "$CONFIG" --json; }
# Exit code of a command; its JSON result is kept in last.json.
rc() { set +e; "$@" > "$HOME/last.json" 2>/dev/null; local c=$?; set -e; echo "$c"; }
status() { op status "$1" > "$HOME/$1.status.json"; }
field() { jq -r "$2" "$HOME/$1.status.json"; }

# Every fixture hostname resolves to this host. Certificates are issued just after a
# reload, so requests are retried briefly.
fetch() { curl --silent --max-time 5 --cacert "$CA" --connect-to ::127.0.0.1: "$@"; }
http() { # url [curl args] -> status code, 000 when the host is not served
  local result=000
  for _ in 1 2 3 4 5 6 7 8; do
    result=$(fetch --output /dev/null --write-out '%{http_code}' "$@" || true)
    [ "$result" != 000 ] && break
    sleep 0.5
  done
  echo "$result"
}
page() { # url [curl args] -> body
  local result=""
  for _ in 1 2 3 4 5 6 7 8; do
    result=$(fetch "$@" || true)
    [ -n "$result" ] && break
    sleep 0.5
  done
  echo "$result"
}
caddyfile_sum() { sha256sum /etc/caddy/Caddyfile | cut -d' ' -f1; }

project() { # name json
  mkdir -p "$HOME/$1/dist"; printf '%s\n' "$2" > "$HOME/$1/cais.json"
}
http_project() { # name extra-json-members
  project "$1" "{\"schema_version\":1,\"project\":\"$1\",\"artifact\":{\"directory\":\"./dist\",\"publish\":[\"app.py\"]},
    \"app\":{\"kind\":\"http\",\"runtime\":\"python\",\"entrypoint\":\"app.py\",\"health\":\"/health\"}${2:+,$2}}"
  cp /fixture/app.py "$HOME/$1/dist/app.py"
}
static_project() { # name content extra-json-members
  project "$1" "{\"schema_version\":1,\"project\":\"$1\",\"artifact\":{\"directory\":\"./dist\",\"publish\":[\"public\"]},
    \"app\":{\"kind\":\"static\",\"public\":\"public\"}${3:+,$3}}"
  mkdir -p "$HOME/$1/dist/public"; echo "$2" > "$HOME/$1/dist/public/index.html"
}
exposure() { echo "\"exposure\":{\"host\":\"$1\",\"path\":\"$2\",\"access_profile\":\"$3\"${4:+,$4}}"; }
register() { # name
  op plan --file "$HOME/$1/cais.json" > "$HOME/$1.plan.json"
  op register --file "$HOME/$1/cais.json" --plan "$HOME/$1.plan.json" --deploy-public-key "$HOME/keys/deploy.pub" > "$HOME/$1.status.json"
  add_deploy_target "$1-deploy" "$(field "$1" .data.deploy_user)"
}
package() { # name
  rm -f "$HOME/$1.tar.gz"
  cais package --file "$HOME/$1/cais.json" --output "$HOME/$1.tar.gz" --json > /dev/null
}
publish() { # name -> exit code of the deployment
  package "$1"; status "$1"
  rc cais deploy --file "$HOME/$1/cais.json" --artifact "$HOME/$1.tar.gz" --expected "$HOME/$1.status.json" \
    --target "$1-deploy" --config "$CONFIG" --json
}
deploy() { [ "$(publish "$1")" = 0 ] || fail "deployment of $1"; status "$1"; }
apply() { status "$1"; op proxy-apply "$1" --expected "$HOME/$1.status.json" > /dev/null; status "$1"; }

sudo cat /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt > "$CA"
before=$(caddyfile_sum)
expect "capabilities advertise proxy management" "$(op capabilities | jq -r .data.proxy_management)" true
expect "unrelated administrator route answers before any change" "$(page https://legacy.example.org/)" legacy

# --- Private HTTP application behind a login provider ---------------------------------
http_project api "$(exposure api.example.org / members),\"data\":{\"preserve\":[\"uploads\"],\"backup\":[\"uploads\"]}"
register api
deploy api
expect "registration alone publishes no route" "$(field api .data.route.state)" absent
expect "unpublished host is not served" "$(http https://api.example.org/health)" 000
apply api
expect "route state is published" "$(field api .data.route.state)" published
expect "route file imports only the administrator snippet" "$(grep -c 'import sso' /etc/caddy/cais/api.caddy)" 1
expect "an anonymous request is redirected, not served" "$(http https://api.example.org/whoami)" 302
expect "the redirect goes to the provider's login with the original address" \
  "$(fetch --output /dev/null --write-out '%{redirect_url}' https://api.example.org/whoami)" \
  "https://login.example.org/login?rd=https%3A%2F%2Fapi.example.org%2Fwhoami"
expect "a client cannot assert an identity without a session" \
  "$(http https://api.example.org/whoami -H 'Remote-User: admin')" 302
expect "login sets a session cookie and returns to the application" \
  "$(page https://api.example.org/whoami --location --cookie-jar "$JAR" --cookie "$JAR")" "path=/whoami user=demo"
expect "the session cookie is scoped to the parent domain and secure" \
  "$(grep -c -E '^#HttpOnly_\.example\.org.*TRUE.*fixture_session' "$JAR")" 1
expect "a session is honoured on later requests without a new login" \
  "$(http https://api.example.org/whoami --cookie "$JAR")" 200
expect "the provider's identity replaces one supplied by the client" \
  "$(page https://api.example.org/whoami --cookie "$JAR" -H 'Remote-User: admin')" "path=/whoami user=demo"

# --- Public static site ----------------------------------------------------------------
static_project site "static fixture" "$(exposure www.example.org / open)"
register site
deploy site
apply site
expect "public static site is served over HTTPS" "$(page https://www.example.org/)" "static fixture"
expect "a public route asks for no login" "$(http https://www.example.org/)" 200
expect "static site stays unreadable to other accounts" "$(cat /srv/cais-apps/site/current/public/index.html 2>/dev/null || echo denied)" denied

# --- Path prefixes ---------------------------------------------------------------------
static_project docs "docs fixture" "$(exposure portal.example.org /docs open)"
register docs; deploy docs; apply docs
expect "a static site is served under its prefix" "$(page https://portal.example.org/docs/)" "docs fixture"
expect "the bare prefix redirects to its directory" "$(http https://portal.example.org/docs)" 308
expect "paths outside the prefix are answered with 404" "$(http https://portal.example.org/)" 404
expect "a sibling path sharing the prefix text is outside it" "$(http https://portal.example.org/docsearch)" 404

http_project keep "$(exposure keep.example.org /api/v1 open)"
register keep; deploy keep; apply keep
expect "an application receives its full path by default" \
  "$(page https://keep.example.org/api/v1/items)" "path=/api/v1/items user=-"
expect "an application under a prefix is not reachable outside it" "$(http https://keep.example.org/health)" 404

http_project strip "$(exposure strip.example.org /api open '"strip_prefix":true')"
register strip; deploy strip; apply strip
expect "a stripped prefix is removed before the application" \
  "$(page https://strip.example.org/api/items)" "path=/items user=-"

# --- Collisions and refusals -----------------------------------------------------------
static_project twin twin "$(exposure api.example.org / open)"
op plan --file "$HOME/twin/cais.json" > "$HOME/twin.plan.json"
expect "a hostname already used by another project is refused" \
  "$(rc op register --file "$HOME/twin/cais.json" --plan "$HOME/twin.plan.json" --deploy-public-key "$HOME/keys/deploy.pub")" 6
static_project share share "$(exposure portal.example.org /other open)"
op plan --file "$HOME/share/cais.json" > "$HOME/share.plan.json"
expect "a second project cannot take another prefix of a claimed hostname" \
  "$(rc op register --file "$HOME/share/cais.json" --plan "$HOME/share.plan.json" --deploy-public-key "$HOME/keys/deploy.pub")" 6
static_project loose loose "$(exposure loose.example.org / unwired)"
expect "a profile the operator was not delegated is denied" "$(rc op plan --file "$HOME/loose/cais.json")" 3
static_project away away "$(exposure away.example.net / open)"
expect "a hostname outside the delegated suffix is denied" "$(rc op plan --file "$HOME/away/cais.json")" 3
static_project badpath badpath "$(exposure bad.example.org '/docs/*' open)"
expect "a prefix with proxy syntax is rejected locally" "$(rc cais validate --file "$HOME/badpath/cais.json" --json)" 2

# A project claiming the administrator's hand-written site must not break the proxy.
static_project clash clash "$(exposure legacy.example.org / open)"
register clash
expect "a route the proxy rejects fails the operation" "$(rc op proxy-apply clash --expected "$HOME/clash.status.json")" 7
expect "the rejected route file is not left behind" "$(ls /etc/caddy/cais | grep -c clash || true)" 0
status clash
expect "the failure is recorded" "$(field clash .data.last_operation.state)" failed
expect "the administrator route still answers" "$(page https://legacy.example.org/)" legacy
expect "published routes survive the rejected change" "$(http https://api.example.org/whoami --cookie "$JAR")" 200
expect "the proxy stayed active" "$(systemctl is-active caddy)" active

# --- Drift, removal and republication --------------------------------------------------
sudo sh -c 'echo "# edited by hand" >> /etc/caddy/cais/api.caddy'
status api
expect "a hand-edited route file is reported as stale" "$(field api .data.route.state)" stale
apply api
expect "applying again restores the managed route" "$(field api .data.route.state)" published
op proxy-remove api --expected "$HOME/api.status.json" > /dev/null
status api
expect "a removed route is absent" "$(field api .data.route.state)" absent
expect "a removed route is no longer served" "$(http https://api.example.org/whoami --cookie "$JAR")" 000
expect "the other project is unaffected by the removal" "$(page https://www.example.org/)" "static fixture"
expect "a stale revision is a conflict" "$(rc op proxy-apply api --expected "$HOME/site.status.json")" 6
apply api
expect "the route can be published again" "$(http https://api.example.org/whoami --cookie "$JAR")" 200
expect "the deployment identity cannot change routes" \
  "$(rc cais proxy-remove api --expected "$HOME/api.status.json" --target api-deploy --config "$CONFIG" --json)" 3
expect "the administrator configuration was never modified" "$(caddyfile_sum)" "$before"

# --- Backup registration and coverage --------------------------------------------------
expect "an unregistered manifest is absent" "$(field api .data.backup.manifest)" absent
expect "an unregistered project is not covered" "$(field api .data.backup.coverage)" not_covered
op backup-register api --expected "$HOME/api.status.json" > /dev/null
expect "the manifest lists the preserved data path" "$(jq -r '.paths[0]' /var/lib/cais-backup/api.json)" /var/lib/cais-data/api/uploads
status api
expect "the manifest is registered" "$(field api .data.backup.manifest)" registered
expect "a registered project without a backup run is not covered" "$(field api .data.backup.coverage)" not_covered
sudo sh -c 'echo covered > /var/lib/fixture-backup/api'
status api
expect "the provider reports coverage" "$(field api .data.backup.coverage)" covered
expect "the last successful backup time is reported" "$(field api .data.backup.last_success_at)" 1700000000
sudo sh -c 'echo broken > /var/lib/fixture-backup/api'
status api
expect "a provider failure is visible, not reported as coverage" "$(field api .data.backup.coverage)" check_failed
sudo sh -c 'echo "{}" > /var/lib/cais-backup/api.json'
status api
expect "a modified manifest is stale" "$(field api .data.backup.manifest)" stale
expect "a stale manifest is not covered" "$(field api .data.backup.coverage)" not_covered
status site
expect "a project without backup intent reports no backup" "$(field site .data.backup)" null
expect "a project without backup intent cannot register one" "$(rc op backup-register site --expected "$HOME/site.status.json")" 4

# --- Databases in the manifest ---------------------------------------------------------
status api
op backup-register api --expected "$HOME/api.status.json" > /dev/null
status api
expect "the manifest lists no database before one exists" "$(jq '.databases | length' /var/lib/cais-backup/api.json)" 0
op db-create api --expected "$HOME/api.status.json" > /dev/null
status api
expect "the project database is ready" "$(field api .data.database.state)" ready
expect "creating a database makes the manifest stale" "$(field api .data.backup.manifest)" stale
op backup-register api --expected "$HOME/api.status.json" > /dev/null
status api
expect "the manifest names the project database" "$(jq -r '.databases[0].name' /var/lib/cais-backup/api.json)" "$(field api .data.database.name)"
expect "the named database exists in the cluster" \
  "$(sudo -u postgres psql -Atc "select count(*) from pg_database where datname = '$(field api .data.database.name)'")" 1
expect "the manifest is registered again" "$(field api .data.backup.manifest)" registered
expect "the manifest holds no credentials" "$(grep -c -i -E 'password|scram|secret' /var/lib/cais-backup/api.json || true)" 0
static_project dbonly "database only"
register dbonly
op db-create dbonly --expected "$HOME/dbonly.status.json" > /dev/null
status dbonly
op backup-register dbonly --expected "$HOME/dbonly.status.json" > /dev/null
expect "a project with only a database can be registered for backup" \
  "$(jq -c '[(.paths | length), (.databases | length)]' /var/lib/cais-backup/dbonly.json)" "[0,1]"

# --- Metadata and catalog --------------------------------------------------------------
CATALOG=/var/lib/cais-catalog/catalog.json
entry() { jq -c --arg p "$1" ".projects[] | select(.project == \$p) | $2" "$CATALOG"; }
status api
expect "registration alone lists the project in the catalog" "$(entry api .kind)" '"http"'
expect "the catalog names the unit a consumer may observe" "$(systemctl is-active "$(entry api .unit | tr -d '"')")" active
expect "the catalog carries the declared hostname" "$(entry api .host)" '"api.example.org"'
expect "a project without metadata is current in the catalog" "$(field api .data.catalog)" current
cat > "$HOME/api/metadata.json" <<'EOF'
{ "schema_version": 1, "title": "Fixture API", "description": "Synthetic service.",
  "url": "https://api.example.org/", "labels": { "dashboard": true, "tier": "internal" } }
EOF
expect "metadata validates locally" "$(rc cais validate --kind metadata --file "$HOME/api/metadata.json" --json)" 0
op metadata-set api --file "$HOME/api/metadata.json" --expected "$HOME/api.status.json" > /dev/null
status api
expect "status returns the stored metadata" "$(field api .data.metadata.title)" "Fixture API"
expect "the catalog publishes the metadata" "$(entry api .metadata.labels.dashboard)" true
expect "the catalog is current after metadata" "$(field api .data.catalog)" current
expect "setting metadata did not redeploy" "$(field api .data.deployment.state)" success
expect "the catalog exposes no paths, environment or credentials" \
  "$(grep -c -i -E 'cais-data|cais-apps|runtime.env|password|secret' "$CATALOG" || true)" 0
expect "other accounts cannot rewrite the catalog" "$(sh -c "echo x >> $CATALOG" 2>/dev/null && echo written || echo denied)" denied
jq '.url = "https://elsewhere.example.net/"' "$HOME/api/metadata.json" > "$HOME/api/foreign.json"
expect "an address on a hostname the project does not own is denied" \
  "$(rc op metadata-set api --file "$HOME/api/foreign.json" --expected "$HOME/api.status.json")" 3
jq '.unit = "ssh.service"' "$HOME/api/metadata.json" > "$HOME/api/unit.json"
expect "metadata cannot name a unit, path or command" \
  "$(rc op metadata-set api --file "$HOME/api/unit.json" --expected "$HOME/api.status.json")" 2
expect "the deployment identity cannot set metadata" \
  "$(rc cais metadata-set api --file "$HOME/api/metadata.json" --expected "$HOME/api.status.json" --target api-deploy --config "$CONFIG" --json)" 3
sudo sh -c "echo '{\"schema_version\":1,\"projects\":[]}' > $CATALOG"
status api
expect "a catalog missing the project is reported as stale" "$(field api .data.catalog)" stale
op metadata-set api --file "$HOME/api/metadata.json" --expected "$HOME/api.status.json" > /dev/null
status api
expect "setting metadata again rebuilds the catalog" "$(field api .data.catalog)" current
expect "the rebuilt catalog still lists the other projects" "$(entry site .kind)" '"static"'

# --- MCP session ----------------------------------------------------------------------
python3 /fixture/mcp_session.py

# --- Faults: competing clients and a held lock ----------------------------------------
restart() { rc op restart "$1" --expected "$HOME/$1.status.json"; }
status api
( rc cais restart api --expected "$HOME/api.status.json" --target operator --config "$CONFIG" --json > "$HOME/first.rc" ) &
( rc cais restart api --expected "$HOME/api.status.json" --target operator --config "$CONFIG" --json > "$HOME/second.rc" ) &
wait
expect "of two clients using one revision, exactly one succeeds" "$(sort "$HOME/first.rc" "$HOME/second.rc" | tr '\n' ' ')" "0 6 "
status api
expect "the losing client left no unresolved operation" "$(field api .data.requires_inspection)" false
sudo flock /var/lib/cais/locks/api.lock sleep 4 &
sleep 1
status api
expect "status observes an operation in progress" "$(field api .data.operation_lock_held)" true
expect "a mutation during another operation is refused as busy" "$(restart api)" 6
expect "the refusal names the cause" "$(jq -r .error.code "$HOME/last.json")" busy
wait
status api
expect "the lock is released afterwards" "$(field api .data.operation_lock_held)" false
expect "the refused mutation can then be made with a fresh revision" "$(restart api)" 0

# --- Faults: a deployment that never becomes healthy ----------------------------------
http_project flaky
register flaky
deploy flaky
good=$(field flaky .data.deployment.sha256)
echo 'raise SystemExit(1)' > "$HOME/flaky/dist/app.py"
expect "a deployment that never becomes healthy fails" "$(publish flaky)" 7
status flaky
expect "the failed deployment is recorded as failed" "$(field flaky .data.deployment.state)" failed
expect "a failure with a known result needs no inspection" "$(field flaky .data.requires_inspection)" false
cp /fixture/app.py "$HOME/flaky/dist/app.py"
expect "a corrected artifact can be deployed after the failure" "$(publish flaky)" 0
status flaky
expect "the recovered deployment is the original artifact" "$(field flaky .data.deployment.sha256)" "$good"
expect "the service is active again" "$(field flaky .data.service)" active

# --- Faults: the server dies in the middle of a mutation ------------------------------
printf 'import time\ntime.sleep(600)\n' > "$HOME/flaky/dist/app.py"
package flaky; status flaky
( rc cais deploy --file "$HOME/flaky/cais.json" --artifact "$HOME/flaky.tar.gz" --expected "$HOME/flaky.status.json" \
    --target flaky-deploy --config "$CONFIG" --json > "$HOME/killed.rc" ) &
sleep 6
sudo pkill -KILL -x cais-broker
wait
expect "a mutation interrupted on the server is an unknown outcome" "$(cat "$HOME/killed.rc")" 8
expect "the client reconnects and reads the state" "$(rc op status flaky)" 0
status flaky
expect "the interrupted operation is left in progress" "$(field flaky .data.last_operation.state)" in_progress
expect "the interrupted operation requires inspection" "$(field flaky .data.requires_inspection)" true
expect "another mutation is refused until inspection" "$(restart flaky)" 6
expect "the same deployment is not accepted again either" \
  "$(rc cais deploy --file "$HOME/flaky/cais.json" --artifact "$HOME/flaky.tar.gz" --expected "$HOME/flaky.status.json" --target flaky-deploy --config "$CONFIG" --json)" 6
expect "an operator cannot resolve it through the normal entrypoint" \
  "$(ssh -o BatchMode=yes -o UserKnownHostsFile="$HOME/known_hosts" -i "$HOME/keys/operator" alice@127.0.0.1 \
      "sudo -n $BROKER --resolve flaky $(field flaky .data.expected.revision) --acknowledge-inspected" > /dev/null 2>&1; echo $?)" 1
sudo "$BROKER" --resolve flaky "$(field flaky .data.expected.revision)" --acknowledge-inspected > /dev/null
status flaky
expect "an administrator records the inspection" "$(field flaky .data.last_operation.state)" resolved
expect "resolution does not claim the deployment succeeded" "$(field flaky .data.deployment.state)" unknown
cp /fixture/app.py "$HOME/flaky/dist/app.py"
expect "work resumes after the inspection" "$(publish flaky)" 0
status flaky
expect "the application is healthy after recovery" "$(field flaky .data.service)" active

# --- Faults: a plan made before the policy changed ------------------------------------
static_project late late
op plan --file "$HOME/late/cais.json" > "$HOME/late.plan.json"
status api
sudo sed -i 's/"runtimes"/"limits": { "tasks": 64 }, "runtimes"/' /etc/cais/server.json
expect "a plan made under an older policy is refused" \
  "$(rc op register --file "$HOME/late/cais.json" --plan "$HOME/late.plan.json" --deploy-public-key "$HOME/keys/deploy.pub")" 6
expect "a status read under an older policy is refused" "$(restart api)" 6
status api
expect "a fresh status works under the new policy" "$(restart api)" 0
op plan --file "$HOME/late/cais.json" > "$HOME/late.plan.json"
expect "a fresh plan registers under the new policy" \
  "$(rc op register --file "$HOME/late/cais.json" --plan "$HOME/late.plan.json" --deploy-public-key "$HOME/keys/deploy.pub")" 0

# --- Another local process holds the application port ---------------------------------
status flaky
port=$(field flaky .data.port)
unit="cais-app-$(field flaky .data.runtime_user | cut -d- -f2-).service"
sudo systemctl stop "$unit"
cat > "$HOME/squatter.py" <<'EOF'
import http.server, sys
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"squatter")
    def log_message(self, *args): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
EOF
python3 "$HOME/squatter.py" "$port" &
squatter=$!
sleep 1
expect "the other process answers the health path" "$(curl --silent --max-time 3 "http://127.0.0.1:$port/health")" squatter
status flaky
expect "an answer from another account is not taken for the application" "$(restart flaky)" 7
expect "the refusal names the cause" "$(jq -r .error.message "$HOME/last.json")" \
  "Another process answers on the application port; inspect the host."
kill "$squatter"; wait "$squatter" 2>/dev/null || true
status flaky
expect "the application returns once the port is free" "$(restart flaky)" 0

# --- A delegation removed from the policy stops at once -------------------------------
policy_edit() { # jq filter
  sudo jq "$1" /etc/cais/server.json > "$HOME/policy.new"
  sudo install -m 0644 -o root -g root "$HOME/policy.new" /etc/cais/server.json
}
policy_edit '.operators.alice.domain_suffixes = ["example.net"]'
status api
expect "a route whose hostname is no longer delegated is not published" \
  "$(rc op proxy-apply api --expected "$HOME/api.status.json")" 3
expect "the refusal is a policy denial" "$(jq -r .error.code "$HOME/last.json")" policy_denied
policy_edit '.operators.alice.domain_suffixes = ["example.org"] | .operators.alice.backup = false'
status api
expect "backup registration stops when the permission is removed" \
  "$(rc op backup-register api --expected "$HOME/api.status.json")" 3
policy_edit '.operators.alice.backup = true | .projects.api = {"operators": ["carol"]}'
expect "an operator removed from a project cannot read it" "$(rc op status api)" 3
expect "other projects of the same operator are unaffected" "$(rc op status flaky)" 0
policy_edit 'del(.projects.api) | .projects.reserved = {"operators": ["carol"], "hosts": ["reserved.example.org"], "access_profiles": ["open"]}'
static_project taken taken "$(exposure reserved.example.org / open)"
expect "a suffix does not reach a hostname the policy names for another project" \
  "$(rc op plan --file "$HOME/taken/cais.json")" 3
status api
expect "restored delegations work again" "$(rc op proxy-apply api --expected "$HOME/api.status.json")" 0

echo "ALL PASS"
