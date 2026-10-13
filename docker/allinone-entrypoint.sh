#!/bin/bash
# allinone-entrypoint.sh: runs the API simulator and nginx in one
# container and stops the container when either of them exits.
#
# Two processes in one container need a supervisor; this script is the
# smallest one that is honest about failures: if the API dies, nginx
# would answer 502 forever, so the container exits instead and the
# orchestrator (restart policy) brings both back. Run it with an init
# (compose `init: true`) so signals and zombies are handled.
set -euo pipefail

# The API listens on the loopback port that nginx proxies to. It binds
# 0.0.0.0, but the port is not published: from outside the container
# only nginx (8080) is reachable.
export PORT="${APILAB_PORT:-9000}"

# The API runs as an unprivileged user, never as root.
setpriv --reuid=nginx --regid=nginx --init-groups /usr/local/bin/apilab &
api_pid=$!

# Wait until the API answers before nginx starts taking traffic.
for _ in $(seq 1 50); do
	if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
		break
	fi
	sleep 0.1
done

# The official nginx entrypoint renders the templates, then runs "$@".
/docker-entrypoint.sh "$@" &
nginx_pid=$!

term() {
	kill -TERM "$nginx_pid" "$api_pid" 2>/dev/null || true
}
trap term TERM INT

# Whichever exits first takes the container down with it.
set +e
wait -n "$api_pid" "$nginx_pid"
status=$?
term
wait
exit "$status"
