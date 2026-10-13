#!/usr/bin/env bash
# explain.sh: which rules decided each test case, read from the Coraza
# audit log (JSON, one transaction per line).
#
# Run after tests/waf-test.sh. For every audited request that carries an
# X-Test-Case header it prints the final status, the rules that matched
# (ids and messages) and, for CRS, the anomaly evaluation that blocked.
#
# Usage: WAF_CONTAINER=coraza-apilab tests/explain.sh [case-filter]
# Requires: docker, jq.
set -euo pipefail

container="${WAF_CONTAINER:-coraza-apilab}"
filter="${1:-}"

docker exec "$container" cat /var/log/coraza/audit.log |
	jq -r --arg f "$filter" '
		select(.transaction.request.headers["x-test-case"] != null)
		| (.transaction.request.headers["x-test-case"][0]) as $case
		| select($f == "" or ($case | contains($f)))
		| "\($case)  status=\(.transaction.response.status)",
		  ( [.messages[]? | {id: .data.id, msg: .data.msg}]
		    | unique_by(.id)[]
		    | "    \(.id)  \(.msg)" )'
