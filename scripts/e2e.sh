#!/usr/bin/env bash
# End-to-end check of a running lab (used by .github/workflows/e2e.yml):
#   1. wait until the 4 agents are active on the manager
#   2. inject every attack scenario with `insurco-sim inject`
#   3. query wazuh-alerts-* (curl, TLS verified against the lab CA) until every rule
#      in each scenario's expected_rules has been indexed since step 2 started
#
#   scripts/e2e.sh            needs: docker compose, curl, jq; INDEXER_PASSWORD in env or .env
#
# Night-only rules (a <time> element in insurco_rules.xml, e.g. 100102, 100133) are
# excluded from the check: they depend on the manager clock, not on the scenario.
# For a deterministic run, start the lab with a manager clock at daytime (the workflow
# sets LAB_TZ so that it is about 12:00) and random attacks disabled (SIM_ATTACK_MIN/MAX
# very large): at night 100133 replaces 100131 and 100132 cannot fire, and a random
# attack just before the injections can trigger a correlation rule's `ignore` window.
#
# Tunables: E2E_AGENT_TIMEOUT (default 300 s), E2E_ALERT_TIMEOUT (default 300 s).
# shellcheck disable=SC2016  # $vars inside single quotes are jq variables, not shell ones
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash: do not rewrite /var/ossec/... container paths

cd "$(dirname "$0")/.."

AGENT_TIMEOUT="${E2E_AGENT_TIMEOUT:-300}"
ALERT_TIMEOUT="${E2E_ALERT_TIMEOUT:-300}"
AGENTS=(srv-linux-01 srv-web-01 srv-db-01 ws-claims-01)
RULES_XML=detection/rules/insurco_rules.xml
CA=stack/certs/root-ca.pem

for tool in docker curl jq; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
if [ -z "${INDEXER_PASSWORD:-}" ] && [ -f .env ]; then
  INDEXER_PASSWORD="$(sed -n 's/^INDEXER_PASSWORD=//p' .env | tail -n1 | tr -d '\r')"
fi
[ -n "${INDEXER_PASSWORD:-}" ] || { echo "INDEXER_PASSWORD not set (env or .env)" >&2; exit 2; }

# The indexer certificate is issued to wazuh.indexer: resolve that name to the published
# 127.0.0.1:9200 so TLS is fully verified. The credentials go through stdin (--config -),
# never on the command line.
# Windows curl (Schannel) also wants a revocation answer, which a private lab CA cannot
# give; the chain and the host name are still verified.
CURL_TLS=(--cacert "$CA" --resolve wazuh.indexer:9200:127.0.0.1)
if curl -V | grep -qi schannel; then CURL_TLS+=(--ssl-no-revoke); fi
indexer() {  # indexer <path> <json body>
  printf 'user = "admin:%s"\n' "$INDEXER_PASSWORD" | curl -sS --fail-with-body --config - "${CURL_TLS[@]}" \
    -H 'Content-Type: application/json' --data-binary "$2" "https://wazuh.indexer:9200$1"
}

jqx() { jq "$@" | tr -d '\r'; }  # jq for Windows prints CRLF

# ---------------------------------------------------------------- 1. agents
echo "== waiting for ${#AGENTS[@]} active agents (up to ${AGENT_TIMEOUT}s) =="
deadline=$((SECONDS + AGENT_TIMEOUT))
while :; do
  listing="$(docker compose exec -T wazuh.manager /var/ossec/bin/agent_control -l 2>/dev/null || true)"
  missing=()
  for name in "${AGENTS[@]}"; do
    grep -qE "Name: ${name}, .*Active" <<<"$listing" || missing+=("$name")
  done
  [ "${#missing[@]}" -eq 0 ] && break
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "agents not active after ${AGENT_TIMEOUT}s: ${missing[*]}" >&2
    echo "$listing" >&2
    exit 1
  fi
  sleep 5
done
echo "all agents active: ${AGENTS[*]}"

# ---------------------------------------------------------------- 2. scenarios
# Night-only rules: ids of <rule> blocks that contain a <time> element.
mapfile -t NIGHT_ONLY < <(awk '
  match($0, /<rule id="[0-9]+"/) { id = substr($0, RSTART + 10, RLENGTH - 11) }
  /<time>/ && id { print id }
  /<\/rule>/ { id = "" }
' "$RULES_XML")
echo "night-only rules (excluded): ${NIGHT_ONLY[*]:-none}"
echo "manager clock: $(docker compose exec -T wazuh.manager date '+%a %H:%M %Z')"

scenarios_json="$(docker compose exec -T simulator insurco-sim list --json)"
mapfile -t SCENARIOS < <(jqx -r '.[].name' <<<"$scenarios_json")

# Alerts must be newer than this (minus 5 s of clock slack between host and containers)
since_ms=$(( ($(date +%s) - 5) * 1000 ))
echo
echo "== injecting ${#SCENARIOS[@]} scenarios =="
for scenario in "${SCENARIOS[@]}"; do
  docker compose exec -T simulator insurco-sim inject "$scenario"
done

# ---------------------------------------------------------------- 3. indexer
# "scenario rule" pairs to check, night-only rules removed
mapfile -t PAIRS < <(jqx -r '.[] | .name as $s | .expected_rules[] | "\($s) \(.)"' <<<"$scenarios_json")
CHECK=()
for pair in "${PAIRS[@]}"; do
  rule="${pair#* }"
  if printf '%s\n' "${NIGHT_ONLY[@]}" | grep -qx "$rule"; then
    echo "skip ${pair} (night-only rule)"
  else
    CHECK+=("$pair")
  fi
done
rule_ids_json="$(printf '%s\n' "${CHECK[@]}" | awk '{print $2}' | sort -u | jqx -R . | jqx -sc .)"
query="$(jqx -nc --argjson since "$since_ms" --argjson ids "$rule_ids_json" '{
  size: 0,
  query: {bool: {filter: [
    {range: {timestamp: {gte: $since, format: "epoch_millis"}}},
    {terms: {"rule.id": $ids}}
  ]}},
  aggs: {rules: {terms: {field: "rule.id", size: 100}}}
}')"

echo
echo "== waiting for ${#CHECK[@]} expected rule alerts in wazuh-alerts-* (up to ${ALERT_TIMEOUT}s) =="
deadline=$((SECONDS + ALERT_TIMEOUT))
last_error=""
while :; do
  rc=0
  response="$(indexer '/wazuh-alerts-*/_search' "$query" 2>&1)" || rc=$?
  case "$rc" in
    0) counts="$(jqx -c '[.aggregations.rules.buckets[]? | {(.key): .doc_count}] | add // {}' <<<"$response")" ;;
    35|51|53|58|59|60|77|83|90|91)  # TLS / certificate problems do not fix themselves
       echo "TLS error talking to the indexer (curl exit $rc), not retrying:" >&2
       echo "$response" >&2
       exit 1 ;;
    *) counts='{}'; last_error="curl exit $rc: $response" ;;  # indexer busy or not up yet: retry
  esac
  unseen=0
  for pair in "${CHECK[@]}"; do
    [ "$(jqx -r --arg r "${pair#* }" '.[$r] // 0' <<<"$counts")" -gt 0 ] || unseen=$((unseen + 1))
  done
  if [ "$unseen" -eq 0 ] || [ "$SECONDS" -ge "$deadline" ]; then break; fi
  sleep 5
done

printf '\n%-15s %-7s %s\n' scenario rule alerts
failed=0
for pair in "${CHECK[@]}"; do
  scenario="${pair% *}"
  rule="${pair#* }"
  n="$(jqx -r --arg r "$rule" '.[$r] // 0' <<<"$counts")"
  if [ "$n" -gt 0 ]; then verdict=ok; else verdict=MISSING; failed=$((failed + 1)); fi
  printf '%-15s %-7s %-6s %s\n' "$scenario" "$rule" "$n" "$verdict"
done
echo
if [ "$failed" -gt 0 ]; then
  if [ -n "$last_error" ]; then echo "last indexer error: ${last_error}" >&2; fi
  echo "FAIL: ${failed}/${#CHECK[@]} expected rules not indexed after ${ALERT_TIMEOUT}s" >&2
  exit 1
fi
echo "OK: ${#CHECK[@]}/${#CHECK[@]} expected rules indexed"
