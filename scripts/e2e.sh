#!/usr/bin/env bash
# End-to-end check of a running lab (used by .github/workflows/e2e.yml):
#   1. wait until the 4 agents are active on the manager
#   2. inject every attack scenario with `insurco-sim inject`
#   3. query wazuh-alerts-* (curl, TLS verified against the lab CA) until every rule
#      in each scenario's expected_rules has been indexed since step 2 started
#
# Real services (compose profile `real`, docs/real-services.md): when real-client is
# running (or E2E_REAL=1), also wait for the 3 real agents, run `lab-traffic all` on the
# test client, assert each job's expected rules ON ITS REAL HOST'S AGENT, then check that
# every detection family fired on both a simulated and a real host. E2E_REAL=0 skips it.
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
# Tunables: E2E_AGENT_TIMEOUT (default 300 s), E2E_ALERT_TIMEOUT (default 300 s), E2E_REAL.
# shellcheck disable=SC2016  # $vars inside single quotes are jq variables, not shell ones
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash: do not rewrite /var/ossec/... container paths

cd "$(dirname "$0")/.."

AGENT_TIMEOUT="${E2E_AGENT_TIMEOUT:-300}"
ALERT_TIMEOUT="${E2E_ALERT_TIMEOUT:-300}"
AGENTS=(srv-linux-01 srv-web-01 srv-db-01 ws-claims-01)
REAL_AGENTS=(real-linux-01 real-web-01 real-db-01)
REAL="${E2E_REAL:-auto}"
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

if [ "$REAL" = auto ]; then
  if [ -n "$(docker compose --profile real ps -q --status running real-client 2>/dev/null)" ]; then REAL=1; else REAL=0; fi
fi
if [ "$REAL" = 1 ]; then AGENTS+=("${REAL_AGENTS[@]}"); fi
echo "real services: $(if [ "$REAL" = 1 ]; then echo "yes (${REAL_AGENTS[*]})"; else echo no; fi)"

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
# Real traffic FIRST, then a pause longer than the largest `ignore` of the rules: Wazuh's
# `ignore` mutes the whole rule after it fires, whatever the source address or user, so the
# simulated brute force would silence the real one for 60 s (100100), the web campaign for
# 120 s (100129), the insider for 300 s (100132). Found by this test; docs/real-services.md.
if [ "$REAL" = 1 ]; then
  echo
  echo "== real services: lab-traffic all (test client -> real hosts) =="
  real_json="$(docker compose --profile real exec -T real-client lab-traffic list --json)"
  docker compose --profile real exec -T real-client lab-traffic all
  max_ignore="$(grep -o 'ignore="[0-9]*"' "$RULES_XML" | grep -o '[0-9]*' | sort -n | tail -n1)"
  echo "waiting $((max_ignore + 15)) s (largest rule ignore window: ${max_ignore} s) before the simulated scenarios"
  sleep "$((max_ignore + 15))"
fi
echo
echo "== injecting ${#SCENARIOS[@]} scenarios =="
for scenario in "${SCENARIOS[@]}"; do
  docker compose exec -T simulator insurco-sim inject "$scenario"
done

# ---------------------------------------------------------------- 3. indexer
# "source where rule" triples to check, night-only rules removed. where = "simulated" (any
# simulated host) or the name of the real host whose agent must raise the rule.
mapfile -t PAIRS < <(jqx -r '.[] | .name as $s | .expected_rules[] | "\($s) simulated \(.)"' <<<"$scenarios_json")
if [ "$REAL" = 1 ]; then
  mapfile -t -O "${#PAIRS[@]}" PAIRS < <(jqx -r '.[] | .name as $j | .host as $h | .expected_rules[] | "\($j) \($h) \(.)"' <<<"$real_json")
fi
CHECK=()
for pair in "${PAIRS[@]}"; do
  rule="${pair##* }"
  if printf '%s\n' "${NIGHT_ONLY[@]}" | grep -qx "$rule"; then
    echo "skip ${pair} (night-only rule)"
  else
    CHECK+=("$pair")
  fi
done
rule_ids_json="$(printf '%s\n' "${CHECK[@]}" | awk '{print $3}' | sort -u | jqx -R . | jqx -sc .)"
query="$(jqx -nc --argjson since "$since_ms" --argjson ids "$rule_ids_json" '{
  size: 0,
  query: {bool: {filter: [
    {range: {timestamp: {gte: $since, format: "epoch_millis"}}},
    {terms: {"rule.id": $ids}}
  ]}},
  aggs: {agents: {terms: {field: "agent.name", size: 50}, aggs: {rules: {terms: {field: "rule.id", size: 100}}}}}
}')"

# Alerts of a rule on the simulated hosts (any agent but real-*), or on one real host
seen() {  # seen "<source> <where> <rule>"
  local where rule
  read -r _ where rule <<<"$1"
  jqx -r --arg w "$where" --arg r "$rule" '[to_entries[]
    | (.key | split("|")) as [$agent, $id]
    | select($id == $r and (if $w == "simulated" then ($agent | startswith("real-") | not) else $agent == $w end))
    | .value] | add // 0' <<<"$counts"
}

echo
echo "== waiting for ${#CHECK[@]} expected rule alerts in wazuh-alerts-* (up to ${ALERT_TIMEOUT}s) =="
deadline=$((SECONDS + ALERT_TIMEOUT))
last_error=""
while :; do
  rc=0
  response="$(indexer '/wazuh-alerts-*/_search' "$query" 2>&1)" || rc=$?
  case "$rc" in
    0) counts="$(jqx -c '[.aggregations.agents.buckets[]? | .key as $a | .rules.buckets[] | {"\($a)|\(.key)": .doc_count}] | add // {}' <<<"$response")" ;;
    35|51|53|58|59|60|77|83|90|91)  # TLS / certificate problems do not fix themselves
       echo "TLS error talking to the indexer (curl exit $rc), not retrying:" >&2
       echo "$response" >&2
       exit 1 ;;
    *) counts='{}'; last_error="curl exit $rc: $response" ;;  # indexer busy or not up yet: retry
  esac
  unseen=0
  for pair in "${CHECK[@]}"; do
    [ "$(seen "$pair")" -gt 0 ] || unseen=$((unseen + 1))
  done
  if [ "$unseen" -eq 0 ] || [ "$SECONDS" -ge "$deadline" ]; then break; fi
  sleep 5
done

printf '\n%-15s %-14s %-7s %s\n' source host rule alerts
failed=0
for pair in "${CHECK[@]}"; do
  read -r source where rule <<<"$pair"
  n="$(seen "$pair")"
  if [ "$n" -gt 0 ]; then verdict=ok; else verdict=MISSING; failed=$((failed + 1)); fi
  printf '%-15s %-14s %-7s %-6s %s\n' "$source" "$where" "$rule" "$n" "$verdict"
done
echo

# Same detection family on simulated AND real logs: every rule a real job expects must also
# fire on a simulated host (100137 is the real-audit-trail twin of 100131).
if [ "$REAL" = 1 ]; then
  echo "== same detection family on simulated and real logs =="
  printf '%-7s %-7s %-7s %-9s %s\n' real alerts twin simulated verdict
  for pair in "${CHECK[@]}"; do
    read -r _ where rule <<<"$pair"
    [ "$where" = simulated ] && continue
    case "$rule" in 100137) twin=100131 ;; *) twin="$rule" ;; esac
    n_real="$(seen "$pair")"
    n_sim="$(seen "family simulated $twin")"
    if [ "$n_real" -gt 0 ] && [ "$n_sim" -gt 0 ]; then verdict=both; else verdict=GAP; failed=$((failed + 1)); fi
    printf '%-7s %-7s %-7s %-9s %s\n' "$rule" "$n_real" "$twin" "$n_sim" "$verdict"
  done
  echo
fi
if [ "$failed" -gt 0 ]; then
  if [ -n "$last_error" ]; then echo "last indexer error: ${last_error}" >&2; fi
  echo "FAIL: ${failed}/${#CHECK[@]} expected rules not indexed after ${ALERT_TIMEOUT}s" >&2
  exit 1
fi
echo "OK: ${#CHECK[@]}/${#CHECK[@]} expected rules indexed"
