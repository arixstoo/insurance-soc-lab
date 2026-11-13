#!/usr/bin/env bash
# Entry point of the "real" lab hosts (compose profile `real`, see docs/real-services.md).
#   1. render the agent config from /etc/insurco/ossec.conf.tpl (one file per host image)
#   2. run the host's start scripts (/etc/insurco/start.d/*.sh, in name order): they start
#      the REAL services of the host (sshd + rsyslog + auditd, nginx, PostgreSQL)
#   3. run the Wazuh agent, which reads the logs those services write
# Configuration is baked into the image or comes from compose: nothing is edited by hand.
set -euo pipefail

: "${WAZUH_MANAGER:?WAZUH_MANAGER is required}"
: "${AGENT_NAME:?AGENT_NAME is required}"
export AGENT_GROUP="${AGENT_GROUP:-default}"

# shellcheck disable=SC2016  # envsubst takes the variable names literally
envsubst '${WAZUH_MANAGER} ${AGENT_NAME} ${AGENT_GROUP}' \
  < /etc/insurco/ossec.conf.tpl > /var/ossec/etc/ossec.conf
chown root:wazuh /var/ossec/etc/ossec.conf && chmod 0640 /var/ossec/etc/ossec.conf

for script in /etc/insurco/start.d/*.sh; do
  echo "[real-host] ${AGENT_NAME}: ${script}"
  bash "$script"
done

stop() {
  if [ -x /etc/insurco/stop.sh ]; then /etc/insurco/stop.sh || true; fi
  /var/ossec/bin/wazuh-control stop
  exit 0
}
trap stop SIGTERM SIGINT

echo "[real-host] ${AGENT_NAME}: starting the Wazuh agent (manager ${WAZUH_MANAGER})"
/var/ossec/bin/wazuh-control start
tail -F /var/ossec/logs/ossec.log &
wait $!
