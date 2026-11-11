#!/usr/bin/env bash
# Render the agent config from environment variables, then run the agent.
set -euo pipefail

: "${WAZUH_MANAGER:?WAZUH_MANAGER is required}"
: "${AGENT_NAME:?AGENT_NAME is required}"
: "${LOG_FORMAT:?LOG_FORMAT is required (syslog|apache|json)}"
: "${LOG_FILE:?LOG_FILE is required}"
export AGENT_GROUP="${AGENT_GROUP:-default}"

envsubst '${WAZUH_MANAGER} ${AGENT_NAME} ${AGENT_GROUP} ${LOG_FORMAT} ${LOG_FILE}' \
  < /etc/insurco/ossec.conf.tpl > /var/ossec/etc/ossec.conf
chown root:wazuh /var/ossec/etc/ossec.conf && chmod 0640 /var/ossec/etc/ossec.conf

# The log file may not exist yet; the agent picks it up once the simulator writes it.
mkdir -p /var/log/insurco

echo "[entrypoint] agent=${AGENT_NAME} manager=${WAZUH_MANAGER} source=/var/log/insurco/${LOG_FILE} (${LOG_FORMAT})"

stop() { /var/ossec/bin/wazuh-control stop; exit 0; }
trap stop SIGTERM SIGINT

/var/ossec/bin/wazuh-control start
tail -F /var/ossec/logs/ossec.log &
wait $!
