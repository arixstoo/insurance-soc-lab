# Wazuh agent simulating one InsurCo host.
# The agent version MUST be <= the manager version.
FROM ubuntu:22.04

ARG WAZUH_VERSION=4.14.9
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg gettext-base procps \
 && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends "wazuh-agent=${WAZUH_VERSION}-1" \
 && apt-mark hold wazuh-agent \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY ossec.conf.tpl /etc/insurco/ossec.conf.tpl
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
  CMD grep -q "status='connected'" /var/ossec/var/run/wazuh-agentd.state || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
