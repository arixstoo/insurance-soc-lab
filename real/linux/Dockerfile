# syntax=docker/dockerfile:1
# real-linux-01: a real Linux server (openssh-server + rsyslog + auditd) with a Wazuh agent
# reading the REAL /var/log/auth.log and /var/log/audit/audit.log.
# Build context: real/. Base image `agent` = the lab agent image (agents/Dockerfile),
# passed by compose as an additional build context, so the agent version is the same.
FROM agent

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server rsyslog auditd \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 # Host keys are generated at container start (start.sh), never baked into the image
 && rm -f /etc/ssh/ssh_host_* \
 # A container has no kernel log: keep Ubuntu's rsyslog config, without the imklog input
 && sed -i -E 's/^(module\(load="imklog".*)$/# \1  (disabled: no kernel log in a container)/' /etc/rsyslog.conf \
 # pam_loginuid needs to write /proc/self/loginuid, which a container may refuse
 && sed -i -E 's/^session\s+required\s+pam_loginuid\.so/session optional pam_loginuid.so/' /etc/pam.d/sshd

COPY common/real-host-entrypoint.sh /usr/local/bin/real-host-entrypoint.sh
COPY linux/ossec.conf.tpl /etc/insurco/ossec.conf.tpl
COPY linux/sshd_config /etc/ssh/sshd_config.d/10-insurco-lab.conf
COPY linux/insurco.rules /etc/audit/rules.d/insurco.rules
COPY linux/start.sh /etc/insurco/start.d/10-linux.sh
RUN chmod 0755 /usr/local/bin/real-host-entrypoint.sh

HEALTHCHECK --interval=15s --timeout=5s --start-period=60s \
  CMD pgrep -x sshd >/dev/null && grep -q "status='connected'" /var/ossec/var/run/wazuh-agentd.state || exit 1

ENTRYPOINT ["/usr/local/bin/real-host-entrypoint.sh"]
