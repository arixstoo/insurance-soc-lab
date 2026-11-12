# syntax=docker/dockerfile:1
# real-web-01: a real nginx serving a tiny static "claims portal", with a Wazuh agent reading
# the REAL /var/log/nginx/access.log. Build context: real/. Base `agent` = lab agent image.
FROM agent

RUN apt-get update \
 && apt-get install -y --no-install-recommends nginx \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nginx/sites-enabled/default

COPY common/real-host-entrypoint.sh /usr/local/bin/real-host-entrypoint.sh
COPY web/ossec.conf.tpl /etc/insurco/ossec.conf.tpl
COPY web/portal.conf /etc/nginx/sites-enabled/claims-portal.conf
COPY web/site/ /srv/claims-portal/
COPY web/start.sh /etc/insurco/start.d/10-web.sh
RUN chmod 0755 /usr/local/bin/real-host-entrypoint.sh && nginx -t

HEALTHCHECK --interval=15s --timeout=5s --start-period=60s \
  CMD pgrep -x nginx >/dev/null && grep -q "status='connected'" /var/ossec/var/run/wazuh-agentd.state || exit 1

ENTRYPOINT ["/usr/local/bin/real-host-entrypoint.sh"]
