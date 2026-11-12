# syntax=docker/dockerfile:1
# real-db-01: a real PostgreSQL with pgaudit and a small FAKE customer dataset, with a Wazuh
# agent reading the REAL server log (jsonlog, pgaudit lines included).
# Build context: real/. Base `agent` = lab agent image (additional build context).

# Stage 1: the seed, generated with a pinned Faker and a fixed seed (same rows every build)
FROM python:3.12-slim-trixie AS seed
RUN pip install --no-cache-dir "faker==40.50.0"
COPY db/gen_seed.py /gen_seed.py
RUN python /gen_seed.py > /seed.sql

# Stage 2: the host
FROM agent
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql postgresql-18-pgaudit \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 # The package creates a cluster at install time: drop it, start.sh creates ours at first start
 && pg_dropcluster --stop 18 main

COPY common/real-host-entrypoint.sh /usr/local/bin/real-host-entrypoint.sh
COPY db/ossec.conf.tpl /etc/insurco/ossec.conf.tpl
COPY db/insurco.conf db/pg_hba.conf db/schema.sql /etc/insurco/postgres/
COPY --from=seed /seed.sql /etc/insurco/postgres/seed.sql
COPY db/start.sh /etc/insurco/start.d/10-db.sh
COPY db/stop.sh /etc/insurco/stop.sh
RUN chmod 0755 /usr/local/bin/real-host-entrypoint.sh /etc/insurco/stop.sh \
 && chmod 0644 /etc/insurco/postgres/*

HEALTHCHECK --interval=15s --timeout=5s --start-period=90s \
  CMD pg_isready -q -h 127.0.0.1 && grep -q "status='connected'" /var/ossec/var/run/wazuh-agentd.state || exit 1

ENTRYPOINT ["/usr/local/bin/real-host-entrypoint.sh"]
