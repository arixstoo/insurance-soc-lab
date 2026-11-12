# real-client: the lab test client (profile `real`). Not a monitored host: no agent.
# It waits; traffic is sent on demand: docker compose exec real-client lab-traffic all
FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sshpass curl postgresql-client \
      python3 python3-yaml ca-certificates \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY lab_traffic.py /usr/local/bin/lab-traffic
RUN chmod 0755 /usr/local/bin/lab-traffic

CMD ["sleep", "infinity"]
