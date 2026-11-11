FROM python:3.15-slim

# Unprivileged user that owns the shared log volume
RUN useradd --uid 10001 --create-home sim \
 && mkdir -p /var/log/insurco && chown sim:sim /var/log/insurco
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /root/.cache

USER sim
# Healthy once the per-host folders exist (agents mount those sub-folders)
HEALTHCHECK --interval=5s --timeout=3s --retries=20 \
  CMD test -d /var/log/insurco/srv-linux-01 && test -d /var/log/insurco/ws-claims-01
ENTRYPOINT ["insurco-sim"]
CMD ["run", "--out", "/var/log/insurco"]
