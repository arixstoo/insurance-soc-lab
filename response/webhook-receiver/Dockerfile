# webhook-receiver: stores and shows the alerts the Wazuh integration posts (lab only, offline).
FROM python:3.15-slim

RUN useradd --uid 10002 --create-home hook \
 && mkdir -p /data && chown hook:hook /data
COPY receiver.py /app/receiver.py

USER hook
ENV DATA_DIR=/data INGEST_PORT=8080 VIEW_PORT=8081 PYTHONUNBUFFERED=1
EXPOSE 8080 8081
HEALTHCHECK --interval=10s --timeout=3s --retries=10 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/healthz', timeout=2)"
ENTRYPOINT ["python", "/app/receiver.py"]
