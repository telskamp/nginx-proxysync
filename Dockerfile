FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NPM_SYNC_HOST=0.0.0.0 \
    NPM_SYNC_PORT=8080 \
    NPM_SYNC_DATA_DIR=/data

WORKDIR /app
COPY nginx_proxysync ./nginx_proxysync
COPY assets ./assets
RUN mkdir -p /data && chown 10001:10001 /data
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import socket; socket.create_connection(('127.0.0.1', 8080), timeout=2).close()"
CMD ["python", "-m", "nginx_proxysync"]
