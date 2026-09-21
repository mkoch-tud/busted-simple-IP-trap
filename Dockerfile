FROM python:3.12-alpine

WORKDIR /app

COPY server.py log_processor.py index.html ./

RUN addgroup -S trap && adduser -S -G trap trap \
    && mkdir -p /data \
    && chown trap:trap /data

USER trap

EXPOSE 8000

CMD ["python", "server.py", "--host", "0.0.0.0", "--port", "8000", "--log-file", "/data/visitors.log"]
