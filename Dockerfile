FROM python:3.12-alpine

WORKDIR /app

COPY server.py log_processor.py index.html ./

RUN mkdir -p /data

EXPOSE 8000

CMD ["python", "server.py", "--host", "0.0.0.0", "--port", "8000", "--log-file", "/data/visitors.log"]
