FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    fail2ban \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel ./sentinel

ENV HOST=0.0.0.0 \
    PORT=8088 \
    DB_PATH=/data/sentinel.db

EXPOSE 8088

CMD ["uvicorn", "sentinel.main:app", "--host", "0.0.0.0", "--port", "8088"]
