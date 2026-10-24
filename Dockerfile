
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY trustvault ./trustvault
COPY run.py .

RUN useradd -r -u 10001 tv \
    && mkdir -p /data/blobs \
    && chown -R tv /data

USER tv

ENV TV_DB_PATH=/data/trustvault.db
ENV TV_STORAGE_DIR=/data/blobs
ENV TV_TRUST_PROXY=1

EXPOSE 8000

CMD ["sh", "-c", "python -m trustvault.seed && exec gunicorn -w 2 -b 0.0.0.0:${PORT:-8000} 'trustvault:create_app()'"]
