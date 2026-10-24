FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY trustvault ./trustvault
COPY run.py .
RUN useradd -r -u 10001 tv && mkdir -p /data && chown tv /data
USER tv
ENV TV_DB_PATH=/data/trustvault.db TV_STORAGE_DIR=/data/blobs TV_TRUST_PROXY=1
# Render provides $PORT; fall back to 8000 for local Docker.
# Seeding is idempotent, so it is safe on every start.
CMD ["sh", "-c", "python -m trustvault.seed && exec gunicorn -w 2 -b 0.0.0.0:${PORT:-8000} 'trustvault:create_app()'"]