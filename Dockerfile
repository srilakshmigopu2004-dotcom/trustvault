FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY trustvault ./trustvault
COPY run.py .
RUN useradd -r -u 10001 tv && mkdir -p /data && chown tv /data
USER tv
ENV TV_DB_PATH=/data/trustvault.db TV_STORAGE_DIR=/data/blobs TV_TRUST_PROXY=1
EXPOSE 8000
# Seed is idempotent; AUDIT key and optional role-specific seed passwords come from the environment.
CMD ["sh", "-c", "python -m trustvault.seed && exec gunicorn -w 2 -b 0.0.0.0:8000 'trustvault:create_app()'"]
