FROM python:3.13-slim

# Install deps first for better layer caching
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

# Non-root runtime user
RUN useradd -u 10000 -m -s /usr/sbin/nologin app

WORKDIR /app
COPY app/ /app/app/

ENV DATA_DIR=/data \
    PORT=8000 \
    PYTHONUNBUFFERED=1

RUN mkdir -p /data/uploads && chown -R app:app /app /data

USER app
VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"

CMD ["sh","-c","exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
