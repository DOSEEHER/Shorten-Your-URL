FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 DATA_DIR=/data
WORKDIR /app
RUN addgroup --system --gid 10001 app && adduser --system --uid 10001 --ingroup app app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py proxy.py docker-entrypoint.sh ./
COPY templates ./templates
RUN mkdir -p /data && sed -i 's/\r$//' /app/docker-entrypoint.sh && chown -R app:app /app /data && chmod +x /app/docker-entrypoint.sh
USER app
EXPOSE 5000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 CMD ["python", "-c", "import os, urllib.request; h = [x.strip() for x in os.environ.get('TRUSTED_HOSTS', '').split(',') if x.strip()]; req = urllib.request.Request('http://127.0.0.1:5000/healthz', headers={'Host': h[0]} if h else {}); urllib.request.urlopen(req, timeout=2)"]
ENTRYPOINT ["/app/docker-entrypoint.sh"]
