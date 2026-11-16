FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 EOLSCAN_DATA=/data
WORKDIR /opt/eolscan

COPY requirements.txt requirements-llm.txt ./
ARG WITH_LLM=1
RUN pip install --no-cache-dir -r requirements.txt \
 && if [ "$WITH_LLM" = "1" ]; then pip install --no-cache-dir -r requirements-llm.txt; fi

COPY app ./app
COPY scripts ./scripts

# Run unprivileged; /data holds the SQLite DB, synced EOL data and transient uploads.
RUN useradd -r -m -u 10001 eolscan && mkdir -p /data && chown -R eolscan /data
USER eolscan
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/api/health')" || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
