FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 EOLSCAN_DATA=/data
WORKDIR /opt/eolscan

COPY requirements.txt requirements-llm.txt requirements-browser.txt ./
ARG WITH_LLM=1
# Headless-browser crawl for single-page apps adds ~400 MB, so it's opt-in:  docker compose build --build-arg WITH_BROWSER=1
ARG WITH_BROWSER=0
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN pip install --no-cache-dir -r requirements.txt \
 && if [ "$WITH_LLM" = "1" ]; then pip install --no-cache-dir -r requirements-llm.txt; fi \
 && if [ "$WITH_BROWSER" = "1" ]; then pip install --no-cache-dir -r requirements-browser.txt \
      && playwright install --with-deps chromium && chmod -R a+rX /ms-playwright; fi

COPY app ./app
COPY scripts ./scripts

# Run unprivileged; /data holds the SQLite DB, synced EOL data and transient uploads.
RUN useradd -r -m -u 10001 eolscan && mkdir -p /data && chown -R eolscan /data
USER eolscan
VOLUME ["/data"]
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8765/api/health')" || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8765", "--proxy-headers"]
