from __future__ import annotations

import os
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("EOLSCAN_DATA", APP_DIR.parent / "data")).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "eolscan.db"
BUNDLED_SNAPSHOT = APP_DIR / "eol" / "data" / "eol_snapshot.json"
LIVE_SNAPSHOT = DATA_DIR / "eol_snapshot.json"
CURATED_FILE = APP_DIR / "eol" / "data" / "curated.json"

# Limits for uploaded archives (code review). Never executed, only parsed.
MAX_UPLOAD_BYTES = int(os.environ.get("EOLSCAN_MAX_UPLOAD_MB", "500")) * 1024 * 1024
MAX_EXTRACTED_BYTES = int(os.environ.get("EOLSCAN_MAX_EXTRACTED_MB", "2000")) * 1024 * 1024
MAX_FILES = int(os.environ.get("EOLSCAN_MAX_FILES", "200000"))

# How many days before EOL we start warning.
EOL_SOON_DAYS = int(os.environ.get("EOLSCAN_EOL_SOON_DAYS", "180"))

USER_AGENT = os.environ.get("EOLSCAN_USER_AGENT", "EOL-Scanner/1.0 (authorized security assessment)")
