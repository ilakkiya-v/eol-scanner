#!/usr/bin/env python3
"""Build the offline EOL snapshot from endoflife.date.

Run this on an internet-connected machine before taking the tool into an
air-gapped / VPN-only lab:

    python scripts/build_snapshot.py            # writes app/eol/data/eol_snapshot.json

The app can also refresh the snapshot itself from Settings -> Data feeds.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.eol.feeds import build_snapshot  # noqa: E402

if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    path, count = build_snapshot(out)
    print(f"wrote {count} products to {path}")
