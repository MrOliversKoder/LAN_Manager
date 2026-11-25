import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("LAN_DATA_DIR", "./data")).resolve()
DB_PATH = DATA_DIR / "lan_manager.db"
HOST = os.environ.get("LAN_HOST", "0.0.0.0")
PORT = int(os.environ.get("LAN_PORT", "8080"))
LOG_LEVEL = os.environ.get("LAN_LOG_LEVEL", "INFO").upper()
MAX_WORKERS = int(os.environ.get("LAN_MAX_WORKERS", "10"))  # parallel checks during a run
