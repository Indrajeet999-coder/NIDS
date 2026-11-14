"""
backend/config.py — Application Configuration & Environment Settings
====================================================================
Loads runtime settings from `.env` with portable relative fallbacks
using pathlib.Path so the application runs identically on Windows and macOS.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# ── Project Root & Directories ───────────────────────────────────────────────
# backend/ is one level below project root
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

# Load .env file from project root if present
load_dotenv(PROJECT_ROOT / ".env")

# ── Server Settings ──────────────────────────────────────────────────────────
BACKEND_HOST = os.getenv("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = int(os.getenv("BACKEND_PORT", "8000"))

# ── Model & Artifact Paths ───────────────────────────────────────────────────
# Relative path from project root or absolute override
MODEL_PATH_SETTING = os.getenv("MODEL_PATH", "ml/models/nids_bundle.joblib")
MODEL_PATH = (
    Path(MODEL_PATH_SETTING)
    if Path(MODEL_PATH_SETTING).is_absolute()
    else (PROJECT_ROOT / MODEL_PATH_SETTING).resolve()
)

METRICS_PATH = (PROJECT_ROOT / "ml" / "results" / "metrics.json").resolve()
DEMO_FLOWS_PATH = (PROJECT_ROOT / "dataset" / "processed" / "demo_test_flows.csv").resolve()

# ── Database Path & URL ──────────────────────────────────────────────────────
# Supports sqlite:///./backend/detections.db or custom paths
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./backend/detections.db")

def resolve_db_path(url: str) -> Path:
    """Extracts and resolves SQLite database file path from a database URL."""
    prefix = "sqlite:///"
    if url.startswith(prefix):
        raw_path = url[len(prefix):]
        # Handle relative prefixes like ./ or .\
        if raw_path.startswith("./") or raw_path.startswith(".\\"):
            raw_path = raw_path[2:]
        return (PROJECT_ROOT / raw_path).resolve()
    return (BASE_DIR / "detections.db").resolve()

DATABASE_PATH = resolve_db_path(DATABASE_URL)

# Ensure parent directory for database exists
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

# ── CORS Settings (Vite React frontend dev server) ───────────────────────────
CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

