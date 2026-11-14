"""
backend/database.py — SQLite Detection Audit Logger
===================================================
Provides a lightweight, zero-configuration SQLite interface via standard `sqlite3`
to persist all inference transactions (single flows and batch CSV uploads).

Table: detection_logs
  - id:              INTEGER PRIMARY KEY AUTOINCREMENT
  - timestamp:       TEXT (UTC ISO-8601 string)
  - source_type:     TEXT ('single_flow' or 'csv_upload')
  - total_flows:     INTEGER
  - intrusion_count: INTEGER
  - normal_count:    INTEGER
  - max_confidence:  REAL (0.0 to 1.0)
  - summary_json:    TEXT (serialized JSON metadata)
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.config import DATABASE_PATH


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """
    Opens a thread-safe connection to the SQLite database and sets row_factory to sqlite3.Row.
    """
    target_path = db_path or DATABASE_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """
    Initializes the SQLite database and creates the `detection_logs` table if it does not exist.
    """
    target_path = db_path or DATABASE_PATH
    with get_connection(target_path) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS detection_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_type TEXT NOT NULL,
                total_flows INTEGER NOT NULL,
                intrusion_count INTEGER NOT NULL,
                normal_count INTEGER NOT NULL,
                max_confidence REAL NOT NULL,
                summary_json TEXT
            );
            """
        )
        conn.commit()


def log_detection(
    source_type: str,
    total_flows: int,
    intrusion_count: int,
    normal_count: int,
    max_confidence: float,
    summary_json: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> int:
    """
    Inserts a new detection record into `detection_logs`.
    Returns the auto-generated primary key ID.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO detection_logs (
                timestamp, source_type, total_flows, intrusion_count,
                normal_count, max_confidence, summary_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                now_iso,
                source_type,
                int(total_flows),
                int(intrusion_count),
                int(normal_count),
                float(max_confidence),
                summary_json,
            ),
        )
        conn.commit()
        return cursor.lastrowid or 0


def get_recent_logs(limit: int = 20, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    Retrieves the most recent detection logs sorted in descending order of creation.
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, source_type, total_flows, intrusion_count,
                   normal_count, max_confidence, summary_json
            FROM detection_logs
            ORDER BY id DESC
            LIMIT ?;
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def clear_logs(db_path: Optional[Path] = None) -> int:
    """
    Deletes all records from `detection_logs`.
    Returns the count of deleted rows.
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM detection_logs;")
        count = cursor.fetchone()[0]
        cursor.execute("DELETE FROM detection_logs;")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='detection_logs';")
        conn.commit()
        return int(count)

