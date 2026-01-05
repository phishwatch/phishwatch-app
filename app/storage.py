import sqlite3
import json
from typing import List, Dict, Optional
from datetime import datetime

from .models import ScanResult


DB_PATH = "phishwatch.db"


# -------------------------------------------
# Database Initialization
# -------------------------------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            normalized_url TEXT NOT NULL,
            verdict TEXT NOT NULL,
            score INTEGER NOT NULL,
            explanation_json TEXT NOT NULL,
            indicators_json TEXT NOT NULL,
            external_json TEXT,
            timestamp TEXT NOT NULL
        )
        """
    )

    c.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_scans_timestamp
        ON scans (timestamp DESC)
        """
    )

    conn.commit()
    conn.close()


# -------------------------------------------
# Insert a ScanResult
# -------------------------------------------

def insert_scan(result: ScanResult):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    explanation_json = json.dumps(result.explanation)
    indicators_json = json.dumps(result.indicators)

    external = {
        "gsb": result.gsb_status,
        "vt": result.vt_status,
    }
    external_json = json.dumps(external)

    c.execute(
        """
        INSERT INTO scans (
            id, url, normalized_url,
            verdict, score,
            explanation_json, indicators_json, external_json,
            timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result.id,
            result.url,
            result.normalized_url,
            result.verdict,
            result.score,
            explanation_json,
            indicators_json,
            external_json,
            result.timestamp.isoformat(),
        ),
    )

    conn.commit()
    conn.close()


# -------------------------------------------
# Fetch Recent Scans
# -------------------------------------------

def get_recent_scans(limit: int = 20) -> List[dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute(
        """
        SELECT id, url, normalized_url, verdict, score, timestamp
        FROM scans
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    )

    rows = c.fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append(
            {
                "id": row[0],
                "url": row[1],
                "normalized_url": row[2],
                "verdict": row[3],
                "score": row[4],
                "timestamp": row[5],
            }
        )

    return results
