import sqlite3
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "telemetry.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  scam_type TEXT,
                  confidence INTEGER)''')
    conn.commit()
    conn.close()

def log_scan(scam_type: str, confidence: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO scans (timestamp, scam_type, confidence) VALUES (?, ?, ?)",
              (datetime.now().isoformat(), scam_type, confidence))
    conn.commit()
    conn.close()

def get_recent_telemetry() -> list:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT scam_type, confidence FROM scans ORDER BY timestamp DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return [{"scam_type": r[0], "confidence": r[1]} for r in rows]
