import sqlite3
import json
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "captures.db")

def init_db():
    """Creates the database table if it doesn't exist."""
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS captures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT,
                method TEXT,
                param TEXT,
                payload TEXT,
                token TEXT,
                status INTEGER,
                headers TEXT,
                body TEXT,
                elapsed_ms REAL
            )
        """)
        con.commit()

def save_capture(data):
    """Opens a fresh connection, saves a single capture, and closes it."""
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            INSERT INTO captures 
            (target_url, method, param, payload, token, status, headers, body, elapsed_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data["target_url"], data["method"], data["param"], data["payload"],
            data["token"], data["status"], json.dumps(data["headers"]),
            data["body"], data["elapsed_ms"]
        ))
        con.commit()