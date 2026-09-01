"""Small SQLite persistence boundary for the ticketing example."""

from __future__ import annotations

import sqlite3
from pathlib import Path

_DEMO_DIRECTORY = Path(__file__).resolve().parents[1] / ".demo"
_DATABASE_PATH = _DEMO_DIRECTORY / "merchant.sqlite3"


def _connect() -> sqlite3.Connection:
    _DEMO_DIRECTORY.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(_DATABASE_PATH, timeout=5.0)


def _initialize_database() -> None:
    with _connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS processed_webhook_events (
                event_id TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS attendee_roster (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payment_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admission_passes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payment_id TEXT NOT NULL
            );
            """
        )


def claim_webhook_event(event_id: str) -> bool:
    """Atomically claim one provider event in the demo's persistent store."""

    with _connect() as connection:
        cursor = connection.execute(
            "INSERT OR IGNORE INTO processed_webhook_events(event_id) VALUES (?)",
            (event_id,),
        )
        return cursor.rowcount == 1


def record_roster_binding(payment_id: str) -> int:
    with _connect() as connection:
        cursor = connection.execute(
            "INSERT INTO attendee_roster(payment_id) VALUES (?)",
            (payment_id,),
        )
        return int(cursor.lastrowid)


def record_admission_pass(payment_id: str) -> int:
    with _connect() as connection:
        cursor = connection.execute(
            "INSERT INTO admission_passes(payment_id) VALUES (?)",
            (payment_id,),
        )
        return int(cursor.lastrowid)


_initialize_database()
