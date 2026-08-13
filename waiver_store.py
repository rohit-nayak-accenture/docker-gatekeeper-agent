"""Persistence for waivers and the decision audit log (Repository pattern).

WaiverStore only knows about SQLite — it has no opinion on policy rules.
"""

import sqlite3
from datetime import datetime

from models import PolicyDecision, Waiver


class WaiverStore:
    def __init__(self, db_path: str = "gatekeeper.db"):
        self.db_path = db_path
        self._create_tables()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _create_tables(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS waivers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    image TEXT NOT NULL,
                    cve_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    approved_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS decision_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    image TEXT NOT NULL,
                    image_tag TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    decided_at TEXT NOT NULL,
                    summary TEXT NOT NULL
                )
                """
            )

    def add_waiver(self, waiver: Waiver) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO waivers (image, cve_id, reason, approved_by, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    waiver.image,
                    waiver.cve_id,
                    waiver.reason,
                    waiver.approved_by,
                    waiver.created_at.isoformat(),
                    waiver.expires_at.isoformat(),
                ),
            )
            return cursor.lastrowid

    def get_active_waivers(
        self, image: str, as_of: datetime | None = None
    ) -> list[Waiver]:
        if as_of is None:
            as_of = datetime.now()

        active_waivers = []
        for waiver in self.get_all_waivers(image):
            if waiver.is_active(as_of=as_of):
                active_waivers.append(waiver)
        return active_waivers

    def get_all_waivers(self, image: str) -> list[Waiver]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, image, cve_id, reason, approved_by, created_at, expires_at
                FROM waivers
                WHERE image = ?
                """,
                (image,),
            ).fetchall()

        waivers = []
        for row in rows:
            waivers.append(self._row_to_waiver(row))
        return waivers

    def log_decision(self, decision: PolicyDecision) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO decision_audit_log (image, image_tag, verdict, decided_at, summary)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    decision.image,
                    decision.image_tag,
                    decision.overall_verdict.value,
                    decision.decided_at.isoformat(),
                    decision.summary,
                ),
            )

    def get_decision_history(self, image: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT image, image_tag, verdict, decided_at, summary
                FROM decision_audit_log
                WHERE image = ?
                ORDER BY decided_at DESC
                """,
                (image,),
            ).fetchall()

        history = []
        for row in rows:
            history.append(
                {
                    "image": row[0],
                    "image_tag": row[1],
                    "verdict": row[2],
                    "decided_at": row[3],
                    "summary": row[4],
                }
            )
        return history

    @staticmethod
    def _row_to_waiver(row: tuple) -> Waiver:
        return Waiver(
            id=row[0],
            image=row[1],
            cve_id=row[2],
            reason=row[3],
            approved_by=row[4],
            created_at=datetime.fromisoformat(row[5]),
            expires_at=datetime.fromisoformat(row[6]),
        )
