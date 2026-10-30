"""Database Access and Assessment Model Module

Provides SQLite initialization, migration, and query interfaces for security
assessment records, ensuring safe parameterized queries, search, and filtering.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Creates a configured connection to the SQLite database with Row factory."""
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    # Enforce foreign keys & WAL mode if file-based
    if db_path != ":memory:":
        conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db(db_path: str) -> None:
    """Initializes the database schema if tables do not exist."""
    conn = get_db_connection(db_path)
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                final_url TEXT NOT NULL,
                hostname TEXT NOT NULL,
                ip_address TEXT,
                scan_timestamp TEXT NOT NULL,
                http_status INTEGER,
                outcome TEXT NOT NULL,
                confidence TEXT NOT NULL,
                xfo_present INTEGER NOT NULL,
                xfo_raw TEXT,
                xfo_status TEXT NOT NULL,
                xfo_details TEXT,
                csp_present INTEGER NOT NULL,
                csp_raw TEXT,
                csp_frame_ancestors TEXT,
                csp_status TEXT NOT NULL,
                csp_details TEXT,
                other_headers_json TEXT,
                redirects_json TEXT,
                explanation TEXT NOT NULL,
                remediation TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_assessments_hostname 
            ON assessments(hostname);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_assessments_outcome 
            ON assessments(outcome);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_assessments_timestamp 
            ON assessments(scan_timestamp DESC);
            """
        )
    conn.close()


class AssessmentRepository:
    """Repository handling all CRUD operations for Assessment entities."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        init_db(db_path)

    def save(self, data: Dict[str, Any]) -> str:
        """Saves a new scan assessment to the database and returns its UUID."""
        assessment_id = data.get("id") or str(uuid.uuid4())
        timestamp = data.get("scan_timestamp") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        other_headers_json = json.dumps(data.get("other_headers", {}))
        redirects_json = json.dumps(data.get("redirects", []))

        conn = get_db_connection(self.db_path)
        with conn:
            conn.execute(
                """
                INSERT INTO assessments (
                    id, url, final_url, hostname, ip_address, scan_timestamp,
                    http_status, outcome, confidence,
                    xfo_present, xfo_raw, xfo_status, xfo_details,
                    csp_present, csp_raw, csp_frame_ancestors, csp_status, csp_details,
                    other_headers_json, redirects_json, explanation, remediation
                ) VALUES (
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?
                );
                """,
                (
                    assessment_id,
                    data.get("url", ""),
                    data.get("final_url", data.get("url", "")),
                    data.get("hostname", ""),
                    data.get("ip_address", "N/A"),
                    timestamp,
                    data.get("http_status"),
                    data.get("outcome", "Inconclusive"),
                    data.get("confidence", "Medium"),
                    1 if data.get("xfo_present") else 0,
                    data.get("xfo_raw"),
                    data.get("xfo_status", "Missing"),
                    data.get("xfo_details", ""),
                    1 if data.get("csp_present") else 0,
                    data.get("csp_raw"),
                    data.get("csp_frame_ancestors"),
                    data.get("csp_status", "Missing"),
                    data.get("csp_details", ""),
                    other_headers_json,
                    redirects_json,
                    data.get("explanation", ""),
                    data.get("remediation", ""),
                ),
            )
        conn.close()
        return assessment_id

    def get_by_id(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves an assessment record by its unique ID."""
        conn = get_db_connection(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,))
        row = cur.fetchone()
        conn.close()

        if not row:
            return None

        result = dict(row)
        try:
            result["other_headers"] = json.loads(result.get("other_headers_json") or "{}")
        except Exception:
            result["other_headers"] = {}

        try:
            result["redirects"] = json.loads(result.get("redirects_json") or "[]")
        except Exception:
            result["redirects"] = []

        return result

    def list_assessments(
        self,
        search_query: Optional[str] = None,
        outcome_filter: Optional[str] = None,
        sort_by: str = "date_desc",
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Lists assessments with search, filtering, and sorting."""
        conn = get_db_connection(self.db_path)
        cur = conn.cursor()

        query = "SELECT * FROM assessments WHERE 1=1"
        params: List[Any] = []

        if search_query:
            query += " AND (hostname LIKE ? OR url LIKE ? OR final_url LIKE ?)"
            wildcard = f"%{search_query.strip()}%"
            params.extend([wildcard, wildcard, wildcard])

        if outcome_filter and outcome_filter.lower() != "all":
            query += " AND outcome = ?"
            params.append(outcome_filter)

        # Ordering
        if sort_by == "date_asc":
            query += " ORDER BY scan_timestamp ASC"
        elif sort_by == "status":
            query += " ORDER BY outcome ASC, scan_timestamp DESC"
        elif sort_by == "hostname":
            query += " ORDER BY hostname ASC, scan_timestamp DESC"
        else:
            query += " ORDER BY scan_timestamp DESC"

        query += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()

        results = []
        for r in rows:
            item = dict(r)
            try:
                item["other_headers"] = json.loads(item.get("other_headers_json") or "{}")
            except Exception:
                item["other_headers"] = {}
            results.append(item)
        return results

    def delete(self, assessment_id: str) -> bool:
        """Deletes a single assessment by ID."""
        conn = get_db_connection(self.db_path)
        with conn:
            cur = conn.execute("DELETE FROM assessments WHERE id = ?", (assessment_id,))
            deleted = cur.rowcount > 0
        conn.close()
        return deleted

    def clear_all(self) -> int:
        """Clears all assessment history records."""
        conn = get_db_connection(self.db_path)
        with conn:
            cur = conn.execute("DELETE FROM assessments")
            count = cur.rowcount
        conn.close()
        return count

    def get_statistics(self) -> Dict[str, Any]:
        """Calculates summary statistics across all assessments."""
        conn = get_db_connection(self.db_path)
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM assessments")
        total = cur.fetchone()[0] or 0

        cur.execute("SELECT COUNT(*) FROM assessments WHERE outcome = 'Protected'")
        protected = cur.fetchone()[0] or 0

        cur.execute("SELECT COUNT(*) FROM assessments WHERE outcome = 'Potential Risk'")
        potential_risk = cur.fetchone()[0] or 0

        cur.execute("SELECT COUNT(*) FROM assessments WHERE outcome = 'Inconclusive'")
        inconclusive = cur.fetchone()[0] or 0

        # Anti-framing mechanism breakdown
        cur.execute("SELECT COUNT(*) FROM assessments WHERE xfo_present = 1")
        xfo_count = cur.fetchone()[0] or 0

        cur.execute("SELECT COUNT(*) FROM assessments WHERE csp_present = 1")
        csp_count = cur.fetchone()[0] or 0

        cur.execute(
            """
            SELECT COUNT(*) FROM assessments 
            WHERE xfo_present = 1 AND csp_present = 1
            """
        )
        both_count = cur.fetchone()[0] or 0

        conn.close()

        protected_pct = round((protected / total * 100), 1) if total > 0 else 0.0
        risk_pct = round((potential_risk / total * 100), 1) if total > 0 else 0.0
        inconclusive_pct = round((inconclusive / total * 100), 1) if total > 0 else 0.0

        return {
            "total": total,
            "protected": protected,
            "potential_risk": potential_risk,
            "inconclusive": inconclusive,
            "protected_pct": protected_pct,
            "risk_pct": risk_pct,
            "inconclusive_pct": inconclusive_pct,
            "xfo_count": xfo_count,
            "csp_count": csp_count,
            "both_count": both_count,
        }
