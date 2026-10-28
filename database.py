import sqlite3
from typing import List, Optional, Dict, Any
from config import cfg


def get_connection() -> sqlite3.Connection:
    """Connects to the SQLite database stored in ~/.vindexav/vindexav.db."""
    conn = sqlite3.connect(str(cfg.db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes tables for scan jobs, flagged detections, and quarantine records."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target_path TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            status TEXT NOT NULL,
            files_scanned INTEGER DEFAULT 0,
            threats_found INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            file_path TEXT NOT NULL,
            file_name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            verdict TEXT NOT NULL,
            score INTEGER NOT NULL,
            reasons TEXT,
            quarantined BOOLEAN DEFAULT 0,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT NOT NULL,
            vault_filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            verdict TEXT NOT NULL,
            reasons TEXT,
            quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def insert_scan(scan_id: str, target_path: str, scan_type: str, status: str = "running"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (id, target_path, scan_type, status)
        VALUES (?, ?, ?, ?)
    """, (scan_id, target_path, scan_type, status))
    conn.commit()
    conn.close()


def update_scan_progress(scan_id: str, files_scanned: int, threats_found: int, status: str = "running", completed: bool = False):
    conn = get_connection()
    cursor = conn.cursor()
    if completed:
        cursor.execute("""
            UPDATE scans
            SET files_scanned = ?, threats_found = ?, status = ?, completed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (files_scanned, threats_found, status, scan_id))
    else:
        cursor.execute("""
            UPDATE scans
            SET files_scanned = ?, threats_found = ?, status = ?
            WHERE id = ?
        """, (files_scanned, threats_found, status, scan_id))
    conn.commit()
    conn.close()


def insert_detection(scan_id: Optional[str], file_path: str, file_name: str, sha256: str, verdict: str, score: int, reasons: str, quarantined: bool = False):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO detections (scan_id, file_path, file_name, sha256, verdict, score, reasons, quarantined)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (scan_id, file_path, file_name, sha256, verdict, score, reasons, 1 if quarantined else 0))
    conn.commit()
    conn.close()


def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    scan = dict(row)
    cursor.execute("SELECT * FROM detections WHERE scan_id = ? ORDER BY id DESC", (scan_id,))
    scan["detections"] = [dict(d) for d in cursor.fetchall()]
    conn.close()
    return scan


def get_all_scans() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 50")
    scans = [dict(r) for r in cursor.fetchall()]
    for s in scans:
        cursor.execute("SELECT * FROM detections WHERE scan_id = ?", (s["id"],))
        s["detections"] = [dict(d) for d in cursor.fetchall()]
    conn.close()
    return scans


def get_system_stats() -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM detections WHERE verdict IN ('suspicious', 'malicious')")
    threats_found = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM quarantine")
    quarantined_files = cursor.fetchone()[0]

    cursor.execute("SELECT created_at FROM scans ORDER BY created_at DESC LIMIT 1")
    last_scan = cursor.fetchone()
    last_scan_time = last_scan[0] if last_scan else None

    conn.close()
    return {
        "total_scans": total_scans,
        "threats_found": threats_found,
        "quarantined_files": quarantined_files,
        "last_scan_time": last_scan_time
    }


def insert_quarantine_record(original_path: str, vault_filename: str, sha256: str, verdict: str, reasons: str) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO quarantine (original_path, vault_filename, sha256, verdict, reasons)
        VALUES (?, ?, ?, ?, ?)
    """, (original_path, vault_filename, sha256, verdict, reasons))
    q_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return q_id


def get_quarantine_items() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM quarantine ORDER BY quarantined_at DESC")
    items = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return items


def get_quarantine_item(item_id: int) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM quarantine WHERE id = ?", (item_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


# Aliases for compatibility across engine and server modules
get_quarantine_item_by_id = get_quarantine_item


def delete_quarantine_record(item_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM quarantine WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()

def get_detections_for_scan(scan_id: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, file_path, file_name, sha256, verdict, score, reasons, quarantined, detected_at
        FROM detections
        WHERE scan_id = ?
        ORDER BY detected_at DESC
    """, (scan_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# Alias for compatibility across engine and server modules
remove_quarantine_record = delete_quarantine_record
