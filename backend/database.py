import sqlite3
import math
from datetime import datetime

DB_FILE = "medjay.db"

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            trust_score INTEGER NOT NULL,
            result TEXT NOT NULL,
            date TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reported_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            reported_on TEXT NOT NULL
        )
    """)

    # Ensure there are enough real rows in SQLite to populate Pages 1, 2, and 3
    cursor.execute("SELECT COUNT(*) as count FROM scan_history")
    current_count = cursor.fetchone()["count"]

    if current_count < 12:
        seed_scans = [
            ("https://stackoverflow.com", 98, "Safe", "Nov 1, 2026, 09:15 AM"),
            ("http://free-prize-winner.xyz/claim", 15, "Unsafe", "Nov 1, 2026, 11:40 AM"),
            ("https://www.python.org", 100, "Safe", "Nov 2, 2026, 02:10 PM"),
            ("https://cloudflare.com", 100, "Safe", "Nov 2, 2026, 06:45 PM"),
            ("http://verify-bank-kyc.top/login", 10, "Unsafe", "Nov 3, 2026, 10:05 AM"),
            ("https://mozilla.org", 96, "Safe", "Nov 3, 2026, 03:30 PM"),
            ("https://unverified-redirect-link.net", 55, "Suspicious", "Nov 3, 2026, 08:12 PM"),
            ("https://npmjs.com", 95, "Safe", "Nov 4, 2026, 11:00 AM"),
            ("https://suspicious-login.net", 52, "Suspicious", "Nov 4, 2026, 01:22 PM"),
            ("https://github.com", 100, "Safe", "Nov 5, 2026, 04:05 PM"),
            ("https://example-phishing.com", 20, "Unsafe", "Nov 6, 2026, 08:17 PM"),
            ("https://www.wikipedia.org", 95, "Safe", "Nov 7, 2026, 10:24 AM"),
        ]
        # Only insert seed rows if the database is brand new, or top up missing rows
        if current_count == 0:
            cursor.executemany(
                "INSERT INTO scan_history (url, trust_score, result, date) VALUES (?, ?, ?, ?)",
                seed_scans
            )
        else:
            cursor.executemany(
                "INSERT INTO scan_history (url, trust_score, result, date) VALUES (?, ?, ?, ?)",
                seed_scans[:8]
            )

    conn.commit()
    conn.close()

def log_scan(url: str, trust_score: int, result: str):
    now = datetime.now().strftime("%b %d, %Y, %I:%M %p")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_history (url, trust_score, result, date) VALUES (?, ?, ?, ?)",
        (url, trust_score, result, now)
    )
    conn.commit()
    conn.close()

def get_history_and_stats(page: int = 1, limit: int = 5):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, url, trust_score, result, date FROM scan_history ORDER BY id DESC")
    all_rows = [dict(row) for row in cursor.fetchall()]

    # Calculate true counts directly from SQLite rows
    safe_count = sum(1 for r in all_rows if r["result"] == "Safe")
    unsafe_count = sum(1 for r in all_rows if r["result"] == "Unsafe")
    suspicious_count = sum(1 for r in all_rows if r["result"] == "Suspicious")
    total_count = len(all_rows)

    total_pages = max(1, math.ceil(total_count / limit))
    start_idx = (page - 1) * limit
    paginated_rows = all_rows[start_idx : start_idx + limit]

    conn.close()
    return {
        "history": all_rows,
        "page_items": paginated_rows,
        "pagination": {
            "page": page,
            "limit": limit,
            "total_pages": total_pages,
            "total_items": total_count
        },
        "stats": {
            "total": total_count,
            "safe": safe_count,
            "unsafe": unsafe_count,
            "suspicious": suspicious_count
        }
    }

def add_reported_domain(domain: str, original_url: str = ""):
    now = datetime.now().strftime("%b %d, %Y, %I:%M %p")
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT OR IGNORE INTO reported_domains (domain, reported_on) VALUES (?, ?)",
        (domain, now)
    )

    if original_url:
        cursor.execute(
            "UPDATE scan_history SET result = 'Unsafe', trust_score = MIN(trust_score, 25) WHERE url = ?",
            (original_url,)
        )

    conn.commit()
    conn.close()

def is_domain_reported(domain: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM reported_domains WHERE domain = ?", (domain,))
    found = cursor.fetchone() is not None
    conn.close()
    return found