"""Build unified chats.db index from decrypted WeChat databases."""
import hashlib
import os
import sqlite3
from datetime import datetime


def _date_str_to_ts(date_str: str, end_of_day: bool = False) -> int:
    """Convert YYYY-MM-DD to Unix timestamp."""
    fmt = '%Y-%m-%d %H:%M:%S' if end_of_day else '%Y-%m-%d'
    if end_of_day:
        date_str = f'{date_str} 23:59:59'
    return int(datetime.strptime(date_str, fmt).timestamp())


def _build_time_where(start_date: str, end_date: str) -> tuple:
    """Build a WHERE clause string and params list for create_time filtering."""
    clauses = ["create_time > 1000000000"]
    params = []
    if start_date:
        clauses.append("create_time >= ?")
        params.append(_date_str_to_ts(start_date))
    if end_date:
        clauses.append("create_time <= ?")
        params.append(_date_str_to_ts(end_date, end_of_day=True))
    return "WHERE " + " AND ".join(clauses), params


def build_index(decrypted_dir: str, output_db: str, on_progress=None,
                start_date: str = None, end_date: str = None) -> str:
    """Build a unified chats.db from all message_N.db files.

    Schema:
        chats: chat_id, display_name, message_count, first_msg_time, last_msg_time, is_group
        messages: chat_id, local_id, local_type, create_time (lean metadata)

    Args:
        decrypted_dir: Path to output dir containing message/ subdirectory with message_N.db files
        output_db: Path to write chats.db (e.g., output_dir/data/chats.db)
        on_progress: Optional callback(detail, progress_0_to_1)
        start_date: YYYY-MM-DD start of message date range (None = unbounded)
        end_date: YYYY-MM-DD end of message date range (None = unbounded)

    Returns:
        Path to the created database.
    """
    where_clause, where_params = _build_time_where(start_date, end_date)

    os.makedirs(os.path.dirname(output_db), exist_ok=True)
    conn = sqlite3.connect(output_db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS chats (
            chat_id TEXT PRIMARY KEY,
            display_name TEXT,
            message_count INTEGER DEFAULT 0,
            first_msg_time INTEGER,
            last_msg_time INTEGER,
            is_group INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS messages (
            chat_id TEXT,
            local_id INTEGER,
            local_type INTEGER,
            create_time INTEGER,
            PRIMARY KEY (chat_id, local_id)
        );
    """)
    conn.execute("BEGIN")

    msg_dir = os.path.join(decrypted_dir, 'message')
    if not os.path.isdir(msg_dir):
        msg_dir = decrypted_dir  # fallback: raw dir itself

    db_files = sorted(
        [f for f in os.listdir(msg_dir) if f.endswith('.db')]
    ) if os.path.isdir(msg_dir) else []

    def _report(detail, progress):
        if on_progress:
            on_progress(detail, progress)

    _report("创建索引表...", 0.05)

    skipped = []
    for fi, fname in enumerate(db_files):
        db_path = os.path.join(msg_dir, fname)
        base_progress = 0.05 + (fi / len(db_files)) * 0.9
        _report(f"扫描 {fname}...", base_progress)
        try:
            src = sqlite3.connect(db_path)
            tables = src.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
            ).fetchall()
            for ti, (tname,) in enumerate(tables):
                h = tname[4:]  # strip "Msg_" prefix
                chat_id = _resolve_chat_id(src, h) or f"unknown_{h[:8]}"
                count, first, last = src.execute(
                    f"SELECT COUNT(*), MIN(create_time), MAX(create_time) FROM [{tname}] {where_clause}",
                    where_params
                ).fetchone()

                conn.execute(
                    """INSERT OR REPLACE INTO chats(chat_id, display_name,
                       message_count, first_msg_time, last_msg_time, is_group)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (chat_id, chat_id, count or 0, first, last,
                     1 if chat_id.endswith('@chatroom') else 0)
                )

                # Index message metadata (batch insert)
                rows = src.execute(
                    f"SELECT local_id, local_type, create_time FROM [{tname}] {where_clause}",
                    where_params
                ).fetchall()
                conn.executemany(
                    "INSERT OR IGNORE INTO messages(chat_id, local_id, local_type, create_time) VALUES (?, ?, ?, ?)",
                    [(chat_id, r[0], r[1], r[2]) for r in rows]
                )
                if tables:
                    table_progress = base_progress + (ti / len(tables)) * (0.9 / len(db_files))
                    _report(f"索引 {fname} ({ti+1}/{len(tables)})", table_progress)
            src.close()
        except sqlite3.Error:
            skipped.append(fname)
            _report(f"跳过损坏: {fname}", base_progress + 0.05)
            continue

    _report("提交索引...", 0.97)
    conn.commit()
    conn.close()
    if skipped:
        _report(f"索引完成 (跳过: {', '.join(skipped)})", 1.0)
    else:
        _report("索引完成", 1.0)
    return output_db


def _resolve_chat_id(conn, hash_val: str) -> str:
    """Resolve Msg_<hash> back to a username via the Name2Id table.

    Returns username on match, or None.
    """
    try:
        for (uname,) in conn.execute("SELECT user_name FROM Name2Id"):
            if uname and hashlib.md5(uname.encode()).hexdigest() == hash_val:
                return uname
    except sqlite3.Error:
        pass
    return None
