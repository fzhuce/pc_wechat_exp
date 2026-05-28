from __future__ import annotations

import hashlib
import heapq
import math
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..adapter import (
    _iter_message_db_paths,
    _load_contact_rows,
    _pick_display_name,
    _should_keep_session,
    _year_range_epoch_seconds,
    get_account_wxid,
)

import logging
logger = logging.getLogger(__name__)


def _mask_name(name: str) -> str:
    s = str(name or "").strip()
    if not s:
        return ""
    if len(s) == 1:
        return "*"
    if len(s) == 2:
        return s[0] + "*"
    return s[0] + ("*" * (len(s) - 2)) + s[-1]


def _format_duration_zh(seconds: int | None) -> str:
    if seconds is None:
        return ""
    try:
        s = int(seconds)
    except Exception:
        s = 0
    if s < 0:
        s = 0

    if s < 60:
        return f"{s}秒"
    m, sec = divmod(s, 60)
    if m < 60:
        return f"{m}分{sec}秒" if sec else f"{m}分钟"
    h, mm = divmod(m, 60)
    if h < 24:
        return f"{h}小时{mm}分钟" if mm else f"{h}小时"
    d, hh = divmod(h, 24)
    return f"{d}天{hh}小时" if hh else f"{d}天"


@dataclass
class _ConvAgg:
    username: str
    incoming: int
    outgoing: int
    replies: int
    sum_gap: int
    sum_gap_capped: int
    min_gap: int
    max_gap: int

    @property
    def total(self) -> int:
        return int(self.incoming) + int(self.outgoing)

    def avg_gap(self) -> float:
        return float(self.sum_gap) / float(self.replies) if self.replies > 0 else 0.0

    def avg_gap_capped(self) -> float:
        return float(self.sum_gap_capped) / float(self.replies) if self.replies > 0 else 0.0


def _score_conv(*, agg: _ConvAgg, tau_seconds: float) -> float:
    interaction = float(min(int(agg.incoming), int(agg.outgoing)))
    if interaction <= 0.0 or agg.replies <= 0:
        return 0.0

    avg_s = float(agg.avg_gap_capped())
    speed_score = 1.0 / (1.0 + (avg_s / float(max(1.0, tau_seconds))))

    volume_score = math.log1p(interaction)
    return float(speed_score * volume_score)


def _resolve_chat_username(conn, table_name: str) -> str | None:
    """Resolve Msg_<hash> table back to a username via Name2Id + MD5."""
    hash_val = table_name[4:] if table_name.startswith("Msg_") else table_name
    try:
        for (uname,) in conn.execute("SELECT user_name FROM Name2Id"):
            if uname and hashlib.md5(
                uname.encode() if isinstance(uname, str) else uname
            ).hexdigest() == hash_val:
                return uname if isinstance(uname, str) else uname.decode("utf-8", errors="ignore")
    except sqlite3.Error:
        pass
    return None


def _resolve_sender_ids(conn, rowids: set) -> dict:
    """Batch-resolve real_sender_id values to usernames via Name2Id."""
    mapping = {}
    if not rowids:
        return mapping
    for rid in rowids:
        try:
            row = conn.execute("SELECT user_name FROM Name2Id WHERE rowid = ?", (int(rid),)).fetchone()
            if row:
                u = row[0]
                mapping[rid] = u if isinstance(u, str) else u.decode("utf-8", errors="ignore")
        except (sqlite3.Error, ValueError, TypeError):
            pass
    return mapping


def compute_reply_speed_stats(*, account_dir: Path, year: int) -> dict[str, Any]:
    """Compute reply speed statistics by scanning raw message databases.

    For each non-group 1-on-1 chat, track sender transitions (reply events)
    and measure reply gap times. Scores each contact by speed * volume.
    """
    start_ts, end_ts = _year_range_epoch_seconds(int(year))
    gap_cap_seconds = 6 * 60 * 60
    tau_seconds = 30 * 60

    my_wxid = get_account_wxid(account_dir)
    db_paths = _iter_message_db_paths(account_dir)
    if not db_paths:
        logger.warning("card_03 reply_speed: no message DBs found in %s", str(account_dir))
        return _empty_result(year, gap_cap_seconds, tau_seconds)

    contact_db_path = account_dir / "contact" / "contact.db"
    if not contact_db_path.exists():
        contact_db_path = account_dir / "contact.db"

    conv_aggs: dict[str, _ConvAgg] = {}
    contact_peak_hours: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    all_reply_events = 0
    all_contacts_sent = set()

    for db_path in db_paths:
        if not db_path.exists():
            continue
        try:
            conn = sqlite3.connect(str(db_path))
        except sqlite3.Error:
            continue
        try:
            tables = [
                t[0] for t in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
                ).fetchall()
            ]
            if not tables:
                continue

            for tname in tables:
                chat_user = _resolve_chat_username(conn, tname)
                if not chat_user or chat_user.endswith("@chatroom"):
                    continue

                rows = conn.execute(
                    f'SELECT real_sender_id, create_time, origin_source FROM "{tname}" '
                    "WHERE create_time >= ? AND create_time < ? AND create_time > 1000000000 "
                    "ORDER BY create_time ASC",
                    (start_ts, end_ts),
                ).fetchall()

                if len(rows) < 2:
                    continue

                # Collect sender IDs for batch resolution
                sender_ids = {r[0] for r in rows if r[0]}
                sender_map = _resolve_sender_ids(conn, sender_ids)

                prev_is_me: bool | None = None
                prev_ts: int = 0
                chat_replies = 0
                chat_incoming = 0
                chat_outgoing = 0
                chat_sum_gap = 0
                chat_sum_gap_capped = 0
                chat_min_gap = 2**63
                chat_max_gap = 0

                for sender_id, ts, origin in rows:
                    is_me = origin == 1
                    if is_me:
                        chat_outgoing += 1
                        all_contacts_sent.add(chat_user)
                    else:
                        chat_incoming += 1

                    hour = (ts // 3600) % 24
                    contact_peak_hours[chat_user][hour] += 1

                    if prev_is_me is not None and is_me != prev_is_me:
                        gap = int(ts) - int(prev_ts)
                        if 0 < gap < gap_cap_seconds:
                            chat_replies += 1
                            chat_sum_gap += gap
                            chat_sum_gap_capped += min(gap, gap_cap_seconds)
                            if gap < chat_min_gap:
                                chat_min_gap = gap
                            if gap > chat_max_gap:
                                chat_max_gap = gap

                    prev_is_me = is_me
                    prev_ts = ts

                if chat_replies > 0:
                    agg = _ConvAgg(
                        username=chat_user,
                        incoming=chat_incoming,
                        outgoing=chat_outgoing,
                        replies=chat_replies,
                        sum_gap=chat_sum_gap,
                        sum_gap_capped=chat_sum_gap_capped,
                        min_gap=chat_min_gap if chat_min_gap != 2**63 else 0,
                        max_gap=chat_max_gap,
                    )
                    conv_aggs[chat_user] = agg
                    all_reply_events += chat_replies
        finally:
            conn.close()

    if not conv_aggs:
        return _empty_result(year, gap_cap_seconds, tau_seconds)

    # Load contact display names
    contact_rows = _load_contact_rows(contact_db_path, list(conv_aggs.keys())) if contact_db_path.exists() else {}

    # Score and rank
    scored = []
    for username, agg in conv_aggs.items():
        score = _score_conv(agg=agg, tau_seconds=float(tau_seconds))
        row = contact_rows.get(username)
        display = _pick_display_name(row, username)
        peak_items = sorted(contact_peak_hours.get(username, {}).items(), key=lambda x: x[1], reverse=True)
        peak_hour = peak_items[0][0] if peak_items else None
        peak_label = f"{peak_hour}:00-{(peak_hour + 1) % 24}:00" if peak_hour is not None else ""

        entry = {
            "username": username,
            "displayName": display,
            "maskedName": display,
            "avatarUrl": row["small_head_url"] if row and row["small_head_url"] else "",
            "totalMessages": agg.total,
            "incoming": agg.incoming,
            "outgoing": agg.outgoing,
            "replies": agg.replies,
            "avgReplySeconds": agg.avg_gap(),
            "minReplySeconds": agg.min_gap,
            "maxReplySeconds": agg.max_gap,
            "score": round(float(score), 4),
            "peakHour": peak_hour,
            "peakHourLabel": peak_label,
            "longestStreakDays": 0,
        }
        scored.append(entry)

    scored.sort(key=lambda x: x["score"], reverse=True)

    best = scored[0] if scored else None
    fastest = min(
        (e for e in scored if e["minReplySeconds"] > 0),
        key=lambda x: x["minReplySeconds"],
        default=None,
    )
    slowest = max(
        (e for e in scored if e["maxReplySeconds"] > 0),
        key=lambda x: x["maxReplySeconds"],
        default=None,
    )

    overall_fastest = fastest["minReplySeconds"] if fastest else None
    overall_slowest = slowest["maxReplySeconds"] if slowest else None

    reply_stats = None
    if scored:
        gaps = [e["avgReplySeconds"] for e in scored if e["avgReplySeconds"] > 0]
        if gaps:
            reply_stats = {
                "meanSeconds": round(sum(gaps) / len(gaps), 1),
                "medianSeconds": round(sorted(gaps)[len(gaps) // 2], 1),
                "totalReplyEvents": all_reply_events,
                "contactsWithReplies": len(gaps),
            }

    return {
        "year": int(year),
        "sentToContacts": len(all_contacts_sent),
        "replyEvents": all_reply_events,
        "replyStats": reply_stats,
        "fastestReplySeconds": overall_fastest,
        "longestReplySeconds": overall_slowest,
        "bestBuddy": best,
        "fastest": fastest,
        "slowest": slowest,
        "topBuddies": scored[:6],
        "topTotals": sorted(scored, key=lambda x: x["totalMessages"], reverse=True)[:6],
        "allContacts": scored,
        "race": None,
        "settings": {
            "gapCapSeconds": int(gap_cap_seconds),
            "tauSeconds": int(tau_seconds),
            "usedIndex": False,
            "indexStatus": "raw_scan",
        },
    }


def _empty_result(year: int, gap_cap_seconds: int, tau_seconds: int) -> dict[str, Any]:
    return {
        "year": int(year),
        "sentToContacts": 0,
        "replyEvents": 0,
        "replyStats": None,
        "fastestReplySeconds": None,
        "longestReplySeconds": None,
        "bestBuddy": None,
        "fastest": None,
        "slowest": None,
        "topBuddies": [],
        "topTotals": [],
        "allContacts": [],
        "race": None,
        "settings": {
            "gapCapSeconds": int(gap_cap_seconds),
            "tauSeconds": int(tau_seconds),
            "usedIndex": False,
            "indexStatus": None,
        },
    }


def build_card_03_reply_speed(*, account_dir: Path, year: int) -> dict[str, Any]:
    stats = compute_reply_speed_stats(account_dir=account_dir, year=year)

    fastest = stats.get("fastestReplySeconds")
    longest = stats.get("longestReplySeconds")
    best = stats.get("bestBuddy") or None
    replies = int(stats.get("replyEvents") or 0)

    if replies <= 0:
        narrative = "今年你还没有可统计的“回复”记录（或尚未构建搜索索引）。"
    else:
        parts: list[str] = []
        if fastest is not None:
            parts.append(f"最快一次，你只用了 {_format_duration_zh(int(fastest))} 就回了消息。")
        if longest is not None:
            parts.append(f"最长一次，你让对方等了 {_format_duration_zh(int(longest))}。")
        if best and isinstance(best, dict) and best.get("displayName"):
            avg_s = best.get("avgReplySeconds")
            try:
                avg_i = int(round(float(avg_s or 0.0)))
            except Exception:
                avg_i = 0
            parts.append(
                f"最像你的聊天搭子是「{_mask_name(str(best.get('displayName') or ''))}」，平均每条回复用时 {_format_duration_zh(avg_i)}。"
            )
        narrative = "".join(parts) if parts else "你的回复速度，藏着你最在意的人。"

    return {
        "id": 3,
        "title": "谁是你「秒回」的置顶关心？",
        "scope": "global",
        "category": "B",
        "status": "ok",
        "kind": "chat/reply_speed",
        "narrative": narrative,
        "data": stats,
    }
