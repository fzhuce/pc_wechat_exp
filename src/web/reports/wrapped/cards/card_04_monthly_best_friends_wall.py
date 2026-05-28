from __future__ import annotations

import calendar
import hashlib
import math
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone, timedelta
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

TZ = timezone(timedelta(hours=8))


def _mask_name(name: str) -> str:
    s = str(name or "").strip()
    if not s:
        return ""
    if len(s) == 1:
        return "*"
    if len(s) == 2:
        return s[0] + "*"
    return s[0] + ("*" * (len(s) - 2)) + s[-1]


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


def _month_range_epoch(year: int, month: int) -> tuple[int, int]:
    """Return (start_epoch, end_epoch) for a given year/month in CST."""
    start = datetime(year, month, 1, 0, 0, 0, tzinfo=TZ)
    if month == 12:
        end = datetime(year + 1, 1, 1, 0, 0, 0, tzinfo=TZ)
    else:
        end = datetime(year, month + 1, 1, 0, 0, 0, tzinfo=TZ)
    return int(start.timestamp()), int(end.timestamp())


def _days_in_month(year: int, month: int) -> int:
    return calendar.monthrange(year, month)[1]


def compute_monthly_best_friends_wall_stats(*, account_dir: Path, year: int) -> dict[str, Any]:
    """Compute monthly best friends by scanning raw message databases.

    For each month, scores non-group contacts on interaction volume, reply speed,
    active-day continuity, and coverage. Returns the top contact per month.
    """
    gap_cap_seconds = 6 * 60 * 60
    tau_seconds = 30 * 60
    weights = {
        "interaction": 0.40,
        "speed": 0.30,
        "continuity": 0.20,
        "coverage": 0.10,
    }
    eligibility = {
        "minTotalMessages": 8,
        "minInteraction": 3,
        "minReplyCount": 1,
        "minActiveDays": 2,
    }

    my_wxid = get_account_wxid(account_dir)
    db_paths = _iter_message_db_paths(account_dir)
    if not db_paths:
        logger.warning("card_04 monthly_best_friends: no message DBs in %s", str(account_dir))
        return _empty_monthly_result(year, weights, tau_seconds, gap_cap_seconds, eligibility)

    contact_db_path = account_dir / "contact" / "contact.db"
    if not contact_db_path.exists():
        contact_db_path = account_dir / "contact.db"

    # Per-month per-contact aggregates
    class MonthAgg:
        def __init__(self):
            self.total = 0
            self.incoming = 0
            self.outgoing = 0
            self.replies = 0
            self.sum_gap = 0
            self.sum_gap_capped = 0
            self.active_days: set = set()

    monthly_contacts: dict[int, dict[str, MonthAgg]] = {m: defaultdict(MonthAgg) for m in range(1, 13)}
    all_usernames: set = set()

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
                    "WHERE create_time > 1000000000 "
                    "ORDER BY create_time ASC",
                ).fetchall()

                if not rows:
                    continue

                all_usernames.add(chat_user)

                # Pre-group rows by month to avoid O(n*m) scanning
                month_rows: dict[int, list] = defaultdict(list)
                for r in rows:
                    ts = r[1]
                    dt = datetime.fromtimestamp(ts, tz=TZ)
                    if dt.year != year:
                        continue
                    month_rows[dt.month].append(r)

                for month, mrows in month_rows.items():
                    agg = monthly_contacts[month][chat_user]
                    agg.total += len(mrows)
                    prev_is_me = None
                    prev_ts = 0

                    for sender_id, ts, origin in mrows:
                        is_me = origin == 1
                        if is_me:
                            agg.outgoing += 1
                        else:
                            agg.incoming += 1
                        day = datetime.fromtimestamp(ts, tz=TZ).day
                        agg.active_days.add(day)

                        if prev_is_me is not None and is_me != prev_is_me:
                            gap = int(ts) - int(prev_ts)
                            if 0 < gap < gap_cap_seconds:
                                agg.replies += 1
                                agg.sum_gap += gap
                                agg.sum_gap_capped += min(gap, gap_cap_seconds)

                        prev_is_me = is_me
                        prev_ts = ts
        finally:
            conn.close()

    # Load contact display names
    contact_rows = _load_contact_rows(contact_db_path, list(all_usernames)) if contact_db_path.exists() else {}

    # Score each month
    months_out = []
    champion_counts: dict[str, int] = defaultdict(int)

    for month in range(1, 13):
        days_in_mo = _days_in_month(year, month)
        month_contacts = monthly_contacts[month]

        candidates = []
        for username, agg in month_contacts.items():
            if agg.total < eligibility["minTotalMessages"]:
                continue
            interaction = min(agg.incoming, agg.outgoing)
            if interaction < eligibility["minInteraction"]:
                continue
            if agg.replies < eligibility["minReplyCount"]:
                continue
            if len(agg.active_days) < eligibility["minActiveDays"]:
                continue

            avg_reply = float(agg.sum_gap_capped) / float(agg.replies) if agg.replies > 0 else float(tau_seconds)
            active_days = len(agg.active_days)

            interaction_score = math.log1p(float(interaction))
            speed_score = 1.0 / (1.0 + avg_reply / float(tau_seconds))
            continuity_score = min(active_days / float(days_in_mo), 1.0)
            coverage_score = math.log1p(float(active_days))

            score = (
                weights["interaction"] * interaction_score
                + weights["speed"] * speed_score
                + weights["continuity"] * continuity_score
                + weights["coverage"] * coverage_score
            )

            row = contact_rows.get(username)
            display = _pick_display_name(row, username)
            candidates.append({
                "username": username,
                "displayName": display,
                "maskedName": display,
                "avatarUrl": row["small_head_url"] if row and row["small_head_url"] else "",
                "score": round(float(score), 4),
                "totalMessages": agg.total,
                "interaction": interaction,
                "replies": agg.replies,
                "avgReplySeconds": round(float(avg_reply), 1),
                "activeDays": active_days,
                "metrics": {
                    "interactionScore": round(float(interaction_score), 4),
                    "speedScore": round(float(speed_score), 4),
                    "continuityScore": round(float(continuity_score), 4),
                    "coverageScore": round(float(coverage_score), 4),
                },
            })

        candidates.sort(key=lambda x: x["score"], reverse=True)

        if candidates:
            winner = candidates[0]
            champion_counts[winner["username"]] += 1
            months_out.append({
                "month": month,
                "winner": winner,
                "metrics": winner.get("metrics"),
                "raw": None,
                "isFallback": False,
                "reason": None,
            })
        else:
            months_out.append({
                "month": month,
                "winner": None,
                "metrics": None,
                "raw": None,
                "isFallback": False,
                "reason": "no_eligible_contact",
            })

    # Determine overall champion
    top_champion = None
    months_with_winner = sum(1 for m in months_out if m["winner"] is not None)
    if champion_counts:
        best_username, best_count = max(champion_counts.items(), key=lambda x: (x[1], x[0]))
        row = contact_rows.get(best_username)
        display = _pick_display_name(row, best_username)
        top_champion = {
            "username": best_username,
            "displayName": display,
            "maskedName": display,
            "avatarUrl": row["small_head_url"] if row and row["small_head_url"] else "",
            "monthsWon": best_count,
        }

    filled = [m["month"] for m in months_out if m["winner"] is not None]

    return {
        "year": int(year),
        "months": months_out,
        "summary": {
            "monthsWithWinner": months_with_winner,
            "topChampion": top_champion,
            "filledMonths": filled,
        },
        "settings": {
            "weights": {
                "interaction": float(weights["interaction"]),
                "speed": float(weights["speed"]),
                "continuity": float(weights["continuity"]),
                "coverage": float(weights["coverage"]),
            },
            "tauSeconds": int(tau_seconds),
            "gapCapSeconds": int(gap_cap_seconds),
            "eligibility": {
                "minTotalMessages": int(eligibility["minTotalMessages"]),
                "minInteraction": int(eligibility["minInteraction"]),
                "minReplyCount": int(eligibility["minReplyCount"]),
                "minActiveDays": int(eligibility["minActiveDays"]),
            },
            "usedIndex": False,
            "indexStatus": "raw_scan",
        },
    }


def _empty_monthly_result(year, weights, tau_seconds, gap_cap_seconds, eligibility) -> dict[str, Any]:
    months: list[dict[str, Any]] = []
    for month in range(1, 13):
        months.append({
            "month": month,
            "winner": None,
            "metrics": None,
            "raw": None,
            "isFallback": False,
            "reason": "fts5_unavailable",
        })
    return {
        "year": int(year),
        "months": months,
        "summary": {
            "monthsWithWinner": 0,
            "topChampion": None,
            "filledMonths": [],
        },
        "settings": {
            "weights": {
                "interaction": float(weights["interaction"]),
                "speed": float(weights["speed"]),
                "continuity": float(weights["continuity"]),
                "coverage": float(weights["coverage"]),
            },
            "tauSeconds": int(tau_seconds),
            "gapCapSeconds": int(gap_cap_seconds),
            "eligibility": {
                "minTotalMessages": int(eligibility["minTotalMessages"]),
                "minInteraction": int(eligibility["minInteraction"]),
                "minReplyCount": int(eligibility["minReplyCount"]),
                "minActiveDays": int(eligibility["minActiveDays"]),
            },
            "usedIndex": False,
            "indexStatus": None,
        },
    }


def build_card_04_monthly_best_friends_wall(*, account_dir: Path, year: int) -> dict[str, Any]:
    data = compute_monthly_best_friends_wall_stats(account_dir=account_dir, year=year)
    summary = dict(data.get("summary") or {})
    top_champion = summary.get("topChampion")
    months_with_winner = int(summary.get("monthsWithWinner") or 0)

    if months_with_winner <= 0:
        narrative = "今年还没有足够的聊天互动数据来评选每月最佳好友（或搜索索引尚未就绪）。"
    elif isinstance(top_champion, dict) and top_champion.get("displayName"):
        champ_name = str(top_champion.get("displayName") or "")
        months_won = int(top_champion.get("monthsWon") or 0)
        narrative = f"{champ_name} 拿下了 {months_won} 个月的月度最佳好友；这一年你们的聊天默契很稳定。"
    else:
        narrative = f"你在 {months_with_winner} 个月里都出现了稳定的“月度最佳好友”。"

    return {
        "id": 4,
        "title": "陪你走过每个月的人",
        "scope": "global",
        "category": "B",
        "status": "ok",
        "kind": "chat/monthly_best_friends_wall",
        "narrative": narrative,
        "data": data,
    }
