"""Unified wxid -> display_name resolution.

Merge of:
- message.py:_lookup_wxid() + _pick_display_name()
- chat.py:_pick_display_name() (duplicate)
- message.py:_resolve_sender_name() logic
"""
import logging
import os
import sqlite3
import threading
import time
from collections import OrderedDict

_name_cache = OrderedDict()
_name_cache_lock = threading.Lock()
_NAME_CACHE_MAX = 200
_NAME_CACHE_TTL = 300  # seconds


def pick_display_name(wxid: str, remark, nick, alias, db_username) -> str:
    """Pick best display name, skipping fields that just echo the wxid/username."""
    remark_v = (remark or '').strip()
    nick_v = (nick or '').strip()
    alias_v = (alias or '').strip()
    uname = (db_username or wxid or '').strip()
    if remark_v and remark_v != uname:
        return remark_v
    if nick_v and nick_v != uname:
        return nick_v
    if alias_v and alias_v != uname:
        return alias_v
    return uname


def resolve_wxid(decrypted_dir: str, wxid: str) -> str:
    """Look up a wxid in contact.db, returning display name or the wxid itself.

    Priority: remark > nick_name > alias > username.
    Falls back to LIKE-fuzzy matching when exact username match fails.
    Results are cached per-process (max 200 entries).
    """
    if not wxid:
        return wxid

    cache_key = f'{decrypted_dir}:{wxid}'
    now = time.monotonic()
    with _name_cache_lock:
        if cache_key in _name_cache:
            result, ts = _name_cache[cache_key]
            if now - ts < _NAME_CACHE_TTL:
                _name_cache.move_to_end(cache_key)
                return result
            # expired — remove and fall through to fresh lookup
            del _name_cache[cache_key]

    contact_db = _find_contact_db(decrypted_dir)
    if not contact_db:
        return wxid

    result = wxid
    try:
        with sqlite3.connect(contact_db) as conn:
            row = conn.execute(
                "SELECT remark, nick_name, alias, username FROM contact WHERE username=?",
                (wxid,)
            ).fetchone()
            if row:
                name = pick_display_name(wxid, row[0], row[1], row[2], row[3])
                if name and name != wxid:
                    result = name
            else:
                # Exact match on alias (the wxid may be stored as alias, not username)
                row = conn.execute(
                    "SELECT remark, nick_name, alias, username FROM contact WHERE alias=?",
                    (wxid,)
                ).fetchone()
                if row:
                    name = pick_display_name(wxid, row[0], row[1], row[2], row[3])
                    if name and name != wxid:
                        result = name

            if result == wxid:
                # LIKE-fuzzy fallback — try username then alias
                base = wxid
                for sfx in ('@chatroom', '@openim'):
                    if base.endswith(sfx):
                        base = base[:-len(sfx)]
                        break
                if base and len(base) >= 4:
                    for col in ('username', 'alias'):
                        row = conn.execute(
                            f"SELECT remark, nick_name, alias, username FROM contact "
                            f"WHERE {col} LIKE ? LIMIT 1",
                            (f'%{base}%',)
                        ).fetchone()
                        if row:
                            name = pick_display_name(wxid, row[0], row[1], row[2], row[3])
                            if name and name != wxid:
                                result = name
                                break
    except sqlite3.Error:
        logging.warning("name_resolver: failed to query %s for wxid=%s", contact_db, wxid)

    with _name_cache_lock:
        while len(_name_cache) >= _NAME_CACHE_MAX:
            _name_cache.popitem(last=False)
        _name_cache[cache_key] = (result, time.monotonic())

    return result


def _find_contact_db(decrypted_dir: str) -> str:
    """Find contact.db under decrypted_dir."""
    for name in ('contact/contact.db', 'Contact/contact.db'):
        path = os.path.join(decrypted_dir, name.replace('/', os.sep))
        if os.path.isfile(path):
            return path
    return None
