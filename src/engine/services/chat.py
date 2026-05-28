"""Contact / group list queries.

Uses the same resolution strategy as chat_list.scan_chats():
1. Pre-load contact.db → id_to_name + name_to_id maps
2. Pre-load session.db → session_summaries
3. Pre-load chat_room → room_owners
4. Build group_members → sender display names per chatroom
5. Resolve each chat via _resolve_display()
"""
import hashlib
import os
import re
import sqlite3

from engine.services.name_resolver import pick_display_name, resolve_wxid
from engine.services.message.decode import decompress_content

# Max characters for auto-generated group name before truncation
_GROUP_NAME_MAX_LEN = 32


def get_contacts(decrypted_dir: str, wxid: str = None) -> list:
    """Return all contacts from decrypted WeChat 4.x message databases."""
    msg_dir = os.path.join(decrypted_dir, "message")
    if os.path.isdir(msg_dir):
        msg_dbs = _find_msg_dbs(msg_dir)
    else:
        # Flat backup layout: .db files directly in decrypted_dir
        msg_dbs = []
        try:
            for f in os.listdir(decrypted_dir):
                m = re.match(r'message_(\d+)\.db', f, re.IGNORECASE)
                if m:
                    msg_dbs.append((int(m.group(1)), os.path.join(decrypted_dir, f)))
        except OSError:
            pass
    if not msg_dbs:
        return []

    # Pre-load all contact name mappings (same as chat_list.py)
    contact_db = _find_file(decrypted_dir, "contact/contact.db", "contact.db")
    if not os.path.isfile(contact_db):
        # Fallback: output/decrypted for backup-based data
        alt = os.path.normpath(os.path.join(decrypted_dir, "..", "..", "..",
                                            "output", "decrypted", "contact", "contact.db"))
        if os.path.isfile(alt):
            contact_db = alt
    session_db = _find_file(decrypted_dir, "session/session.db", "session.db")

    id_to_name, name_to_id, name_to_avatar = _load_contacts(contact_db)
    session_summaries = _load_sessions(session_db)
    room_owners = _load_room_owners(contact_db)

    hash_to_name = _build_hash_map(msg_dbs)
    group_members = _build_group_members(msg_dbs, hash_to_name,
                                          name_to_id, id_to_name)

    contacts = {}
    for idx, db_path in msg_dbs:
        try:
            conn = sqlite3.connect(db_path)
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
            ).fetchall()
            for (tname,) in tables:
                h = tname[4:]
                uname = hash_to_name.get(h)
                if not uname:
                    uname = f"unknown_{h[:8]}"
                if wxid and uname == wxid:
                    continue

                count_row = conn.execute(
                    f"SELECT COUNT(*) FROM [{tname}]"
                ).fetchone()
                last_row = conn.execute(
                    f"SELECT MAX(create_time) FROM [{tname}]"
                ).fetchone()
                cnt = count_row[0] if count_row else 0
                last_time = last_row[0] if last_row else 0

                if uname in contacts and (last_time or 0) <= (contacts[uname].get('last_msg_time') or 0):
                    continue

                is_group = uname.endswith('@chatroom')
                contacts[uname] = {
                    'id': uname,
                    'name': _resolve_display(uname, is_group, decrypted_dir,
                                              id_to_name, name_to_id,
                                              session_summaries, room_owners,
                                              group_members),
                    'type': 'group' if is_group else 'user',
                    'last_msg_time': last_time,
                    'msg_count': cnt,
                    'avatar_url': f'/api/avatar/{uname}',
                }
            conn.close()
        except sqlite3.Error:
            continue

    return sorted(contacts.values(), key=lambda c: c['last_msg_time'] or 0, reverse=True)


def _find_file(decrypted_dir: str, *rel_paths: str) -> str:
    """Find a file by trying multiple relative paths, with a shallow walk fallback."""
    for rel in rel_paths:
        path = os.path.join(decrypted_dir, rel.replace('/', os.sep))
        if os.path.isfile(path):
            return path
    # Walk one level deep as fallback
    target_name = os.path.basename(rel_paths[0])
    try:
        for entry in os.scandir(decrypted_dir):
            if entry.is_dir():
                candidate = os.path.join(entry.path, target_name)
                if os.path.isfile(candidate):
                    return candidate
            elif entry.is_file() and entry.name == target_name:
                return entry.path
    except OSError:
        pass
    return os.path.join(decrypted_dir, rel_paths[0].replace('/', os.sep))


def _find_msg_dbs(msg_dir: str) -> list:
    dbs = []
    for f in os.listdir(msg_dir):
        m = re.match(r'message_(\d+)\.db', f)
        if m:
            dbs.append((int(m.group(1)), os.path.join(msg_dir, f)))
    dbs.sort(key=lambda x: x[0])
    return dbs


def _build_hash_map(msg_dbs: list) -> dict:
    hmap = {}
    for idx, db_path in msg_dbs:
        try:
            conn = sqlite3.connect(db_path)
            for (uname,) in conn.execute("SELECT user_name FROM Name2Id"):
                if uname:
                    hmap[hashlib.md5(uname.encode()).hexdigest()] = uname
            conn.close()
        except sqlite3.Error:
            pass
    return hmap


def _load_contacts(contact_db: str) -> tuple:
    """Load contact.db into id→name, name→id, and name→avatar maps (mirrors chat_list.py)."""
    id_to_name = {}
    name_to_id = {}
    name_to_avatar = {}
    if not os.path.isfile(contact_db):
        return id_to_name, name_to_id, name_to_avatar
    try:
        conn = sqlite3.connect(contact_db)
        for r in conn.execute(
            "SELECT id, username, remark, nick_name, alias, small_head_url FROM contact"
        ):
            cid, uname, remark, nick, alias, avatar_url = r
            uname = (uname or "").strip()
            display = pick_display_name(uname, remark, nick, alias, uname)
            if cid and display:
                id_to_name[cid] = display
            if uname:
                name_to_id[uname] = cid
                if avatar_url:
                    name_to_avatar[uname] = str(avatar_url).strip()
        conn.close()
    except sqlite3.Error:
        pass
    return id_to_name, name_to_id, name_to_avatar


def _load_sessions(session_db: str) -> dict:
    """Load session.db SessionTable summaries."""
    summaries = {}
    if not os.path.isfile(session_db):
        return summaries
    try:
        conn = sqlite3.connect(session_db)
        for r in conn.execute("SELECT username, summary FROM SessionTable"):
            uname, summary = r
            if uname and summary:
                summaries[uname] = str(summary).strip()
        conn.close()
    except sqlite3.Error:
        pass
    return summaries


def _load_room_owners(contact_db: str) -> dict:
    """Load chat_room owner field from contact.db."""
    owners = {}
    if not os.path.isfile(contact_db):
        return owners
    try:
        conn = sqlite3.connect(contact_db)
        for r in conn.execute("SELECT username, owner FROM chat_room"):
            uname, owner = r
            if uname and owner:
                owners[uname] = str(owner).strip()
        conn.close()
    except sqlite3.Error:
        pass
    return owners


def _build_group_members(msg_dbs: list, hash_to_name: dict,
                         name_to_id: dict, id_to_name: dict) -> dict:
    """Build chatroom → [display_name, ...] map from message sender prefixes.

    Samples up to 200 text messages per table to extract unique sender wxids,
    then maps them to contact display names.
    """
    members = {}
    for idx, db_path in msg_dbs:
        try:
            conn = sqlite3.connect(db_path)
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
            ).fetchall()
            for (tname,) in tables:
                h = tname[4:]
                uname = hash_to_name.get(h)
                if not uname or not uname.endswith('@chatroom'):
                    continue
                if uname in members:
                    continue  # already collected from a richer DB

                rows = conn.execute(
                    f"SELECT message_content FROM [{tname}] "
                    f"WHERE message_content LIKE '%:' || char(10) || '%' LIMIT 200"
                ).fetchall()
                seen = set()
                names = []
                for (content,) in rows:
                    if isinstance(content, bytes):
                        content = decompress_content(content)
                    if isinstance(content, bytes):
                        try:
                            content = content.decode('utf-8', errors='replace')
                        except Exception:
                            continue
                    if not isinstance(content, str) or ':\n' not in content[:100]:
                        continue
                    raw = content.split(':\n', 1)[0].strip()
                    m = re.search(
                        r'(?:wxid_[a-z0-9]{10,20}'
                        r'|[a-zA-Z][a-zA-Z0-9_]{3,30}'
                        r'|[0-9]{5,20}@openim'
                        r'|[0-9]{5,20})',
                        raw
                    )
                    if not m:
                        continue
                    wxid = m.group(0)
                    if wxid in seen:
                        continue
                    seen.add(wxid)
                    # Resolve to display name
                    name = wxid
                    if wxid in name_to_id:
                        cid = name_to_id[wxid]
                        if cid in id_to_name:
                            name = id_to_name[cid]
                    names.append(name)
                if names:
                    members[uname] = names
            conn.close()
        except sqlite3.Error:
            continue
    return members


def get_group_members(decrypted_dir: str, chatroom_id: str) -> list:
    """Return member list with display names for a group chat.
    Returns [{wxid, display_name, is_owner}, ...].
    """
    msg_dir = os.path.join(decrypted_dir, "message")
    if os.path.isdir(msg_dir):
        msg_dbs = _find_msg_dbs(msg_dir)
    else:
        msg_dbs = []
        try:
            for f in os.listdir(decrypted_dir):
                m = re.match(r'message_(\d+)\.db', f, re.IGNORECASE)
                if m:
                    msg_dbs.append((int(m.group(1)), os.path.join(decrypted_dir, f)))
        except OSError:
            pass
    if not msg_dbs:
        return []

    contact_db = _find_file(decrypted_dir, "contact/contact.db", "contact.db")
    id_to_name, name_to_id, _ = _load_contacts(contact_db)
    room_owners = _load_room_owners(contact_db)
    hash_to_name = _build_hash_map(msg_dbs)
    members_map = _build_group_members(msg_dbs, hash_to_name, name_to_id, id_to_name)
    member_names = members_map.get(chatroom_id, [])

    owner_wxid = room_owners.get(chatroom_id, '')
    owner_display = ''
    if owner_wxid and owner_wxid in name_to_id:
        cid = name_to_id[owner_wxid]
        owner_display = id_to_name.get(cid, owner_wxid)
    else:
        owner_display = owner_wxid

    result = []
    seen = set()
    for name in member_names:
        wxid = None
        for w, cid in name_to_id.items():
            if id_to_name.get(cid) == name:
                wxid = w
                break
        if not wxid:
            wxid = name
        if wxid in seen:
            continue
        seen.add(wxid)
        result.append({
            'wxid': wxid,
            'display_name': name,
            'is_owner': (wxid == owner_wxid),
        })

    # Add owner if not already in list
    if owner_wxid and owner_wxid not in seen:
        result.insert(0, {
            'wxid': owner_wxid,
            'display_name': owner_display or owner_wxid,
            'is_owner': True,
        })

    return result


def get_group_info(decrypted_dir: str, chat_id: str) -> dict:
    """Return group info including members, owner, notice."""
    if not chat_id.endswith('@chatroom'):
        return None

    # SessionTable.summary field is "群名:最新消息预览" not the actual
    # announcement. Real columns (announcement_/xml_announcement_) are in
    # a different table not available in this schema.
    notice = ''

    members = get_group_members(decrypted_dir, chat_id)
    owner = next((m['display_name'] for m in members if m['is_owner']), '')

    return {
        'chat_id': chat_id,
        'member_count': len(members),
        'owner': owner,
        'notice': notice,
        'members': members,
    }


def _resolve_display(uname: str, is_group: bool, decrypted_dir: str,
                     id_to_name: dict, name_to_id: dict,
                     session_summaries: dict, room_owners: dict,
                     group_members: dict = None) -> str:
    """Resolve display name for a chat username (mirrors chat_list._resolve_display)."""
    # Contact lookup via name_resolver (exact match + LIKE fuzzy, cached)
    name = resolve_wxid(decrypted_dir, uname)
    if name and name != uname:
        return name

    if not is_group:
        # Check pre-built id_to_name dict (populated by _load_contacts from contact.db).
        # resolve_wxid queries by username= which can miss contacts where the lookup
        # key is an alias or nick_name — the dicts cover all contacts regardless of column.
        if uname in name_to_id:
            cid = name_to_id[uname]
            if cid in id_to_name:
                name = id_to_name[cid]
                if name and name != uname:
                    return name
        return uname

    # --- Group chat resolution below ---

    # 1. Try contact.db with @chatroom stripped (some DBs store without suffix)
    if uname.endswith('@chatroom'):
        base_grp = uname[:-9]
        if base_grp in name_to_id:
            cid = name_to_id[base_grp]
            if cid in id_to_name:
                name = id_to_name[cid]
                if name and name != base_grp:
                    return name

    # 2. Session summary: "GroupName:last_message" format
    if uname in session_summaries:
        summary = session_summaries[uname]
        for sep in [":", "："]:
            if sep in summary:
                name_part = summary.split(sep, 1)[0].strip()
                if name_part and len(name_part) < 60:
                    return name_part
        # No colon — if summary is short enough to be a group name, use it
        if summary and len(summary) < 40 and not any(c in summary for c in '\n\r'):
            return summary.strip()

    # 3. Member-based name: join display names with '、'
    if group_members and uname in group_members:
        names = group_members[uname]
        if names:
            joined = '、'.join(names)
            if len(joined) <= _GROUP_NAME_MAX_LEN:
                return joined
            truncated = joined[:_GROUP_NAME_MAX_LEN]
            while truncated and truncated[-1] in ('、', '​', '‍'):
                truncated = truncated[:-1]
            return truncated + '..'

    # 4. Room owner from chat_room table
    if uname in room_owners:
        owner = room_owners[uname]
        if owner in name_to_id:
            cid = name_to_id[owner]
            if cid in id_to_name:
                owner_name = id_to_name[cid]
                return f"{owner_name}的群聊"
        return f"{owner}的群聊"

    # 5. Fallback: shortened chatroom ID
    short = uname[:12] + "..." if len(uname) > 12 else uname
    return f"群聊({short})"
