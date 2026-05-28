"""Message query service for WeChat 4.x per-chat Msg_<hash> tables."""
import hashlib
import os
import re
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime
from engine.parsers import PARSERS
from engine.parsers import types as _  # trigger parser registration
from engine.services.emoji_map import translate_wechat_emoji
from engine.services.name_resolver import resolve_wxid, pick_display_name as _pick_display_name
from engine.services.message.media_resolve import (
    _resolve_media_from_proto, _lookup_resource_file_name,
    _resolve_voice_path, _scan_filesystem_for_media, _resolve_via_resource_db
)

try:
    import zstandard as zstd
    _ZSTD_CTX = zstd.ZstdDecompressor()
except ImportError:
    _ZSTD_CTX = None

# WeChat 4.x uses high bits of local_type for flags (e.g. type 49 = 0x500000031).
# The actual message type is in the lower 16 bits.
_LOCAL_TYPE_MASK = 0xFFFF

# WeChat 4.x zstd compression magic (NOT protobuf — zstd frame header)
_ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'


def _zstd_decompress_xml(data: bytes) -> str:
    """Decompress WeChat 4.x zstd-compressed message_content to XML text.

    WeChat 4.x stores message metadata as zstd-compressed XML (NOT protobuf).
    The magic bytes 28 B5 2F FD identify the zstd frame header.
    Strips sender prefix ("wxid_xxx:\\n" or "username:\\n") before XML content.

    Returns decompressed XML string, or None on failure.
    """
    if _ZSTD_CTX is None or len(data) < 4 or data[:4] != _ZSTD_MAGIC:
        return None
    try:
        raw = _ZSTD_CTX.decompress(data, max_output_size=50 * 1024 * 1024)
    except Exception:
        return None

    # Strip sender prefix (e.g. "wxid_xxx:\\n" or "username:\\n") that WeChat
    # prepends to the XML body in zstd-compressed content for types 3/43/47 etc.
    lt_pos = raw.find(b'<')
    if lt_pos > 0:
        raw = raw[lt_pos:]

    # Try UTF-8 first, then GBK for CDATA content
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        try:
            text = raw.decode('gbk', errors='replace')
        except Exception:
            text = raw.decode('utf-8', errors='replace')

    # Handle CDATA sections that may contain GBK-encoded bytes within UTF-8 XML
    if '�' in text:
        text = _fix_cdata_encoding(raw)

    return text.strip()


def _fix_cdata_encoding(raw: bytes) -> str:
    """Fix mixed-encoding XML where CDATA sections may be GBK-encoded.

    WeChat 4.x XML sometimes has UTF-8 structure with GBK-encoded CDATA content.
    This detects CDATA blocks and re-decodes them as GBK.
    """
    result = bytearray()
    i = 0
    while i < len(raw):
        # Find CDATA start
        cdata_start = raw.find(b'<![CDATA[', i)
        if cdata_start < 0:
            result.extend(raw[i:])
            break
        # Copy everything before CDATA as UTF-8
        result.extend(raw[i:cdata_start])
        # Extract CDATA content
        cdata_content_start = cdata_start + 9  # len('<![CDATA[')
        cdata_end = raw.find(b']]>', cdata_content_start)
        if cdata_end < 0:
            # Malformed CDATA — treat rest as UTF-8
            result.extend(raw[cdata_start:])
            break
        # Check if CDATA content is valid UTF-8
        cdata_bytes = raw[cdata_content_start:cdata_end]
        try:
            cdata_text = cdata_bytes.decode('utf-8')
            # Valid UTF-8 — re-encode as UTF-8
            result.extend(b'<![CDATA[')
            result.extend(cdata_text.encode('utf-8'))
            result.extend(b']]>')
        except UnicodeDecodeError:
            # Try GBK
            try:
                cdata_text = cdata_bytes.decode('gbk')
                result.extend(b'<![CDATA[')
                result.extend(cdata_text.encode('utf-8'))
                result.extend(b']]>')
            except Exception:
                # Can't decode — keep raw with replacement chars
                result.extend(b'<![CDATA[')
                result.extend(cdata_bytes.decode('utf-8', errors='replace').encode('utf-8'))
                result.extend(b']]>')
        i = cdata_end + 3  # len(']]>')
    return result.decode('utf-8', errors='replace')


def _finderr(_e):
    pass  # xml parser error callback — ignore, regex fallback handles malformed XML


import html as _html_mod
def html_unescape(s: str) -> str:
    try:
        return _html_mod.unescape(s)
    except Exception:
        return s


def _scandir_msg_dbs(search_dir: str) -> list:
    """Scan a directory for message_<n>.db files, return [(idx, full_path), ...] sorted."""
    if not os.path.isdir(search_dir):
        return []
    dbs = []
    for f in os.listdir(search_dir):
        m = re.match(r'message_(\d+)\.db$', f, re.IGNORECASE)
        if m:
            dbs.append((int(m.group(1)), os.path.join(search_dir, f)))
    dbs.sort(key=lambda x: x[0])
    return dbs


def _find_msg_dbs(decrypted_dir: str):
    """Find message_*.db files — checks both 'message' subdir and parent dir."""
    dbs = _scandir_msg_dbs(os.path.join(decrypted_dir, "message"))
    if not dbs:
        dbs = _scandir_msg_dbs(decrypted_dir)
    return dbs


def _find_chat_db(decrypted_dir: str, chat_id: str) -> tuple:
    """Find (db_path, table_name) for a given chat_id across message_*.db files."""
    dbs = _find_msg_dbs(decrypted_dir)
    if not dbs:
        raise FileNotFoundError(f"no message_*.db files found under: {decrypted_dir}")

    h = hashlib.md5(chat_id.encode()).hexdigest()
    tname = f"Msg_{h}"

    for idx, db_path in dbs:
        try:
            conn = sqlite3.connect(db_path)
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (tname,)
            ).fetchone()
            conn.close()
            if row:
                return db_path, tname
        except sqlite3.Error:
            continue

    raise FileNotFoundError(f"table {tname} not found for chat {chat_id}")


def _build_where(start_date, end_date, msg_types, sender, keyword, is_group=False):
    """Build WHERE clause and params list for WeChat 4.x Msg_ table columns."""
    clauses = ['create_time > 1000000000']
    params = []

    if start_date and end_date and start_date > end_date:
        start_date, end_date = end_date, start_date
    if start_date:
        try:
            clauses.append("create_time >= ?")
            params.append(_date_to_ts(start_date))
        except ValueError:
            pass
    if end_date:
        try:
            clauses.append("create_time <= ?")
            params.append(_date_to_ts(end_date, end_of_day=True))
        except ValueError:
            pass
    if msg_types:
        try:
            types = [int(t.strip()) for t in msg_types.split(',') if t.strip()]
        except ValueError:
            types = []
        types = [t for t in types if t in MSG_TYPE_LABELS]
        if types:
            placeholders = ','.join('?' for _ in types)
            clauses.append(f"(local_type & {_LOCAL_TYPE_MASK}) IN ({placeholders})")
            params.extend(types)
    if sender:
        if sender == '__self__':
            clauses.append('origin_source = 1')
        elif sender == '__sys__':
            clauses.append(f'(local_type & {_LOCAL_TYPE_MASK}) IN (10000, 10002)')
        elif is_group:
            clauses.append('message_content LIKE ? ESCAPE \'\\\'')
            params.append(f'{_escape_like(sender)}:\\n%')
        else:
            clauses.append('origin_source != 1')
    if keyword:
        clauses.append("message_content LIKE ? ESCAPE \'\\\'")
        params.append(f'%{_escape_like(keyword)}%')

    return ' AND '.join(clauses), params


def _escape_like(s: str) -> str:
    """Escape LIKE wildcards % and _ in user-supplied strings."""
    return s.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


def _date_to_ts(date_str: str, end_of_day: bool = False) -> int:
    """Convert YYYY-MM-DD to Unix timestamp."""
    fmt = '%Y-%m-%d %H:%M:%S' if end_of_day else '%Y-%m-%d'
    if end_of_day:
        date_str = f'{date_str} 23:59:59'
    return int(datetime.strptime(date_str, fmt).timestamp())


# Regex for extracting clean WeChat IDs from potentially garbage-prefixed strings
_WXID_PATTERN = re.compile(
    r'(?:wxid_[a-z0-9]{10,20}'          # wxid_xxxxxxxxxxxxx
    r'|[a-zA-Z][a-zA-Z0-9_]{3,30}'       # alphanumeric username
    r'|[0-9]{5,20}@openim'               # openim IDs
    r'|[0-9]{5,20})'                     # numeric QQ-style IDs
)


def _clean_sender_prefix(raw_prefix: str) -> str:
    """Extract the real sender wxid/username from a potentially garbage-prefixed string.

    WeChat 4.x sometimes prepends binary protobuf data to the sender prefix,
    producing strings like '(�/� �m�\twxid_xxx'.
    This extracts the last valid ID pattern from the raw text.
    """
    if not raw_prefix:
        return ''
    # Find the last valid wxid/username in the string
    matches = list(_WXID_PATTERN.finditer(raw_prefix))
    if matches:
        return matches[-1].group(0)
    # Fallback: if no match, strip obvious garbage (replacement chars, control chars)
    cleaned = raw_prefix.strip()
    # Remove leading garbage: chars that aren't typical in wxid/username
    # (replacement char, low control chars, whitespace beyond spaces)
    while cleaned and (ord(cleaned[0]) < 0x20 or ord(cleaned[0]) == 0xFFFD):
        cleaned = cleaned[1:]
    return cleaned.strip()


def _resolve_sender_name(decrypted_dir: str, real_sender_id: int, content_sender: str,
                         sender_map: dict = None, wxid_name_cache: dict = None) -> str:
    """Resolve a sender's display name from contact.db.

    Priority:
    1. content_sender (wxid from message prefix) — most reliable for text messages
    2. sender_map[real_sender_id] → lookup wxid in contacts — for binary messages
    3. raw wxid / ID placeholder

    In WeChat 4.x, real_sender_id does NOT map to contact.db rowid.
    It is a per-chat member index. The sender_map (built from text message
    prefixes) bridges real_sender_id to the actual wxid.

    The wxid_name_cache reduces redundant contact.db lookups within a single
    query_messages() call by caching resolved wxid → display_name mappings.
    """
    if wxid_name_cache is None:
        wxid_name_cache = {}

    # Primary: resolve by content_sender wxid (authoritative for text messages)
    if content_sender:
        if content_sender in wxid_name_cache:
            return wxid_name_cache[content_sender]
        name = resolve_wxid(decrypted_dir, content_sender)
        result = name if (name and name != content_sender) else content_sender
        wxid_name_cache[content_sender] = result
        return result

    # Fallback: use sender_map to translate real_sender_id → wxid
    if real_sender_id and real_sender_id != 0:
        cache_key = f'_rsid_{real_sender_id}'
        if cache_key in wxid_name_cache:
            return wxid_name_cache[cache_key]
        wxid = (sender_map or {}).get(real_sender_id)
        if wxid:
            if wxid in wxid_name_cache:
                name = wxid_name_cache[wxid]
            else:
                name = resolve_wxid(decrypted_dir, wxid)
                wxid_name_cache[wxid] = name if (name and name != wxid) else wxid
            result = name if (name and name != wxid) else wxid
        else:
            result = '未知'
        wxid_name_cache[cache_key] = result
        return result

    return '未知'


# Fallback labels when XML parsing fails (WeChat 4.x uses protobuf, not XML)
MSG_TYPE_LABELS = {
    3: '[图片]', 6: '[文件]', 34: '[语音]', 42: '[名片]',
    43: '[视频]', 47: '[表情]', 48: '[位置]', 49: '[链接]',
    50: '[网络电话]', 66: '[消息]',
}

# Types where message_content is zstd-compressed XML (28 B5 2F FD magic)
_ZSTD_TYPES = {3, 6, 42, 43, 47, 48, 49, 50}

# Types that may have XML embedded in protobuf binary (legacy, pre-zstd)
_MIXED_CONTENT_TYPES = {10000, 10002}

# Types that have pure XML content (after zstd decompression or natively)
_XML_CONTENT_TYPES = {48, 49, 3, 6, 34, 42, 43, 47, 50}


def _extract_xml_bytes(content_bytes: bytes, ltype: int) -> bytes:
    """Extract XML portion from mixed protobuf+XML content.

    WeChat 4.x message_content for some types has a binary protobuf header
    followed by XML body. This finds and extracts just the XML part.
    For type 48 (location), the entire content is pure XML.
    """
    # XML markers to search for (in priority order)
    markers = {
        49: [b'<appmsg', b'<?xml'],
        10000: [b'<sysmsg', b'<?xml'],
        10002: [b'<sysmsg', b'<?xml'],
    }
    closing = {
        b'<appmsg': b'</appmsg>',
        b'<sysmsg': b'</sysmsg>',
        b'<?xml': None,  # self-closing or has child elements
        b'<msg': b'</msg>',
    }

    search_markers = markers.get(ltype, [b'<msg', b'<?xml', b'<appmsg', b'<sysmsg'])

    best_xml = None
    best_len = 0

    for marker in search_markers:
        idx = content_bytes.find(marker)
        if idx < 0:
            continue

        xml_part = content_bytes[idx:]

        # Try to find closing tag
        end_tag = closing.get(marker)
        if end_tag:
            end_idx = xml_part.find(end_tag)
            if end_idx > 0:
                xml_part = xml_part[:end_idx + len(end_tag)]

        # Validate by attempting parse
        try:
            ET.fromstring(xml_part)
            if len(xml_part) > best_len:
                best_xml = xml_part
                best_len = len(xml_part)
        except ET.ParseError:
            # Try finding the XML declaration and reparsing from there
            decl_idx = xml_part.find(b'<?xml')
            if decl_idx > 0:
                xml_part2 = xml_part[decl_idx:]
                for et in closing.values():
                    if et:
                        ei = xml_part2.find(et)
                        if ei > 0:
                            candidate = xml_part2[:ei + len(et)]
                            try:
                                ET.fromstring(candidate)
                                if len(candidate) > best_len:
                                    best_xml = candidate
                                    best_len = len(candidate)
                            except ET.ParseError:
                                pass

    return best_xml


def _row_to_message(row, chat_id: str, decrypted_dir: str = '', parse_xml: bool = True, sender_map: dict = None, wxid_name_cache: dict = None) -> dict:
    """Convert a Msg_ table row to the API message dict.

    Column order: local_id, local_type, origin_source, create_time, status,
                  message_content, real_sender_id
    """
    local_id = row[0]
    ltype = (row[1] or 0) & _LOCAL_TYPE_MASK if isinstance(row[1], (int, float)) else (row[1] or 0)
    origin = row[2]
    create_time = row[3]
    content = row[5]  # message_content
    real_sender_id = row[6] if len(row) > 6 else 0
    packed_info = row[7] if len(row) > 7 else None

    # Save raw protobuf bytes for mixed-content types (48, 49, 10000, 10002)
    # before they're stripped. WeChat 4.x embeds XML within protobuf binary;
    # standard XML parsing fails, but regex can extract key fields.
    raw_content_bytes = content if isinstance(content, bytes) else None

    if isinstance(content, bytes):
        # Check for WeChat 4.x zstd-compressed content (28 B5 2F FD = zstd frame magic).
        # After decompression, these yield XML with full message metadata.
        if len(content) >= 4 and content[:4] == _ZSTD_MAGIC:
            zstd_xml = _zstd_decompress_xml(content)
            if zstd_xml:
                content = zstd_xml
            else:
                content = ''
        else:
            try:
                decoded = content.decode('utf-8', errors='replace')
                # If the result is mostly replacement chars, treat as binary
                if decoded and len(decoded) > 0:
                    sample = decoded[:100]
                    repl_count = sample.count('�')
                    if repl_count > len(sample) * 0.3:
                        content = ''
                    else:
                        content = decoded
                else:
                    content = decoded
            except Exception:
                content = ''

    is_sender = (origin == 1)
    is_group = chat_id.endswith('@chatroom')

    # Extract sender prefix for group messages: "sender:\nactual_content"
    if is_sender:
        sender_name = '我'
    elif is_group:
        sender_name = chat_id
    else:
        sender_name = resolve_wxid(decrypted_dir, chat_id)
    display_content = content or ''
    content_sender = ''
    if is_group and not is_sender and isinstance(content, str) and ':\n' in content[:100]:
        parts = content.split(':\n', 1)
        content_sender = _clean_sender_prefix(parts[0])
        display_content = parts[1] if len(parts) > 1 else content

    # Resolve sender name for group chats
    sender_wxid = None
    if is_group and not is_sender:
        if ltype in (10000, 10002):  # System notifications — not attributed to a person
            sender_name = '系统消息'
        else:
            sender_name = _resolve_sender_name(decrypted_dir, real_sender_id, content_sender, sender_map, wxid_name_cache)
            # Derive sender_wxid for avatar URL
            if content_sender:
                sender_wxid = content_sender
            elif real_sender_id and real_sender_id != 0 and sender_map:
                sender_wxid = sender_map.get(real_sender_id)

    # Parse XML for rich media types (after stripping sender prefix)
    xml_parsed = {}
    xml_source = display_content if (is_group and not is_sender) else (content or '')

    if parse_xml and ltype != 1:
        parser = PARSERS.get(ltype)
        xml_raw = None

        if parser:
            raw_bytes = xml_source.encode('utf-8', errors='replace') if isinstance(xml_source, str) else xml_source

            if ltype in _MIXED_CONTENT_TYPES:
                # Try to extract XML from binary protobuf+XML mixed content.
                # Use raw_content_bytes (pre-strip) for WeChat 4.x protobuf content.
                source = raw_content_bytes if (raw_content_bytes and not xml_source) else raw_bytes
                extracted = _extract_xml_bytes(source, ltype)
                if extracted:
                    xml_raw = extracted
                elif raw_content_bytes:
                    # XML extraction failed — pass raw protobuf bytes to parser
                    # so it can use regex fallback to extract key fields
                    xml_raw = raw_content_bytes
            elif ltype in _XML_CONTENT_TYPES:
                xml_raw = raw_content_bytes if (raw_content_bytes and not xml_source) else raw_bytes
            else:
                # For other types, try parsing only if content looks like XML
                s = xml_source.lstrip() if isinstance(xml_source, str) else ''
                if s and (s.startswith('<') or '<msg' in s):
                    xml_raw = raw_bytes
                elif raw_content_bytes and not xml_source:
                    # WeChat 4.x protobuf content for non-mixed types (e.g. 50)
                    # — pass raw bytes to parser for regex fallback
                    xml_raw = raw_content_bytes

            if xml_raw:
                try:
                    xml_str = xml_raw.decode('utf-8', errors='replace') if isinstance(xml_raw, bytes) else xml_raw
                    xml_bytes = xml_str.encode('utf-8', errors='replace') if isinstance(xml_str, str) else xml_str
                    parsed = parser(xml_bytes)
                    xml_parsed = parsed
                except Exception:
                    pass

    # Resolve media info from protobuf packed_info_data (must precede display fallback)
    media_info = _resolve_media_from_proto(decrypted_dir, packed_info, ltype,
                                            local_id=local_id, create_time=create_time,
                                            chat_id=chat_id)

    # Apply emoji translation to text message content field
    if ltype == 1 and isinstance(content, str) and content:
        content = translate_wechat_emoji(content)

    # Translate emoji in xml_parsed text fields
    if xml_parsed and isinstance(xml_parsed, dict):
        for key in ('text', 'title', 'des', 'poiname', 'label'):
            val = xml_parsed.get(key)
            if isinstance(val, str) and val:
                xml_parsed[key] = translate_wechat_emoji(val)

    return {
        'id': local_id,
        'msg_type': ltype,
        'is_sender': is_sender,
        'sender_name': sender_name,
        'sender_wxid': sender_wxid,
        'content': content,
        'create_time': create_time,
        'xml_parsed': xml_parsed,
        'real_sender_id': real_sender_id,
        'media_info': media_info,
    }


def _build_sender_map(conn, table_name: str) -> dict:
    """Build a real_sender_id → wxid map from text messages with sender prefix.

    WeChat 4.x real_sender_id is a per-chat member index, NOT a contact.db rowid.
    Text messages have a ``sender:\\ncontent`` prefix that carries the real wxid.
    This function scans text messages to build the mapping, so non-text messages
    (images, videos, links) without a prefix can still resolve sender names.
    """
    sender_map = {}
    try:
        rows = conn.execute(
            f"""SELECT real_sender_id, message_content FROM [{table_name}]
                WHERE real_sender_id IS NOT NULL AND real_sender_id != 0
                  AND (local_type & 0xFFFF) = 1
                  AND message_content IS NOT NULL
                LIMIT 2000"""
        ).fetchall()
        seen = set()
        for rsid, content in rows:
            rsid_int = int(rsid) if rsid else 0
            if rsid_int in seen or not rsid_int:
                continue
            if not isinstance(content, str):
                continue
            pos = content.find(':\n')
            if pos <= 0 or pos > 80:
                continue
            wxid = _clean_sender_prefix(content[:pos])
            if wxid:
                sender_map[rsid_int] = wxid
                seen.add(rsid_int)
    except sqlite3.Error:
        pass
    return sender_map


def query_messages(decrypted_dir: str, chat_id: str, wxid: str = None,
                   page: int = 1, per_page: int = 50,
                   start_date: str = None, end_date: str = None,
                   msg_types: str = None, sender: str = None,
                   keyword: str = None) -> dict:
    """Paginated message query for a specific chat.

    Pagination: most recent messages on page 1. Within a page, oldest first.
    """
    per_page = max(1, per_page)  # guard against ZeroDivisionError
    db_path, table_name = _find_chat_db(decrypted_dir, chat_id)
    is_group = chat_id.endswith('@chatroom')
    where_clause, params = _build_where(start_date, end_date, msg_types, sender, keyword, is_group)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Build real_sender_id → wxid map for group chats (fixes wrong sender names)
    sender_map = _build_sender_map(conn, table_name) if is_group else {}

    # Per-request cache for wxid → display_name lookups
    wxid_name_cache = {}

    cur.execute(f"SELECT COUNT(*) FROM [{table_name}] WHERE {where_clause}", params)
    total = cur.fetchone()[0]
    if total > 0:
        total_pages = (total + per_page - 1) // per_page
        page = max(1, min(page, total_pages))
    else:
        total_pages = 0
        page = 1

    # Page 1 = most recent messages. Within page, oldest first.
    offset = (page - 1) * per_page
    cur.execute(
        f"""SELECT local_id, local_type, origin_source, create_time, status,
                   message_content, real_sender_id, packed_info_data
            FROM [{table_name}] WHERE {where_clause}
            ORDER BY create_time DESC
            LIMIT ? OFFSET ?""",
        params + [per_page, offset]
    )

    # Fetch rows and reverse for oldest-first display within the page
    rows = cur.fetchall()
    rows = list(reversed(rows))

    messages = []
    for row in rows:
        msg = _row_to_message(row, chat_id, decrypted_dir, parse_xml=True,
                              sender_map=sender_map, wxid_name_cache=wxid_name_cache)
        messages.append(msg)

    cur.close()
    conn.close()

    return {
        'messages': messages,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': total_pages,
        },
    }


def _find_all_msg_dbs(decrypted_dir: str) -> list:
    """Find all message_*.db files sorted by index."""
    return _find_msg_dbs(decrypted_dir)


def query_message_detail(decrypted_dir: str, msg_id: int, chat_id: str = '') -> dict:
    """Get full detail for a single message by its local_id.

    When chat_id is provided, queries ONLY the exact Msg_<hash> table for
    that chat to avoid cross-table local_id collisions.
    """
    dbs = _find_all_msg_dbs(decrypted_dir)
    if not dbs:
        return None

    # Phase 1: when chat_id is known, search ONLY the exact table for that chat
    if chat_id:
        try:
            chat_db_path, tname = _find_chat_db(decrypted_dir, chat_id)
            conn = sqlite3.connect(chat_db_path)
            try:
                row = conn.execute(
                    f"""SELECT local_id, local_type, origin_source, create_time, status,
                               message_content, real_sender_id, packed_info_data
                        FROM [{tname}] WHERE local_id=?""",
                    (msg_id,)
                ).fetchone()
                if row:
                    sender_map = _build_sender_map(conn, tname) if chat_id.endswith('@chatroom') else {}
                    msg = _row_to_message(row, chat_id, decrypted_dir, parse_xml=True, sender_map=sender_map)
                    return msg
                return None  # correct table queried, message not found
            finally:
                conn.close()
        except (sqlite3.Error, FileNotFoundError, OSError):
            pass  # DB error on exact lookup — fall through to Phase 2 full scan

    # Phase 2: no chat_id provided — search all tables (slower, may collide)
    for idx, db_path in dbs:
        try:
            conn = sqlite3.connect(db_path)
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
            ).fetchall()
            for (tname,) in tables:
                row = conn.execute(
                    f"""SELECT local_id, local_type, origin_source, create_time, status,
                               message_content, real_sender_id, packed_info_data
                        FROM [{tname}] WHERE local_id=?""",
                    (msg_id,)
                ).fetchone()
                if row:
                    h = tname[4:]
                    resolved_chat_id = _resolve_chat_id_from_hash(db_path, h, dbs) or tname
                    sender_map = _build_sender_map(conn, tname) if resolved_chat_id.endswith('@chatroom') else {}
                    msg = _row_to_message(row, resolved_chat_id, decrypted_dir, parse_xml=True, sender_map=sender_map)
                    conn.close()
                    return msg
            conn.close()
        except sqlite3.Error:
            continue

    return None


def _resolve_chat_id_from_hash(db_path: str, h: str, dbs: list) -> str:
    """Try to resolve a Msg_ hash back to a username via Name2Id."""
    for idx, other_path in dbs:
        try:
            conn = sqlite3.connect(other_path)
            for (uname,) in conn.execute("SELECT user_name FROM Name2Id"):
                if uname and hashlib.md5(uname.encode()).hexdigest() == h:
                    conn.close()
                    return uname
            conn.close()
        except sqlite3.Error:
            pass
    return None


def get_chat_stats(decrypted_dir: str, chat_id: str) -> dict:
    """Get statistics overview for a chat."""
    db_path, table_name = _find_chat_db(decrypted_dir, chat_id)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute(f"SELECT COUNT(*), MIN(create_time), MAX(create_time) FROM [{table_name}] WHERE create_time > 1000000000")
    row = cur.fetchone()
    total = row[0] or 0
    date_range = {
        'start': datetime.fromtimestamp(row[1]).strftime('%Y-%m-%d') if row[1] else '',
        'end': datetime.fromtimestamp(row[2]).strftime('%Y-%m-%d') if row[2] else '',
    }

    # Resolve individual senders for sender_distribution.
    # For group chats, extract sender wxid from message_content prefix;
    # for non-group chats, origin_source is sufficient.
    is_group = chat_id.endswith('@chatroom') if chat_id else False
    if is_group:
        cur.execute(
            f"SELECT message_content, real_sender_id, origin_source, local_type "
            f"FROM [{table_name}] WHERE create_time > 1000000000"
        )
        sender_counts = {}
        wxid_name_cache = {}
        contact_db = os.path.join(decrypted_dir, "contact", "contact.db")
        for row in cur.fetchall():
            content = row[0]
            real_sender_id = row[1] or 0
            origin = row[2]
            ltype = (row[3] or 0) & _LOCAL_TYPE_MASK if isinstance(row[3], (int, float)) else (row[3] or 0)

            if origin == 1:
                raw_sender = '__self__'
                display_name = '我'
            elif ltype in (10000, 10002):
                raw_sender = '__sys__'
                display_name = '系统消息'
            else:
                # Decode bytes content
                if isinstance(content, bytes):
                    try:
                        content = content.decode('utf-8', errors='replace')
                    except Exception:
                        content = ''
                content_sender = ''
                if isinstance(content, str) and ':\n' in content[:100]:
                    parts = content.split(':\n', 1)
                    content_sender = _clean_sender_prefix(parts[0])
                if content_sender:
                    raw_sender = content_sender
                    if content_sender not in wxid_name_cache:
                        name = resolve_wxid(decrypted_dir, content_sender)
                        wxid_name_cache[content_sender] = name if (name and name != content_sender) else content_sender
                    display_name = wxid_name_cache[content_sender]
                else:
                    # Fall back to real_sender_id lookup (same as _resolve_sender_name)
                    cache_key = f'_rsid_{real_sender_id}'
                    raw_sender = cache_key
                    if cache_key not in wxid_name_cache:
                        wxid_name_cache[cache_key] = _resolve_sender_name(
                            decrypted_dir, real_sender_id, '',
                            wxid_name_cache=wxid_name_cache)
                    display_name = wxid_name_cache[cache_key]

            entry = sender_counts.get(raw_sender)
            if entry:
                entry['count'] += 1
            else:
                sender_counts[raw_sender] = {'name': display_name, 'count': 1}
        sender_dist = sender_counts
    else:
        cur.execute(f"SELECT origin_source, COUNT(*) FROM [{table_name}] WHERE create_time > 1000000000 GROUP BY origin_source")
        sender_dist = {}
        partner_display = resolve_wxid(decrypted_dir, chat_id)
        if not partner_display or partner_display == chat_id:
            partner_display = chat_id
        for r in cur.fetchall():
            sender_dist['我' if r[0] == 1 else partner_display] = r[1]

    cur.close()
    conn.close()

    return {
        'chat_id': chat_id,
        'total_messages': total,
        'date_range': date_range,
        'sender_distribution': sender_dist,
    }


def get_chat_dates(decrypted_dir: str, chat_id: str) -> dict:
    """Get dates that have messages and per-day counts."""
    db_path, table_name = _find_chat_db(decrypted_dir, chat_id)

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            f"""SELECT date(create_time, 'unixepoch') as d, COUNT(*) as cnt
                FROM [{table_name}] WHERE create_time > 1000000000
                GROUP BY d ORDER BY d DESC"""
        )
        counts = {}
        for row in cur.fetchall():
            counts[row[0]] = row[1]
        cur.close()
    finally:
        conn.close()
    return {'counts': counts}
