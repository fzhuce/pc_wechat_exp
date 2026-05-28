"""
聊天记录导出 — 按联系人/时间/关键词过滤，输出格式化 TXT。
"""
import os
import re
import sqlite3
from datetime import datetime

from engine.constants import TZ, MSG_TYPES_CN
from engine.services.message.decode import decompress_content


def export_chat(chat_info, out_dir, start_ts=None, end_ts=None, keyword=None,
                print_fn=None, progress_fn=None, fmt='txt', display_name=None):
    """导出单个聊天的消息记录。
    Args:
        chat_info: from chat_list.scan_chats
        out_dir: 输出目录
        start_ts: 起始时间戳
        end_ts: 结束时间戳
        keyword: 关键词过滤
        fmt: 输出格式 'txt' 或 'html'
        display_name: display name from UI selection (overrides resolved name for filename)
    Returns: (msg_count, file_path)
    """
    if print_fn is None:
        print_fn = print

    uname = chat_info["username"]
    display = chat_info["display_name"]
    tables = chat_info["tables"]

    # Load all messages
    all_rows = []
    for t in tables:
        conn = None
        try:
            conn = sqlite3.connect(t["db_path"])
            where = []
            params = []
            if start_ts:
                where.append("create_time >= ?")
                params.append(start_ts)
            if end_ts:
                where.append("create_time <= ?")
                params.append(end_ts)
            if keyword:
                where.append("message_content LIKE ?")
                params.append(f"%{keyword}%")

            query = f"""
                SELECT local_id, local_type, real_sender_id, create_time,
                       status, message_content, origin_source
                FROM [{t['table_name']}]
                WHERE create_time > 1000000000
            """
            if where:
                query += " AND " + " AND ".join(where)
            query += " ORDER BY create_time ASC"

            for r in conn.execute(query, params):
                all_rows.append(r)
        except (sqlite3.Error, OSError):
            pass
        finally:
            if conn:
                conn.close()

    if not all_rows:
        return 0, None

    all_rows.sort(key=lambda r: r[3] or 0)

    # Load sender names for this chat
    sender_map = {}
    contact_db_path = None
    for t in tables:
        d = os.path.dirname(t["db_path"])
        parent = os.path.dirname(d)
        candidate = os.path.join(parent, "contact", "contact.db")
        if os.path.exists(candidate):
            contact_db_path = candidate
            break
    # Fallback: search relative path
    if not contact_db_path:
        for t in tables:
            db_path = t["db_path"]
            parts = db_path.replace("\\", "/").split("/")
            for i in range(len(parts)):
                cand = "/".join(parts[:i] + ["contact", "contact.db"])
                if os.path.exists(cand):
                    contact_db_path = cand
                    break
            if contact_db_path:
                break

    if contact_db_path:
        try:
            conn = sqlite3.connect(contact_db_path)
            for r in conn.execute(
                "SELECT id, remark, nick_name, alias, username FROM contact"
            ):
                if r[0]:
                    wxid = r[0]
                    remark_v = (r[1] or '').strip()
                    nick_v = (r[2] or '').strip()
                    alias_v = (r[3] or '').strip()
                    uname = (r[4] or wxid or '').strip()
                    display = remark_v if (remark_v and remark_v != uname) else (
                        nick_v if (nick_v and nick_v != uname) else (
                            alias_v if (alias_v and alias_v != uname) else uname
                        )
                    )
                    if display:
                        sender_map[wxid] = display
            conn.close()
        except (sqlite3.Error, OSError):
            pass

    # Also try Name2Id mapping from message DBs for sender resolution
    name2id_reverse = {}
    for t in tables:
        try:
            conn = sqlite3.connect(t["db_path"])
            for r in conn.execute("SELECT rowid, user_name FROM Name2Id"):
                name2id_reverse[r[0]] = r[1]
            conn.close()
        except (sqlite3.Error, OSError):
            pass

    # Format messages
    lines = []
    lines.append(f"联系人: {display}")
    lines.append(f"微信号: {uname}")
    lines.append(f"导出时间: {datetime.now(TZ).strftime('%Y-%m-%d %H:%M:%S')}")
    if start_ts:
        lines.append(f"起始: {datetime.fromtimestamp(start_ts, tz=TZ).strftime('%Y-%m-%d %H:%M:%S')}")
    if end_ts:
        lines.append(f"结束: {datetime.fromtimestamp(end_ts, tz=TZ).strftime('%Y-%m-%d %H:%M:%S')}")
    if keyword:
        lines.append(f"关键词: {keyword}")
    lines.append(f"消息数: {len(all_rows)}")
    lines.append("=" * 70)
    lines.append("")

    is_group = uname.endswith("@chatroom")

    for row in all_rows:
        local_id, ltype, sender_id, create_time, status, content, origin = row
        base_type = ltype & 0xFFFFFFFF if isinstance(ltype, int) else ltype

        # Resolve sender
        if origin == 1:
            sender = "我"
        elif is_group and isinstance(content, str) and ":\n" in content[:100]:
            parts = content.split(":\n", 1)
            raw_sender = parts[0]
            sender = raw_sender
        elif sender_id and sender_id in sender_map:
            sender = sender_map[sender_id]
        elif sender_id and sender_id in name2id_reverse:
            u = name2id_reverse[sender_id]
            sender = sender_map.get(u, u)
        else:
            sender = f"ID:{sender_id}" if sender_id else ""

        # Parse content — decompress zstd first, then decode
        if isinstance(content, bytes):
            content = decompress_content(content)
        if isinstance(content, bytes):
            try:
                content = content.decode('utf-8', errors='replace')
            except Exception:
                content = ""

        # Format text content
        text = _format_content(content, base_type, is_group)

        dt = datetime.fromtimestamp(create_time, tz=TZ)
        ts = dt.strftime("%Y-%m-%d %H:%M:%S")

        type_tag = ""
        if base_type != 1:
            cn = MSG_TYPES_CN.get(base_type, f"类型{base_type}")
            type_tag = f"[{cn}] "

        lines.append(f"[{ts}] {type_tag}{sender}: {text}")

    # Write file — prefer UI-selected display_name for filename
    file_display = display_name if display_name else display
    safe_name = re.sub(r'[<>:"/\\|?*]', '_', file_display)[:40]
    ext = 'html' if fmt == 'html' else 'txt'
    out_path = os.path.join(out_dir, f"{safe_name}.{ext}")
    os.makedirs(out_dir, exist_ok=True)

    if fmt == 'html':
        _write_html(out_path, display, uname, lines, start_ts, end_ts, keyword)
    else:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

    return len(all_rows), out_path


def _write_html(out_path, display, uname, lines, start_ts, end_ts, keyword):
    """Write chat export as a styled HTML document."""
    # Skip the first 8 header lines (contact/export info + separator + blank)
    body_lines = lines[8:] if len(lines) > 8 else []

    msgs_html = []
    for line in body_lines:
        escaped = _escape_html(line)
        msgs_html.append(f'<div class="msg-line">{escaped}</div>')

    html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>聊天记录 - {_escape_html(display)}</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:#0d1117; color:#c9d1d9; font-family:"Microsoft YaHei","PingFang SC",sans-serif; padding:24px; }}
  .header {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:20px 24px; margin-bottom:16px; }}
  .header h1 {{ color:#58a6ff; font-size:18px; margin-bottom:8px; }}
  .header .meta {{ color:#8b949e; font-size:13px; line-height:1.8; }}
  .header .meta span {{ color:#c9d1d9; }}
  .msg-list {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px 24px; }}
  .msg-line {{ font-size:14px; line-height:1.7; padding:6px 0; border-bottom:1px solid #21262d; font-family:"Cascadia Code","Fira Code",monospace; white-space:pre-wrap; word-break:break-all; }}
  .msg-line:last-child {{ border-bottom:none; }}
</style>
</head>
<body>
<div class="header">
  <h1>聊天记录导出</h1>
  <div class="meta">
    联系人: <span>{_escape_html(display)}</span><br>
    微信号: <span>{_escape_html(uname)}</span><br>
    消息数: <span>{len(body_lines)}</span><br>
    导出时间: <span>{_escape_html(datetime.now(TZ).strftime('%Y-%m-%d %H:%M:%S'))}</span>
  </div>
</div>
<div class="msg-list">
{''.join(msgs_html)}
</div>
</body>
</html>'''
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)


def _escape_html(text):
    """Escape text for HTML body content."""
    if text is None:
        return ''
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _format_content(content, base_type, is_group):
    """格式化消息内容为可读文本。"""
    if content is None:
        return ""

    # Strip sender prefix for group messages
    if is_group and isinstance(content, str) and ":\n" in content[:100]:
        parts = content.split(":\n", 1)
        if len(parts) == 2:
            content = parts[1]

    if base_type == 1:  # text
        return content
    elif base_type == 3:  # image
        return "[图片]"
    elif base_type == 6:  # file
        return "[文件]"
    elif base_type == 34:  # voice
        return "[语音]"
    elif base_type == 42:  # contact_card
        return "[名片]"
    elif base_type == 43:  # video
        return "[视频]"
    elif base_type == 47:  # emoji
        return "[表情]"
    elif base_type == 48:  # location
        return "[位置]"
    elif base_type == 49:  # link/app
        _APP_TYPE_LABELS = {
            '16': '音乐', '33': '小程序', '36': '视频号',
            '2001': '红包', '2000': '转账',
        }
        if isinstance(content, str) and '<appmsg' in content:
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(content)
                title = root.findtext('.//title')
                app_type = root.findtext('.//type') or ''
                label = _APP_TYPE_LABELS.get(app_type, '链接')
                if title:
                    return f"[{label}] {title}"
                if app_type in _APP_TYPE_LABELS:
                    return f"[{_APP_TYPE_LABELS[app_type]}]"
            except ET.ParseError:
                pass
        return "[链接/应用]"
    elif base_type == 50:  # voip
        return "[网络电话]"
    elif base_type in (10000, 10002):  # system
        if isinstance(content, str) and '<sysmsg' in content:
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(content)
                inner = root.findtext('.//content')
                if inner:
                    return f"[系统] {inner.strip()}"
            except Exception:
                pass
        return f"[系统消息] {content}" if content else "[系统消息]"
    return str(content) if content else ""


def export_all_contacts(decrypted_dir, out_dir, start_ts=None, end_ts=None,
                        keyword=None, name_filter=None, print_fn=None, progress_fn=None):
    """导出所有匹配联系人的聊天记录。
    Returns: [(name, msg_count, file_path), ...]
    """
    from chat_list import scan_chats

    if print_fn is None:
        print_fn = print
    if progress_fn is None:
        progress_fn = lambda pct, msg: None

    chats, _, _ = scan_chats(decrypted_dir)

    results = []
    total = len(chats)

    for i, c in enumerate(chats):
        if name_filter:
            kw = name_filter.lower()
            if kw not in c["display_name"].lower() and kw not in c["username"].lower():
                continue

        pct = int((i + 1) / total * 100)
        progress_fn(pct, f"导出: {c['display_name']}")

        count, path = export_chat(c, out_dir, start_ts, end_ts, keyword,
                                  print_fn=print_fn)
        if count > 0:
            results.append((c["display_name"], count, path))
            print_fn(f"  {c['display_name']}: {count} 条消息 -> {os.path.basename(path)}")

    return results
