"""Media resolution for WeChat 4.x messages.

Resolves media file paths from protobuf packed_info, HardLink DB,
MessageResourceInfo, and filesystem scanning for image, video, file,
and voice messages.
"""
import os
import sqlite3

from engine.services.media import _get_base_storage


def _scan_filesystem_for_media(decrypted_dir: str, file_name_prefix: str,
                                ltype: int) -> str:
    """Scan the filesystem for a media file by file_name prefix.

    Walks msg/attach (images), msg/video, or msg/file directories under all
    wxid directories in the WeChat file storage, looking for a file whose
    name starts with file_name_prefix. Returns a relative path like
    'msg/attach/{hash}/{date}/Img/{file_name}' or None.
    """
    import os as _os

    base = _get_base_storage(decrypted_dir)
    if not base:
        return None

    # Try all wxid directories under the base storage
    try:
        wxid_dirs = [d for d in _os.listdir(base)
                     if _os.path.isdir(_os.path.join(base, d))
                     and d.startswith('wxid')]
    except OSError:
        return None

    if ltype == 3:
        leaf_dir = 'Img'
    elif ltype in (43, 6):
        leaf_dir = None
    else:
        return None

    for wxid in wxid_dirs:
        wxid_dir = _os.path.join(base, wxid)
        if ltype == 3:
            search_root = _os.path.join(wxid_dir, 'msg', 'attach')
        elif ltype == 43:
            search_root = _os.path.join(wxid_dir, 'msg', 'video')
        elif ltype == 6:
            search_root = _os.path.join(wxid_dir, 'msg', 'file')
        else:
            continue

        if not _os.path.isdir(search_root):
            continue

        try:
            for hash_dir in _os.listdir(search_root):
                hash_path = _os.path.join(search_root, hash_dir)
                if not _os.path.isdir(hash_path):
                    continue
                for date_dir in _os.listdir(hash_path):
                    target = (_os.path.join(hash_path, date_dir, leaf_dir)
                              if leaf_dir else _os.path.join(hash_path, date_dir))
                    if not _os.path.isdir(target):
                        continue
                    for f in _os.listdir(target):
                        if f.startswith(file_name_prefix):
                            if ltype == 3:
                                return f'msg/attach/{hash_dir}/{date_dir}/Img/{f}'
                            elif ltype == 43:
                                return f'msg/video/{date_dir}/{f}'
                            else:
                                return f'msg/file/{date_dir}/{f}'
        except OSError:
            continue
    return None


def _resolve_via_resource_db(decrypted_dir: str, chat_id: str, local_id: int,
                              ltype: int, extra: dict = None) -> dict:
    """Resolve media file path via MessageResourceInfo → HardLink DB fallback.

    Used when the packed_info_data protobuf doesn't contain a valid md5,
    or when the md5 isn't found in the HardLink DB.
    """
    res_name = _lookup_resource_file_name(decrypted_dir, chat_id, local_id, ltype)
    if not res_name:
        return extra if extra else None

    hardlink_db = os.path.join(decrypted_dir, "hardlink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        hardlink_db = os.path.join(decrypted_dir, "HardLink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        return extra if extra else None

    table_map = {3: 'image', 43: 'video', 6: 'file'}
    table_suffix = table_map.get(ltype, 'image')
    table_name = f'{table_suffix}_hardlink_info_v4'

    try:
        hl_conn = sqlite3.connect(hardlink_db)
        row = hl_conn.execute(
            f"SELECT file_name, file_size, dir1, dir2 FROM [{table_name}]"
            " WHERE file_name LIKE ?",
            (res_name + '%',)
        ).fetchone()
        if not row:
            hl_conn.close()
            # Last resort: scan filesystem directly for the file
            fs_path = _scan_filesystem_for_media(decrypted_dir, res_name, ltype)
            if fs_path:
                file_name = os.path.basename(fs_path)
                file_size = os.path.getsize(fs_path) if os.path.isfile(fs_path) else 0
                result = {
                    'md5': '',
                    'file_name': file_name,
                    'file_size': file_size,
                    'local_path': fs_path,
                    'media_type': ltype,
                }
                if extra:
                    result.update(extra)
                return result
            return extra if extra else None

        file_name, file_size, dir1, dir2 = row

        dir1_name = None
        dir2_name = None
        if dir2:
            d2 = hl_conn.execute("SELECT username FROM dir2id WHERE rowid=?", (dir2,)).fetchone()
            dir2_name = d2[0] if d2 else str(dir2)
        if dir1:
            d1 = hl_conn.execute("SELECT username FROM dir2id WHERE rowid=?", (dir1,)).fetchone()
            dir1_name = d1[0] if d1 else str(dir1)
        hl_conn.close()

        if ltype == 3 and dir1_name and dir2_name:
            local_path = f'msg/attach/{dir1_name}/{dir2_name}/Img/{file_name}'
        elif ltype == 43 and dir1_name:
            local_path = f'msg/video/{dir1_name}/{file_name}'
        elif ltype == 6 and dir1_name:
            local_path = f'msg/file/{dir1_name}/{file_name}'
        else:
            local_path = None

        result = {
            'md5': '',
            'file_name': file_name,
            'file_size': file_size,
            'local_path': local_path,
            'media_type': ltype,
        }
        if extra:
            result.update(extra)
        return result
    except sqlite3.Error:
        return extra if extra else None


def _resolve_media_from_proto(decrypted_dir: str, packed_info: bytes, ltype: int,
                              local_id: int = 0, create_time: int = 0,
                              chat_id: str = '') -> dict:
    """Decode protobuf packed_info_data and resolve to local file paths via HardLink DB.

    For voice (type 34): extracts duration from packed_info and looks up voice data
    in VoiceInfo table of media_0.db by (create_time, local_id).
    For image/video/file (types 3/43/6): extracts md5, queries HardLink DB for local paths.
    Falls back to MessageResourceInfo file_name lookup if md5-based resolution fails.

    Returns dict or None if nothing useful found.
    """
    if not packed_info or not isinstance(packed_info, bytes):
        return None

    try:
        import blackboxprotobuf
        decoded, _ = blackboxprotobuf.decode_message(packed_info)
    except Exception:
        return None

    # Voice: extract duration and resolve voice file from VoiceInfo table
    if ltype == 34:
        duration = decoded.get('1', 0)
        if not isinstance(duration, int) or duration <= 0:
            return None
        result = {'duration': duration, 'media_type': 34}
        if local_id and create_time:
            voice_path = _resolve_voice_path(decrypted_dir, create_time, local_id)
            if voice_path:
                result['voice_path'] = voice_path
                result['local_path'] = voice_path
        return result

    # Image/video/file: extract md5 for HardLink resolution
    md5_val = None
    field_3 = decoded.get('3', {})
    field_4 = decoded.get('4', {})
    if isinstance(field_3, dict):
        md5_val = field_3.get('4', b'')
    # Video stores md5 in field 4 nested message key '8'
    if not md5_val and isinstance(field_4, dict):
        md5_val = field_4.get('8', b'')
    # Fallback: top-level field 4 (bytes)
    if not md5_val:
        md5_val = decoded.get('4', b'') if isinstance(decoded.get('4'), (bytes, str)) else None
    if isinstance(md5_val, bytes):
        try:
            md5_str = md5_val.decode('ascii', errors='replace')
        except Exception:
            return None
    elif isinstance(md5_val, str):
        md5_str = md5_val
    else:
        md5_str = ''

    # Strip _t/_h suffix. The protobuf may store the thumbnail md5
    # (e.g. "abc123_t") while the HardLink DB indexes by the bare CDN
    # md5 ("abc123") which maps to both original (.dat) and thumbnails
    # (_h.dat, _t.dat).
    if md5_str and len(md5_str) == 34 and (md5_str.endswith('_t') or md5_str.endswith('_h')):
        md5_str = md5_str[:-2]

    # Video: extract dimensions from field 4 nested message
    extra = {'media_type': ltype}
    if ltype == 43 and isinstance(field_4, dict):
        w = field_4.get('4') or field_4.get('5')
        h = field_4.get('5') if w == field_4.get('4') else field_4.get('4')
        if isinstance(w, int) and isinstance(h, int) and w > 0 and h > 0:
            extra['width'] = w
            extra['height'] = h

    if not md5_str or len(md5_str) != 32:
        if chat_id:
            return _resolve_via_resource_db(decrypted_dir, chat_id, local_id, ltype, extra)
        return extra if extra else None

    # Look up in HardLink DB
    hardlink_db = os.path.join(decrypted_dir, "hardlink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        hardlink_db = os.path.join(decrypted_dir, "HardLink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        if chat_id:
            return _resolve_via_resource_db(decrypted_dir, chat_id, local_id, ltype, extra)
        r = {'md5': md5_str}
        r.update(extra)
        return r

    table_map = {3: 'image', 43: 'video', 6: 'file'}
    table_suffix = table_map.get(ltype, 'image')
    table_name = f'{table_suffix}_hardlink_info_v4'

    try:
        hl_conn = sqlite3.connect(hardlink_db)
        # Prefer original (.dat) over thumbnails (_h.dat, _t.dat) when the
        # same CDN md5 maps to multiple rows in the HardLink DB.
        rows = hl_conn.execute(
            f"SELECT file_name, file_size, dir1, dir2 FROM [{table_name}]"
            f" WHERE md5=? ORDER BY CASE WHEN substr(file_name, -6)='_h.dat' THEN 2"
            f" WHEN substr(file_name, -6)='_t.dat' THEN 3 ELSE 1 END",
            (md5_str,)
        ).fetchall()
        if not rows:
            hl_conn.close()
            # Fallback: try resource hash from message_resource.db
            if chat_id:
                res_name = _lookup_resource_file_name(
                    decrypted_dir, chat_id, local_id, ltype)
                if res_name:
                    hl2 = sqlite3.connect(hardlink_db)
                    fb_row = hl2.execute(
                        f"SELECT file_name, file_size, dir1, dir2 FROM [{table_name}]"
                        " WHERE file_name LIKE ?",
                        (res_name + '%',)
                    ).fetchone()
                    if fb_row:
                        rows = [fb_row]
                        hl_conn = hl2
                    else:
                        hl2.close()
                        # Last resort: scan filesystem directly
                        fs_path = _scan_filesystem_for_media(
                            decrypted_dir, res_name, ltype)
                        if fs_path:
                            fname = os.path.basename(fs_path)
                            result = {
                                'md5': md5_str,
                                'file_name': fname,
                                'file_size': 0,
                                'local_path': fs_path,
                                'media_type': ltype,
                            }
                            result.update(extra)
                            return result
            if not rows:
                r = {'md5': md5_str, 'media_type': ltype}
                r.update(extra)
                return r

        file_name, file_size, dir1, dir2 = rows[0]

        # Resolve directory names from dir2id
        dir1_name = None
        dir2_name = None
        if dir2:
            d2 = hl_conn.execute("SELECT username FROM dir2id WHERE rowid=?", (dir2,)).fetchone()
            dir2_name = d2[0] if d2 else str(dir2)
        if dir1:
            d1 = hl_conn.execute("SELECT username FROM dir2id WHERE rowid=?", (dir1,)).fetchone()
            dir1_name = d1[0] if d1 else str(dir1)

        hl_conn.close()

        # Construct relative path based on media type
        # Image: msg/attach/{dir1_hash}/{dir2_date}/Img/{file_name}
        # Video: msg/video/{dir1_date}/{file_name}
        # File:  msg/file/{dir1_date}/{file_name}
        if ltype == 3 and dir1_name and dir2_name:
            local_path = f'msg/attach/{dir1_name}/{dir2_name}/Img/{file_name}'
        elif ltype == 43 and dir1_name:
            local_path = f'msg/video/{dir1_name}/{file_name}'
        elif ltype == 6 and dir1_name:
            local_path = f'msg/file/{dir1_name}/{file_name}'
        else:
            local_path = None

        result = {
            'md5': md5_str,
            'file_name': file_name,
            'file_size': file_size,
            'local_path': local_path,
            'media_type': ltype,
        }
        result.update(extra)
        return result
    except sqlite3.Error:
        r = {'md5': md5_str}
        r.update(extra)
        return r


def _lookup_resource_file_name(decrypted_dir: str, chat_id: str, local_id: int,
                               media_type: int) -> str:
    """Look up the file_name hash from message_resource.db for a given message.

    WeChat 4.x stores file references in MessageResourceInfo.packed_info as
    {'2': {'1': b'file_name_hash'}}. This hash matches the file_name column
    in HardLink DB, allowing path resolution when the md5 lookup fails.
    """
    import os as _os
    res_db = _os.path.join(decrypted_dir, "message", "message_resource.db")
    if not _os.path.isfile(res_db):
        return None
    try:
        conn = sqlite3.connect(res_db)
        chat_row = conn.execute(
            "SELECT rowid FROM ChatName2Id WHERE user_name=?", (chat_id,)
        ).fetchone()
        if not chat_row:
            conn.close()
            return None
        chat_id_int = chat_row[0]
        res_row = conn.execute(
            "SELECT packed_info FROM MessageResourceInfo"
            " WHERE chat_id=? AND message_local_id=? AND message_local_type=?",
            (chat_id_int, local_id, media_type)
        ).fetchone()
        conn.close()
        if not res_row or not res_row[0]:
            return None
        import blackboxprotobuf
        decoded, _ = blackboxprotobuf.decode_message(res_row[0])
        file_name = decoded.get('2', {}).get('1', b'')
        if isinstance(file_name, bytes):
            return file_name.decode('ascii', errors='replace')
    except Exception:
        pass
    return None


def _resolve_voice_path(decrypted_dir: str, create_time: int, local_id: int) -> str:
    """Look up voice data in VoiceInfo table and cache to output/voice/ directory.

    Returns a relative path like 'voice/{create_time}_{local_id}.silk' suitable
    for serving via the /api/voice endpoint.
    """
    import os as _os
    media_db = _os.path.join(decrypted_dir, "message", "media_0.db")
    if not _os.path.isfile(media_db):
        return None

    try:
        conn = sqlite3.connect(media_db)
        row = conn.execute(
            "SELECT voice_data FROM VoiceInfo WHERE create_time=? AND local_id=?",
            (create_time, local_id)
        ).fetchone()
        conn.close()
        if not row or not row[0]:
            return None

        voice_data = row[0]
        if not isinstance(voice_data, bytes) or len(voice_data) < 10:
            return None

        # Cache to <decrypted_dir>/media/voice/ directory
        output_dir = _os.path.join(decrypted_dir, "media", "voice")
        _os.makedirs(output_dir, exist_ok=True)
        voice_file = _os.path.join(output_dir, f'{create_time}_{local_id}.silk')
        if not _os.path.isfile(voice_file):
            with open(voice_file, 'wb') as f:
                f.write(voice_data)

        return f'media/voice/{create_time}_{local_id}.silk'
    except sqlite3.Error:
        return None
