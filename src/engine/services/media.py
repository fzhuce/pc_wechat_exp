"""Media file resolution and serving."""
import os
import sqlite3
import mimetypes
import struct
from flask import abort, send_file

STORAGE_CANDIDATES = [
    'MsgAttach', 'FileStorage', 'Image', 'Video',
    'FileStorage/MsgAttach', 'FileStorage/Image',
]

# Common WeChat .dat file XOR keys
_DAT_XOR_KEYS = [0xC9, 0x37, 0x96, 0x6A, 0xFF]

# WeChat .dat encryption version signatures
# V1: \x07\x08V1\x08\x07 — AES-128-ECB with fixed key (MD5 of '0')
# V2: \x07\x08V2\x08\x07 — AES-128-ECB with dynamic app-specific key
_DAT_V1_HEADER = b'\x07\x08\x56\x31\x08\x07'
_DAT_V2_HEADER = b'\x07\x08\x56\x32\x08\x07'
_DAT_V2_DEFAULT_XOR = 0xC9  # empirically confirmed: 17325+ files use this
# V1 fixed AES key: MD5 of '0'
_DAT_V1_AES_KEY = bytes.fromhex('cfcd208495d565ef')

# Cache of image AES keys collected from type 3 XML messages
_image_aes_keys = {}


def _detect_wxid(decrypted_dir: str) -> str:
    """Auto-detect the WeChat user wxid from the storage directory.

    Tries: db_info uuid, scanning xwechat_files for matching subdir,
    checking contact DB for own username.
    """
    # Strategy 1: From hardlink.db db_info -> uuid -> storage root
    hardlink_db = os.path.join(decrypted_dir, "hardlink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        hardlink_db = os.path.join(decrypted_dir, "HardLink", "hardlink.db")
    if os.path.isfile(hardlink_db):
        conn = None
        try:
            conn = sqlite3.connect(hardlink_db)
            row = conn.execute(
                "SELECT ValueStdStr FROM db_info WHERE Key='uuid'"
            ).fetchone()
            conn.close()
            conn = None
            if row and row[0]:
                parts = str(row[0]).split('_', 2)
                if len(parts) >= 3:
                    storage_root = parts[-1]
                    if os.path.isdir(storage_root):
                        # Find the wxid dir in storage root (exclude dot-dirs, all_users)
                        for d in os.listdir(storage_root):
                            if d.startswith('wxid_') and os.path.isdir(
                                os.path.join(storage_root, d)
                            ):
                                return d
        except (sqlite3.Error, OSError):
            pass
        finally:
            if conn:
                conn.close()

    # Strategy 2: Scan known storage locations
    for storage_root in [r'D:\xwechat_files', r'C:\xwechat_files',
                         r'D:\WeChat Files', r'C:\WeChat Files']:
        try:
            if os.path.isdir(storage_root):
                for d in os.listdir(storage_root):
                    if d.startswith('wxid_') and os.path.isdir(
                        os.path.join(storage_root, d)
                    ):
                        return d
        except OSError:
            continue

    return os.path.basename(os.path.dirname(decrypted_dir))


def _get_base_storage(decrypted_dir: str) -> str:
    """Get the original WeChat file storage root from hardlink.db's db_info table."""
    hardlink_db = os.path.join(decrypted_dir, "hardlink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        hardlink_db = os.path.join(decrypted_dir, "HardLink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        return None
    conn = None
    try:
        conn = sqlite3.connect(hardlink_db)
        row = conn.execute(
            "SELECT ValueStdStr FROM db_info WHERE Key='uuid'"
        ).fetchone()
        conn.close()
        conn = None
        if row and row[0]:
            parts = str(row[0]).split('_', 2)
            if len(parts) >= 3:
                storage_path = parts[-1]
                if os.path.isdir(storage_path):
                    return storage_path
    except sqlite3.Error:
        pass
    finally:
        if conn:
            conn.close()
    return None


def _resolve_hardlink_path(decrypted_dir: str, media_info: dict, wxid: str = None) -> str:
    """Resolve a HardLink-based media reference to an absolute filesystem path.

    media_info contains: md5, local_path (relative to wxid dir), media_type (3/43/6/34).
    local_path format per type:
      - Image (3):  msg/attach/{dir1_hash}/{dir2_date}/Img/{file_name}
      - Video (43): msg/video/{dir1_date}/{file_name}
      - File (6):   msg/file/{dir1_date}/{file_name}
    """
    if not media_info:
        return None

    local_path = media_info.get('local_path')
    md5 = media_info.get('md5', '')
    media_type = media_info.get('media_type', 0)

    wxid = wxid or os.path.basename(os.path.dirname(decrypted_dir))

    # Helper: try all combinations of base + wxid + path
    def _try_paths(rel_path):
        if not rel_path:
            return None
        rel_path = rel_path.replace('/', os.sep)
        storage_roots = []
        base = _get_base_storage(decrypted_dir)
        if base:
            storage_roots.append(base)
        for sr in ['D:\\xwechat_files', 'C:\\xwechat_files',
                   'D:\\WeChat Files', 'C:\\WeChat Files']:
            if os.path.isdir(sr) and sr not in storage_roots:
                storage_roots.append(sr)
        for root in storage_roots:
            for wd in [wxid, '']:
                if not wd:
                    continue
                candidate = os.path.join(root, wd, rel_path)
                try:
                    real = os.path.realpath(candidate)
                except (OSError, ValueError):
                    continue
                if not os.path.isfile(real):
                    continue
                # Containment check — prevent path traversal (e.g. ?path=..\..\Windows\...)
                expected_parent = os.path.realpath(os.path.join(root, wd))
                try:
                    if os.path.commonpath([real, expected_parent]) != expected_parent:
                        continue
                except ValueError:
                    continue
                return real
        return None

    if local_path:
        result = _try_paths(local_path)
        if result:
            return result

    # Fallback: look up md5 in HardLink DB and construct path
    if md5 and len(md5) == 32:
        result = _resolve_from_hardlink_db(decrypted_dir, md5, media_type)
        print(f"  [RESOLVE] bare md5={md5[:16]}... hldb_result={result}")
        if result:
            abs_path = _try_paths(result)
            if abs_path:
                return abs_path
            # _try_paths failed — try backup media/ directory
            hldb_fname = os.path.basename(result)
            candidate = _try_backup_media_dir(decrypted_dir, media_type, hldb_fname)
            if candidate:
                return candidate

    # Fallback: search backup media/ directory by file_name from media_info
    # After backup, media files are migrated to {decrypted_dir}/media/{category}/
    # but _try_paths only searches original WeChat storage.
    file_name = media_info.get('file_name', '')
    if not file_name and local_path:
        file_name = os.path.basename(local_path)
    candidate = _try_backup_media_dir(decrypted_dir, media_type, file_name)
    if candidate:
        return candidate

    # Fallback: md5-based search in backup media directory
    # When file_name is missing (e.g. forwarded videos), try common extensions
    if md5 and len(md5) == 32:
        candidate = _try_backup_media_by_md5(decrypted_dir, media_type, md5)
        if candidate:
            return candidate

    # Final fallback: when bare md5/path (no _t/_h suffix) doesn't resolve,
    # try thumbnail variants, then directory scan. Full-size image may exist
    # on disk without a HardLink DB entry.
    if md5 and len(md5) == 32 and not (md5.endswith('_t') or md5.endswith('_h')):
        _fallback_file = None  # thumbnail to use if directory scan finds nothing
        _fallback_dir = None   # directory to scan for full-size file
        for suffix in ('_h', '_t'):  # _h first (higher quality thumbnail)
            variant_md5 = md5 + suffix
            # Try HardLink DB
            variant_hl_path = _resolve_from_hardlink_db(decrypted_dir, variant_md5, media_type)
            if variant_hl_path:
                v_dir, v_fname = os.path.split(variant_hl_path)
                v_name, v_ext = os.path.splitext(v_fname)
                # Try bare (full-size) file first
                if v_name.endswith(suffix):
                    bare_fname = v_name[:-len(suffix)] + v_ext
                    bare_hl_path = os.path.join(v_dir, bare_fname) if v_dir else bare_fname
                    abs_path = _try_paths(bare_hl_path)
                    if abs_path:
                        return abs_path
                # Check if variant (thumbnail) file exists — remember as fallback
                abs_path = _try_paths(variant_hl_path)
                if abs_path and _fallback_file is None:
                    _fallback_file = abs_path
                    _fallback_dir = v_dir
                # Try backup media by variant filename
                hldb_fname = os.path.basename(variant_hl_path)
                candidate = _try_backup_media_dir(decrypted_dir, media_type, hldb_fname)
                if candidate:
                    return candidate
                if _fallback_dir is None:
                    _fallback_dir = v_dir
            # Try backup media by variant md5
            if _fallback_file is None:
                candidate = _try_backup_media_by_md5(decrypted_dir, media_type, variant_md5)
                if candidate:
                    _fallback_file = candidate
        # Try _t/_h suffix on the local_path filename itself
        if local_path and _fallback_file is None:
            dir_part, fname = os.path.split(local_path)
            name, ext = os.path.splitext(fname)
            if not (name.endswith('_t') or name.endswith('_h')):
                for suffix in ('_h', '_t'):
                    variant_path = os.path.join(dir_part, name + suffix + ext) if dir_part else name + suffix + ext
                    result = _try_paths(variant_path)
                    if result:
                        _fallback_file = result
                        break
        # Directory scan: look for files matching the bare md5 prefix in the
        # same directory as the thumbnail. The original may exist without a
        # HardLink DB entry (e.g. WeChat indexed only the thumbnail).
        if _fallback_dir:
            wxid_val = wxid or os.path.basename(os.path.dirname(decrypted_dir))
            roots = [_get_base_storage(decrypted_dir)] if _get_base_storage(decrypted_dir) else []
            for sr in ['D:\\xwechat_files', 'C:\\xwechat_files',
                       'D:\\WeChat Files', 'C:\\WeChat Files']:
                if os.path.isdir(sr) and sr not in roots:
                    roots.append(sr)
            for root in roots:
                abs_dir = os.path.join(root, wxid_val, _fallback_dir)
                if os.path.isdir(abs_dir):
                    try:
                        for fname in os.listdir(abs_dir):
                            if fname.startswith(md5) and not (
                                fname.endswith('_t.dat') or fname.endswith('_h.dat')):
                                candidate = os.path.join(abs_dir, fname)
                                if os.path.isfile(candidate):
                                    print(f"  [RESOLVE] dir scan found: {fname}")
                                    return candidate
                    except OSError:
                        pass
        # Return thumbnail as last resort
        if _fallback_file:
            return _fallback_file

    return None


def _try_backup_media_dir(decrypted_dir: str, media_type: int, file_name: str) -> str:
    """Try to find a media file in the backup's flat media/ directory.

    After backup, `migrate_media` copies files to:
      {decrypted_dir}/media/images/  (type 3)
      {decrypted_dir}/media/videos/  (type 43)
      {decrypted_dir}/media/files/   (type 6)
      {decrypted_dir}/media/voice/   (type 34)
    """
    if not file_name:
        return None
    cat_map = {3: 'images', 43: 'videos', 6: 'files', 34: 'voice'}
    category = cat_map.get(media_type, '')
    if not category:
        return None
    candidate = os.path.join(decrypted_dir, 'media', category, file_name)
    if os.path.isfile(candidate):
        return os.path.realpath(candidate)
    return None


def _try_backup_media_by_md5(decrypted_dir: str, media_type: int, md5: str) -> str:
    """Find a media file in the backup media/ dir by md5 with common extensions."""
    cat_map = {3: 'images', 43: 'videos', 6: 'files', 34: 'voice'}
    category = cat_map.get(media_type, '')
    if not category or len(md5) < 8:
        return None
    base_dir = os.path.join(decrypted_dir, 'media', category)
    if not os.path.isdir(base_dir):
        return None
    # Common extensions per type
    exts_map = {3: ['.dat', '.jpg', '.png', '.gif', '.webp', '_h.dat', '_t.dat'],
                43: ['.mp4', '.mov', '.avi', '.dat'],
                6: ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar', ''],
                34: ['.silk', '.wav', '.amr', '.mp3']}
    exts = exts_map.get(media_type, ['.dat'])
    for ext in exts:
        fname = md5 + ext
        candidate = os.path.join(base_dir, fname)
        if os.path.isfile(candidate):
            return os.path.realpath(candidate)
    # Broader search: any file in the category dir starting with this md5
    md5_lower = md5.lower()
    try:
        for fname in os.listdir(base_dir):
            if fname.lower().startswith(md5_lower):
                return os.path.realpath(os.path.join(base_dir, fname))
    except OSError:
        pass
    return None


def _resolve_from_hardlink_db(decrypted_dir: str, md5: str, media_type: int) -> str:
    """Look up a file in the HardLink DB by md5 and return its relative path."""
    hardlink_db = os.path.join(decrypted_dir, "hardlink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        hardlink_db = os.path.join(decrypted_dir, "HardLink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        return None

    table_map = {3: 'image', 43: 'video', 6: 'file', 34: 'voice'}
    table_suffix = table_map.get(media_type, 'image')
    table_name = f'{table_suffix}_hardlink_info_v4'

    conn = None
    try:
        conn = sqlite3.connect(hardlink_db)
        # Prefer original (.dat) over thumbnails (_h.dat, _t.dat) when the
        # same CDN md5 maps to multiple rows in the HardLink DB.
        rows = conn.execute(
            f"SELECT file_name, dir1, dir2 FROM [{table_name}] WHERE md5=? "
            f"ORDER BY CASE WHEN substr(file_name, -6)='_h.dat' THEN 2 "
            f"WHEN substr(file_name, -6)='_t.dat' THEN 3 ELSE 1 END",
            (md5,)
        ).fetchall()
        if not rows:
            return None

        file_name, dir1, dir2 = rows[0]
        dir1_name = None
        dir2_name = None
        if dir2:
            d2 = conn.execute("SELECT * FROM dir2id WHERE rowid=?", (dir2,)).fetchone()
            dir2_name = d2[0] if d2 else None
        if dir1:
            d1 = conn.execute("SELECT * FROM dir2id WHERE rowid=?", (dir1,)).fetchone()
            dir1_name = d1[0] if d1 else None

        if media_type == 3:  # Image
            if dir1_name and dir2_name:
                return f'msg/attach/{dir1_name}/{dir2_name}/Img/{file_name}'
        elif media_type == 43:  # Video
            if dir1_name:
                return f'msg/video/{dir1_name}/{file_name}'
        elif media_type == 6:  # File
            if dir1_name:
                return f'msg/file/{dir1_name}/{file_name}'

        return None
    except sqlite3.Error:
        return None
    finally:
        if conn:
            conn.close()


def resolve_media_path(db_dir: str, file_path: str) -> str:
    """Resolve a WeChat file reference to an absolute filesystem path."""
    if not file_path or not db_dir:
        return None

    if file_path.startswith('http://') or file_path.startswith('https://'):
        return None

    cleaned = file_path
    for prefix in ['THUMBNAIL_DIRPATH://', 'FILEID://', 'big/']:
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):]

    wxid_dir = os.path.dirname(db_dir)
    allowed_roots = [db_dir, wxid_dir]
    allowed_roots = [os.path.realpath(r) for r in allowed_roots if r]

    def _safe_join_try(base, rel):
        trial = os.path.realpath(os.path.join(base, rel))
        if not os.path.isfile(trial):
            return None
        for root in allowed_roots:
            try:
                if os.path.commonpath([trial, root]) == root:
                    return trial
            except ValueError:
                pass
        return None

    if os.path.isabs(cleaned):
        for root in allowed_roots:
            result = _safe_join_try(root, os.path.basename(cleaned))
            if result:
                return result

    for candidate in STORAGE_CANDIDATES:
        for base in [db_dir, wxid_dir]:
            result = _safe_join_try(base, os.path.join(candidate, cleaned))
            if result:
                return result

    result = _safe_join_try(wxid_dir, cleaned)
    if result:
        return result

    return None


def serve_media(db_dir: str, file_path: str):
    """Flask response: serve a media file using traditional path resolution."""
    resolved = resolve_media_path(db_dir, file_path)
    if resolved is None or not os.path.isfile(resolved):
        abort(404)
    mime, _ = mimetypes.guess_type(resolved)
    return send_file(resolved, mimetype=mime or 'application/octet-stream',
                     max_age=86400)


# Common WeChat .dat file XOR keys
_DAT_XOR_KEYS = [0xC9, 0x37, 0x96, 0x6A, 0xFF]


def _detect_dat_xor_key(file_path: str) -> tuple:
    """Try to detect the XOR key for an encrypted .dat file.

    Returns (key, file_ext) if found, or (None, None) if the file is not
    XOR-encrypted or uses an unknown key.
    """
    MAGICS = [
        # (magic_bytes, ext, mime, min_match_len)
        (b'\xff\xd8\xff', 'jpg', 'image/jpeg', 3),
        (b'\x89PNG\r\n\x1a\n', 'png', 'image/png', 4),
        (b'GIF89a', 'gif', 'image/gif', 4),
        (b'GIF87a', 'gif', 'image/gif', 4),
        (b'RIFF', 'webp', 'image/webp', 4),
    ]
    try:
        fsize = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            data = f.read(16)
        if len(data) < 4:
            return None, None
        # Try known keys first
        for key in _DAT_XOR_KEYS:
            dec = bytes(b ^ key for b in data)
            for magic, ext, _, min_len in MAGICS:
                if dec[:min_len] == magic[:min_len]:
                    return key, ext
        # Auto-detect: try all 256 possible keys (only for strong matches)
        for key in range(256):
            if key in _DAT_XOR_KEYS:
                continue
            dec = bytes(b ^ key for b in data)
            for magic, ext, _, min_len in MAGICS:
                if dec[:min_len] == magic[:min_len]:
                    # For JPEG, also verify the next marker byte
                    if ext == 'jpg' and dec[3] not in (0xe0, 0xe1, 0xe2, 0xdb, 0xc4, 0xc0):
                        continue
                    return key, ext
    except OSError:
        pass
    return None, None


def _decrypt_dat_file(src_path: str, xor_key: int, output_dir: str) -> str:
    """Decrypt a .dat file using XOR and cache the result.

    Returns the path to the decrypted file.
    """
    import hashlib
    src_hash = hashlib.md5(src_path.encode()).hexdigest()[:12]
    out_name = f'{src_hash}.dec'
    out_path = os.path.join(output_dir, out_name)
    if os.path.isfile(out_path) and os.path.getsize(out_path) > 0:
        return out_path
    try:
        with open(src_path, 'rb') as f:
            data = f.read()
        dec = bytes(b ^ xor_key for b in data)
        os.makedirs(output_dir, exist_ok=True)
        with open(out_path, 'wb') as f:
            f.write(dec)
        return out_path
    except OSError:
        return None


def _detect_wechat_dat_version(data: bytes) -> int:
    """Detect WeChat .dat image encryption version from file header.

    V0: No version signature — pure XOR encryption (classic WeChat)
    V1: \\x07\\x08V1\\x08\\x07 — AES-128-ECB with fixed key cfcd208495d565ef
    V2: \\x07\\x08V2\\x08\\x07 — AES-128-ECB with dynamic app-specific key
    Returns 0, 1, or 2.
    """
    if len(data) < 6:
        return 0
    if data[:6] == _DAT_V2_HEADER:
        return 2
    if data[:6] == _DAT_V1_HEADER:
        return 1
    # Short match: just the first 4 bytes (some variants)
    if data[:4] == b'\x07\x08\x56\x32':
        return 2
    if data[:4] == b'\x07\x08\x56\x31':
        return 1
    return 0


def _decrypt_dat_v1(file_path: str, output_dir: str) -> str:
    """Decrypt a V1 .dat file using fixed AES key + XOR.

    V1 format: 6-byte header + AES-ECB body + XOR tail.
    Returns path to decrypted file, or None.
    """
    try:
        from Crypto.Cipher import AES
    except ImportError:
        return None

    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except OSError:
        return None

    if len(data) < 22:
        return None

    # Try to find XOR key from the last bytes
    # V1 files have an XOR-encrypted tail after the AES portion
    # The XOR key is typically the last byte XOR magic_byte
    xor_key = None
    for key in _DAT_XOR_KEYS:
        # Try decrypting the last few bytes with this key
        test = bytes(b ^ key for b in data[-16:])
        # Check for JPEG/PNG end markers
        if test[-2:] == b'\xff\xd9' or b'IEND' in test:
            xor_key = key
            break

    if xor_key is None:
        return None

    # Decrypt: AES-128-ECB from byte 6 to (end - xor_tail_len)
    # The exact split between AES and XOR is encoded in the header after the 6-byte signature
    try:
        aes_size = struct.unpack_from('<I', data, 6)[0]
        xor_size = struct.unpack_from('<I', data, 10)[0]
    except struct.error:
        return None

    body_start = 15  # 6 (sig) + 4 (aes_size) + 4 (xor_size) + 1 (padding)
    if body_start + aes_size > len(data):
        return None

    aes_data = data[body_start:body_start + aes_size]
    raw_start = body_start + aes_size
    xor_data = data[raw_start:]

    # Decrypt AES portion
    try:
        cipher = AES.new(_DAT_V1_AES_KEY, AES.MODE_ECB)
        dec_aes = cipher.decrypt(aes_data)
        # Remove PKCS7 padding
        pad = dec_aes[-1]
        if 0 < pad <= 16:
            dec_aes = dec_aes[:-pad]
    except Exception:
        return None

    # Decrypt XOR portion (if any)
    dec_xor = bytes(b ^ xor_key for b in xor_data) if xor_data else b''

    result = dec_aes + dec_xor

    import hashlib
    src_hash = hashlib.md5(file_path.encode()).hexdigest()[:12]
    out_path = os.path.join(output_dir, f'{src_hash}_v1.dec')
    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(out_path, 'wb') as f:
            f.write(result)
        return out_path
    except OSError:
        return None


_ACCOUNT_KEYS_CACHE: dict = {}  # wxid -> {'xor': int, 'aes': bytes}


# --- Per-image V2 key map (replaces broken per-account model) ---

_IMAGE_KEY_MAP: dict = {}  # md5 -> {'aes': bytes, 'xor': int}
_IMAGE_KEY_MAP_DIR: str = None


def _load_or_build_image_key_map(decrypted_dir: str) -> dict:
    """Load md5->key map from _media_keys.json cache.

    Only loads keys that were verified by memory extraction (harvest-keys).
    Does NOT rebuild from message DBs — those contain CDN aeskeys which have
    been confirmed to NOT decrypt local .dat files.
    """
    global _IMAGE_KEY_MAP, _IMAGE_KEY_MAP_DIR

    if _IMAGE_KEY_MAP and _IMAGE_KEY_MAP_DIR == decrypted_dir:
        return _IMAGE_KEY_MAP

    import json as _json
    keys_file = os.path.join(decrypted_dir, '_media_keys.json')

    result = {}
    try:
        if os.path.isfile(keys_file) and os.path.getsize(keys_file) > 0:
            with open(keys_file, 'r', encoding='utf-8') as f:
                cached = _json.load(f)
            md5_keys = cached.get('md5_keys', {})
            for md5, v in md5_keys.items():
                try:
                    result[md5] = {
                        'aes': bytes.fromhex(v['aes_key']),
                        'xor': int(v.get('xor_key', '0'), 16)
                    }
                except (ValueError, KeyError):
                    pass
            if result:
                # Ensure _h thumbnail variants exist for all cached keys
                _h_added = 0
                for md5 in list(result.keys()):
                    if not md5.endswith('_h'):
                        thumb = md5 + '_h'
                        if thumb not in result:
                            result[thumb] = result[md5]
                            _h_added += 1
                if _h_added:
                    print(f"[media] Added {_h_added} _h thumbnail variants to cached keys", flush=True)
                print(f"[media] Loaded {len(result)} verified keys from cache", flush=True)

    except Exception:
        pass

    _IMAGE_KEY_MAP = result
    _IMAGE_KEY_MAP_DIR = decrypted_dir
    return result


def _get_account_media_keys(decrypted_dir: str, wxid: str) -> tuple:
    """Get per-account XOR and AES keys for V2 .dat decryption.

    Checks local cache first, then extracts keys from decrypted message DBs
    by scanning V2 image/video XML for the per-account aeskey attribute.
    Returns (xor_key: int, aes_key: bytes) or (None, None).
    """
    global _ACCOUNT_KEYS_CACHE

    if wxid in _ACCOUNT_KEYS_CACHE:
        cached = _ACCOUNT_KEYS_CACHE[wxid]
        return cached.get('xor'), cached.get('aes')

    # Check _media_keys.json cache file
    keys_file = os.path.join(decrypted_dir, '_media_keys.json')
    try:
        if os.path.isfile(keys_file):
            import json
            with open(keys_file, 'r', encoding='utf-8') as f:
                all_keys = json.load(f)
            account_keys = all_keys.get(wxid, {})
            if account_keys.get('aes_key'):
                xor_raw = account_keys.get('xor_key', '')
                if isinstance(xor_raw, str) and xor_raw.startswith('0x'):
                    xor_key = int(xor_raw, 16)
                elif isinstance(xor_raw, (int, float)):
                    xor_key = int(xor_raw)
                else:
                    xor_key = int(xor_raw) if xor_raw else 0
                aes_key_raw = account_keys['aes_key']
                if len(aes_key_raw) == 32 and all(c in '0123456789abcdefABCDEF' for c in aes_key_raw):
                    aes_key = bytes.fromhex(aes_key_raw)
                else:
                    aes_key = aes_key_raw[:16].encode('ascii')
                _ACCOUNT_KEYS_CACHE[wxid] = {'xor': xor_key, 'aes': aes_key}
                return xor_key, aes_key
    except Exception:
        pass

    # Extract keys locally from decrypted message DBs
    xor_key, aes_key = _extract_media_keys_from_dbs(decrypted_dir)
    if aes_key is None:
        return None, None

    # Cache in memory and file
    _ACCOUNT_KEYS_CACHE[wxid] = {'xor': xor_key, 'aes': aes_key}

    try:
        os.makedirs(os.path.dirname(keys_file), exist_ok=True)
        all_keys = {}
        if os.path.isfile(keys_file):
            with open(keys_file, 'r', encoding='utf-8') as f:
                all_keys = json.load(f)
        all_keys[wxid] = {'xor_key': f'0x{xor_key:02X}', 'aes_key': aes_key.hex()}
        with open(keys_file, 'w', encoding='utf-8') as f:
            json.dump(all_keys, f, indent=2)
    except Exception:
        pass

    return xor_key, aes_key


def _extract_media_keys_from_dbs(decrypted_dir: str) -> tuple:
    """Extract V2 media AES key from decrypted message databases.

    Scans Msg_ tables for V2 image/video XML that contains the per-account
    aeskey attribute. The XOR key defaults to 0 (most common case).

    Returns (xor_key: int, aes_key: bytes) or (None, None).
    """
    import json
    import re as _re

    msg_dir = os.path.join(decrypted_dir, 'message')
    if not os.path.isdir(msg_dir):
        print("[media] message dir not found:", msg_dir, flush=True)
        return None, None

    try:
        import zstandard as zstd
        dctx = zstd.ZstdDecompressor()
    except ImportError:
        print("[media] zstandard not installed — cannot decompress message_content", flush=True)
        return None, None

    _ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'
    _AESKEY_RE = _re.compile(rb'''aeskey\s*=\s*["']([0-9a-fA-F]{32,64}|[0-9a-zA-Z+/=]{16,48})["']''')
    _XORKEY_RE = _re.compile(rb'xorkey\s*=\s*["\']([0-9a-fA-F]{2})["\']')

    total_scanned = 0
    total_zstd = 0
    for fname in sorted(os.listdir(msg_dir)):
        if not fname.startswith('message_') or not fname.endswith('.db'):
            continue
        db_path = os.path.join(msg_dir, fname)
        try:
            conn = sqlite3.connect(db_path)
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
            ).fetchall()
            for (tname,) in tables:
                # Search both message_content and packed_info_data for each type individually
                # to avoid the IN clause which might be optimized differently
                for search_type in (3, 43):
                    rows = conn.execute(
                        f"SELECT message_content FROM [{tname}] "
                        f"WHERE (local_type & 0xFFFF) = ? AND length(message_content) > 50 "
                        f"LIMIT 100",
                        (search_type,)
                    ).fetchall()
                    for (content,) in rows:
                        total_scanned += 1
                        if not isinstance(content, bytes):
                            continue
                        # Try zstd first
                        dec = None
                        if content[:4] == _ZSTD_MAGIC:
                            total_zstd += 1
                            try:
                                dec = dctx.decompress(content)
                            except Exception:
                                pass
                        if dec is None:
                            # Not zstd — try raw text
                            try:
                                dec = content.decode('utf-8', errors='replace')
                                if 'aeskey' not in dec:
                                    dec = None
                            except Exception:
                                pass
                        if dec is None:
                            continue
                        m = _AESKEY_RE.search(dec)
                        if not m:
                            continue
                        aes_hex = m.group(1).decode('ascii')
                        if len(aes_hex) >= 32:
                            try:
                                aes_key = bytes.fromhex(aes_hex[:32])
                            except ValueError:
                                aes_key = aes_hex[:16].encode('ascii')
                        else:
                            aes_key = aes_hex[:16].encode('ascii')

                        xor_key = _DAT_V2_DEFAULT_XOR
                        xm = _XORKEY_RE.search(dec)
                        if xm:
                            try:
                                xor_key = int(xm.group(1), 16)
                            except ValueError:
                                pass

                        print(f"[media] Found aeskey in {fname}/{tname} type={search_type}, "
                              f"xor=0x{xor_key:02X}", flush=True)
                        conn.close()
                        return xor_key, aes_key
            conn.close()
        except sqlite3.Error:
            continue

    print(f"[media] Key scan complete: scanned {total_scanned} messages "
          f"({total_zstd} zstd) across {msg_dir}, no aeskey found", flush=True)
    return None, None


def _translate_file_md5_to_cdn_md5(decrypted_dir: str, file_md5: str) -> str:
    """Map a file-name md5 (from .dat file) to the CDN md5 (from XML) via hardlink DB.

    The hardlink DB's image_hardlink_info_v4 table maps:
      - md5 column: CDN image md5 (appears in message_content XML with aeskey)
      - file_name column: local .dat file name ({file_content_md5}.dat)

    This function bridges the two, enabling key lookup:
      file_md5 → hardlink DB → CDN md5 → message_content XML → aeskey

    Returns the CDN md5 string, or None if not found.
    """
    if not file_md5 or len(file_md5) != 32:
        return None
    hardlink_db = os.path.join(decrypted_dir, "hardlink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        hardlink_db = os.path.join(decrypted_dir, "HardLink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        return None
    try:
        conn = sqlite3.connect(hardlink_db)
        # file_name is stored as {md5}.dat, {md5}_t.dat, {md5}_h.dat, etc.
        row = conn.execute(
            "SELECT md5 FROM image_hardlink_info_v4 WHERE file_name LIKE ? LIMIT 1",
            (file_md5 + '%',)
        ).fetchone()
        conn.close()
        if row and row[0]:
            return row[0]
    except sqlite3.Error:
        pass
    return None


def _collect_image_aeskey(decrypted_dir: str, md5: str) -> str:
    """Find the AES key for a specific V2 image by searching message DBs.

    Handles thumbnail (_h) suffix: if md5 ends with '_h', also tries the
    parent image's md5. Searches both aeskey and cdnthumbaeskey attributes.

    Returns the 32-char hex aeskey string, or None.
    """
    global _image_aes_keys
    if md5 in _image_aes_keys:
        return _image_aes_keys[md5]

    import re as _re

    # Resolve search targets: if md5 ends with '_h', also try base md5
    search_md5s = [md5]
    is_thumb = md5.endswith('_h')
    if is_thumb:
        base_md5 = md5[:-2]
        if base_md5 in _image_aes_keys:
            _image_aes_keys[md5] = _image_aes_keys[base_md5]
            return _image_aes_keys[base_md5]
        search_md5s.append(base_md5)

    # If direct search fails, also try CDN md5 via hardlink DB bridge.
    # The file md5 (from .dat file name) is different from the CDN md5
    # (from XML <img md5="...">), but they map via image_hardlink_info_v4.
    for _sm5 in list(search_md5s):
        _cdn = _translate_file_md5_to_cdn_md5(decrypted_dir, _sm5)
        if _cdn and _cdn not in search_md5s:
            search_md5s.append(_cdn)

    msg_dir = os.path.join(decrypted_dir, 'message')
    if not os.path.isdir(msg_dir):
        return None

    try:
        import zstandard as zstd
        dctx = zstd.ZstdDecompressor()
    except ImportError:
        return None

    _ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'
    _AESKEY_PAT = _re.compile(rb'''aeskey\s*=\s*["']([0-9a-fA-F]{32,64})["']''')
    _CDNTHUMB_PAT = _re.compile(rb'''cdnthumbaeskey\s*=\s*["']([0-9a-fA-F]{32,64})["']''')

    # Pre-compile md5 patterns for all search variants
    _md5_patterns = [
        (sm5, _re.compile(
            rb'''md5\s*=\s*["'](''' + _re.escape(sm5.encode()) + rb''')["']'''
        ))
        for sm5 in search_md5s
    ]

    for fname in os.listdir(msg_dir):
        if not fname.startswith('message_') or not fname.endswith('.db'):
            continue
        db_path = os.path.join(msg_dir, fname)
        try:
            conn = sqlite3.connect(db_path)
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
            ).fetchall()
            for (tname,) in tables:
                # Search both type 3 (image) and type 43 (video, may ref thumbnails)
                for search_type in (3, 43):
                    cursor = conn.execute(
                        f"SELECT message_content FROM [{tname}] "
                        f"WHERE (local_type & 0xFFFF) = ? AND length(message_content) > 50",
                        (search_type,)
                    )
                    while True:
                        batch = cursor.fetchmany(500)
                        if not batch:
                            break
                        for (content,) in batch:
                            if not isinstance(content, bytes):
                                continue
                            dec = None
                            if content[:4] == _ZSTD_MAGIC:
                                try:
                                    dec = dctx.decompress(content)
                                except Exception:
                                    pass
                            if dec is None:
                                # zstd failed — check if content has aeskey patterns as plain text.
                                # Keep as bytes for regex compatibility.
                                if b'aeskey' not in content and b'cdnthumbaeskey' not in content:
                                    dec = None
                                else:
                                    dec = content
                            if dec is None:
                                continue
                            # Check each search md5
                            for sm5, md5_pat in _md5_patterns:
                                if not md5_pat.search(dec):
                                    continue
                                # Try aeskey first, then cdnthumbaeskey
                                m_key = _AESKEY_PAT.search(dec)
                                if not m_key:
                                    m_key = _CDNTHUMB_PAT.search(dec)
                                if m_key:
                                    key = m_key.group(1).decode('ascii')[:32]
                                    # Cache for both the searched md5 and the original
                                    _image_aes_keys[sm5] = key
                                    if sm5 != md5:
                                        _image_aes_keys[md5] = key
                                    # Also cache _h variant for non-thumb md5s
                                    if not sm5.endswith('_h'):
                                        _image_aes_keys[sm5 + '_h'] = key
                                    print(f"[media] Found per-image aeskey for md5={sm5[:16]}... in {fname}", flush=True)
                                    conn.close()
                                    return key
            conn.close()
        except sqlite3.Error:
            pass

    return None


def _decrypt_dat_v2(file_path: str, aes_key: bytes, xor_key: int = None, output_dir: str = None) -> str:
    """Decrypt a V2 .dat file using AES-128-ECB key + XOR tail.

    V2 format (WeChat 4.x):
      [15 bytes: 6-byte sig + 4-byte AES size + 4-byte XOR size + 1 pad]
      [AES-encrypted data (aes_sz plaintext, PKCS7-padded to 16-byte boundary)]
      [Raw unencrypted data]
      [XOR-encrypted tail (xor_sz bytes)]

    aes_key: 16 raw bytes (ASCII string from _media_keys.json, not hex-decoded)
    xor_key: integer 0-255 (default: 0xC9, the empirically-confirmed WeChat 4.x value)
    output_dir: directory for cached decrypted file (default: temp dir next to file)

    Returns path to decrypted file, or None.
    """
    if xor_key is None:
        xor_key = _DAT_V2_DEFAULT_XOR
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(file_path), 'decrypted_media')
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Padding
    except ImportError:
        return None

    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except OSError:
        return None

    if len(data) < 22:
        return None

    try:
        sig = data[:6]
        aes_size, hdr_xor_size = struct.unpack_from('<II', data, 6)
    except struct.error:
        return None

    if sig != _DAT_V2_HEADER:
        return None

    padded_aes_size = aes_size + 16 - (aes_size % 16)

    body_start = 15
    if body_start + padded_aes_size > len(data):
        return None

    aes_data = data[body_start:body_start + padded_aes_size]

    try:
        cipher = AES.new(aes_key[:16], AES.MODE_ECB)
        dec_aes_padded = cipher.decrypt(aes_data)
        dec_aes = Padding.unpad(dec_aes_padded, AES.block_size)
    except Exception:
        return None

    raw_start = body_start + padded_aes_size
    if hdr_xor_size > 0 and raw_start + hdr_xor_size <= len(data):
        raw_data = data[raw_start:-hdr_xor_size]
        xor_data = data[-hdr_xor_size:]
    else:
        raw_data = data[raw_start:]
        xor_data = b''

    dec_xor = bytes(b ^ xor_key for b in xor_data) if xor_data else b''
    result = dec_aes + raw_data + dec_xor

    # Convert wxgf (WeChat proprietary) to standard image if needed
    if result[:4] == b'wxgf':
        result = _convert_wxgf(result) or result

    import hashlib
    src_hash = hashlib.md5(file_path.encode()).hexdigest()[:12]
    out_path = os.path.join(output_dir, f'{src_hash}_v2.dec')
    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(out_path, 'wb') as f:
            f.write(result)
        return out_path
    except OSError:
        return None


def _convert_wxgf(data: bytes) -> bytes:
    """Convert WeChat wxgf image format to standard JPEG/PNG using native DLL."""
    if os.name != 'nt':
        return None

    # Try to find VoipEngine.dll
    dll_paths = [
        os.path.join(os.path.dirname(__file__), 'native', 'VoipEngine.dll'),
        r'D:\perl_wrk\PC_Wechat\WeChatDataAnalysis_ref\src\wechat_decrypt_tool\native\VoipEngine.dll',
    ]
    dll_path = None
    for p in dll_paths:
        if os.path.isfile(p):
            dll_path = p
            break
    if not dll_path:
        return None

    try:
        import ctypes

        class _WxAMConfig(ctypes.Structure):
            _fields_ = [('mode', ctypes.c_int), ('reserved', ctypes.c_int)]

        voip = ctypes.WinDLL(dll_path)
        fn = voip.wxam_dec_wxam2pic_5
        fn.argtypes = [ctypes.c_int64, ctypes.c_int, ctypes.c_int64,
                       ctypes.POINTER(ctypes.c_int), ctypes.c_int64]
        fn.restype = ctypes.c_int64

        max_out = 52 * 1024 * 1024
        for mode in (0, 3):
            config = _WxAMConfig()
            config.mode = mode
            config.reserved = 0
            in_buf = ctypes.create_string_buffer(data, len(data))
            out_buf = ctypes.create_string_buffer(max_out)
            out_sz = ctypes.c_int(max_out)

            ret = fn(ctypes.addressof(in_buf), len(data),
                     ctypes.addressof(out_buf), ctypes.byref(out_sz),
                     ctypes.addressof(config))
            if ret == 0 and out_sz.value > 0:
                return out_buf.raw[:out_sz.value]
    except Exception:
        pass

    return None


def _find_cached_thumbnail(decrypted_dir: str, md5: str, local_id: int = 0, wxid: str = None) -> str:
    """Find a cached thumbnail in WeChat's cache directory for a V2 image.

    WeChat 4.x stores decrypted thumbnails at:
      {storage_root}/{wxid}/cache/YYYY-MM/Message/{dir1_hash}/Thumb/{local_id}_{ts}_thumb.jpg

    This is a fallback when the V2 AES key is unavailable — thumbnails are
    already decrypted by WeChat and can be served directly.
    """
    if not md5 or len(md5) != 32:
        return None

    # Get dir1 from hardlink DB
    hardlink_db = os.path.join(decrypted_dir, "hardlink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        hardlink_db = os.path.join(decrypted_dir, "HardLink", "hardlink.db")
    if not os.path.isfile(hardlink_db):
        return None

    try:
        conn = sqlite3.connect(hardlink_db)
        # Try file_name LIKE first (file md5), then md5 column (CDN md5)
        row = conn.execute(
            "SELECT dir1 FROM image_hardlink_info_v4 WHERE file_name LIKE ? LIMIT 1",
            (md5 + '%',)
        ).fetchone()
        if not row:
            row = conn.execute(
                "SELECT dir1 FROM image_hardlink_info_v4 WHERE md5=? LIMIT 1",
                (md5,)
            ).fetchone()
        if not row:
            conn.close()
            return None

        dir1_id = row[0]
        dir1_row = conn.execute(
            "SELECT username FROM dir2id WHERE rowid=?", (dir1_id,)
        ).fetchone()
        conn.close()
        if not dir1_row or not dir1_row[0]:
            return None
        dir1_name = dir1_row[0]
    except sqlite3.Error:
        return None

    # Find WeChat storage root and wxid
    storage_root = _get_base_storage(decrypted_dir)
    wxid = wxid or _detect_wxid(decrypted_dir)
    if not storage_root or not wxid:
        # Try well-known locations
        for sr in [r'D:\xwechat_files', r'C:\xwechat_files']:
            if os.path.isdir(sr):
                storage_root = sr
                break
        if not storage_root:
            return None

    wxid_dir = os.path.join(storage_root, wxid)
    if not os.path.isdir(wxid_dir):
        return None

    # Search cache directories for matching thumbnail
    cache_base = os.path.join(wxid_dir, 'cache')
    if not os.path.isdir(cache_base):
        return None

    if not local_id or local_id <= 0:
        return None  # must have local_id for correct mapping

    thumb_dir = os.path.join(cache_base, '*', 'Message', dir1_name, 'Thumb')
    thumb_glob = os.path.join(thumb_dir, f'{local_id}_*_thumb.*')

    import glob
    matches = glob.glob(thumb_glob)
    if not matches:
        return None

    # Return the largest (highest quality) match
    best = max(matches, key=os.path.getsize)
    return best if os.path.isfile(best) else None


def serve_hardlink_media(decrypted_dir: str, media_info: dict, wxid: str = None):
    """Flask response: serve a media file resolved via HardLink DB.

    Handles V0 (XOR), V1 (fixed AES), and V2 (dynamic AES) WeChat .dat encryption.
    """
    if not media_info:
        abort(404)

    resolved = _resolve_hardlink_path(decrypted_dir, media_info, wxid)
    print(f"  [LIGHTBOX] md5={media_info.get('md5','')[:16]}... resolved={resolved}")
    if resolved is None or not os.path.isfile(resolved):
        abort(404)

    # Handle .dat encrypted files
    if resolved.lower().endswith('.dat'):
        # Detect encryption version
        try:
            with open(resolved, 'rb') as f:
                header = f.read(256)
        except OSError:
            abort(404)

        version = _detect_wechat_dat_version(header)

        # V2: per-image AES key (keys are only in WeChat process memory)
        if version == 2:
            md5_val = media_info.get('md5', '')

            def _try_v2_decrypt(key_bytes, xor_val):
                """Try to decrypt and return a Flask response or None."""
                if key_bytes is None:
                    return None
                cache_dir = os.path.join(os.path.dirname(decrypted_dir), 'decrypted_media')
                dec_path = _decrypt_dat_v2(resolved, key_bytes, xor_val, cache_dir)
                if dec_path and os.path.isfile(dec_path):
                    mime, _ = mimetypes.guess_type(dec_path)
                    return send_file(dec_path, mimetype=mime or 'image/jpeg')
                return None

            # Collect md5 variants to try (base + _h thumbnail)
            # NOTE: CDN md5 bridge and message-DB aeskey search are intentionally
            # removed. CDN aeskeys from XML <img aeskey="..."> have been confirmed
            # to NEVER decrypt local .dat files. Only memory-extracted keys
            # (from harvest-keys) can decrypt V2 files.
            _md5_variants = []
            if md5_val and len(md5_val) == 32:
                _md5_variants = [md5_val]
                # Add common WeChat thumbnail suffixes (_h, _t) and strip suffix for lookup
                for _suffix in ('_h', '_t'):
                    if md5_val.endswith(_suffix):
                        _md5_variants.append(md5_val[:-2])
                        break
                else:
                    _md5_variants.append(md5_val + '_h')
                    _md5_variants.append(md5_val + '_t')

                # 1) Try cached key map (keys from memory extraction via harvest-keys)
                key_map = _load_or_build_image_key_map(decrypted_dir)
                for _try_md5 in _md5_variants:
                    entry = key_map.get(_try_md5)
                    if entry:
                        rv = _try_v2_decrypt(entry['aes'], entry['xor'])
                        if rv:
                            return rv

                # 2) Try MMKV-based local key derivation (py_wx_key approach)
                # Derives keys OFFLINE from %APPDATA%\Tencent\xwechat\**\kvcomm\
                # key_N_.statistic files — no WeChat process or memory scan needed.
                from engine.services.v2_key_extract import extract_keys_from_mmkv
                try:
                    mmkv_keys = extract_keys_from_mmkv(decrypted_dir, wxid)
                    if mmkv_keys:
                        # extract_keys_from_mmkv already caches to _media_keys.json
                        # Invalidate in-memory cache so reload picks up new keys
                        global _IMAGE_KEY_MAP, _IMAGE_KEY_MAP_DIR
                        _IMAGE_KEY_MAP = {}
                        _IMAGE_KEY_MAP_DIR = None
                        key_map = _load_or_build_image_key_map(decrypted_dir)
                        for _try_md5 in _md5_variants:
                            entry = key_map.get(_try_md5)
                            if entry:
                                rv = _try_v2_decrypt(entry['aes'], entry['xor'])
                                if rv:
                                    return rv
                except Exception as e:
                    print(f"  [V2] MMKV key extraction failed: {e}")

                # 2b) Account-key fallback: V2 keys are per-account, not per-image.
                # If we have ANY cached key but this specific MD5 isn't in the map,
                # try the account-level key directly — it should decrypt ALL V2 files.
                if key_map and not any(key_map.get(m) for m in _md5_variants):
                    fallback_entry = next(iter(key_map.values()))
                    rv = _try_v2_decrypt(fallback_entry['aes'], fallback_entry['xor'])
                    if rv:
                        return rv

                # 3) Try live memory extraction from running WeChat
                from engine.services.v2_key_extract import find_keys_for_files, is_wechat_running
                if is_wechat_running():
                    for _try_md5 in _md5_variants:
                        found = find_keys_for_files(decrypted_dir, wxid, [_try_md5])
                        if _try_md5 in found:
                            rv = _try_v2_decrypt(found[_try_md5], _DAT_V2_DEFAULT_XOR)
                            if rv:
                                return rv

            # 4) Thumbnail cache fallback — WeChat stores decrypted thumbnails
            local_id = media_info.get('local_id', 0) if media_info else 0
            thumb = _find_cached_thumbnail(decrypted_dir, md5_val, local_id, wxid)
            if thumb and os.path.isfile(thumb):
                mime, _ = mimetypes.guess_type(thumb)
                return send_file(thumb, mimetype=mime or 'image/jpeg', max_age=86400)

            # Diagnostic: report why this image failed
            diag_parts = [os.path.basename(resolved)]
            if md5_val and len(md5_val) == 32:
                diag_parts.append(f'md5={md5_val[:8]}...')
                diag_parts.append('steps:key+mmkv')
                try:
                    _v2_check_wx = is_wechat_running
                except NameError:
                    _v2_check_wx = None
                if _v2_check_wx and _v2_check_wx():
                    diag_parts.append('+mem')
            elif md5_val:
                diag_parts.append(f'md5-short({len(md5_val)})')
            else:
                diag_parts.append('no-md5')
            if not thumb:
                diag_parts.append('no-thumb')
            elif not os.path.isfile(thumb):
                diag_parts.append('thumb-miss')
            print(f"  [V2 IMG FAIL] {' | '.join(diag_parts)}")

            # Provide actionable error message
            from engine.services.v2_key_extract import is_wechat_running as _wx_running
            if _wx_running():
                abort(415, description='V2加密图片，请在微信中查看该图片后刷新重试')
            else:
                abort(415, description='V2加密图片 — 本地密钥推导未匹配，请启动微信浏览该图片后刷新')

        # V1: fixed AES key — decryptable
        if version == 1:
            cache_dir = os.path.join(os.path.dirname(decrypted_dir), 'decrypted_media')
            dec_path = _decrypt_dat_v1(resolved, cache_dir)
            if dec_path and os.path.isfile(dec_path):
                mime, _ = mimetypes.guess_type(dec_path)
                return send_file(dec_path, mimetype=mime or 'image/jpeg')

        # V0: XOR encryption — try known keys
        xor_key, ext = _detect_dat_xor_key(resolved)
        if xor_key is not None:
            cache_dir = os.path.join(os.path.dirname(decrypted_dir), 'decrypted_media')
            dec_path = _decrypt_dat_file(resolved, xor_key, cache_dir)
            if dec_path and os.path.isfile(dec_path):
                mime, _ = mimetypes.guess_type(f'file.{ext}')
                return send_file(dec_path, mimetype=mime or 'application/octet-stream')

        # Serve raw (might be non-encrypted .dat)
        mime, _ = mimetypes.guess_type(resolved)
        return send_file(resolved, mimetype=mime or 'application/octet-stream',
                         max_age=86400)

    mime, _ = mimetypes.guess_type(resolved)
    return send_file(resolved, mimetype=mime or 'application/octet-stream',
                     max_age=86400)


# --- Emoji / Sticker AES-128-CBC decryption ---


def decrypt_emoticon_aes_cbc(data: bytes, aes_key_hex: str):
    """Decrypt WeChat emoticon/sticker payload using AES-128-CBC.

    Scheme (observed in WeChat 4.x):
      - Key = bytes.fromhex(aes_key_hex)  (16 bytes, typically the emoji MD5)
      - IV  = key
      - Cipher = AES-128-CBC
      - Padding = PKCS7

    Returns decrypted bytes or None on failure.
    """
    if not data or len(data) % 16 != 0:
        return None

    khex = str(aes_key_hex or '').strip().lower()
    if len(khex) != 32 or not all(c in '0123456789abcdef' for c in khex):
        return None

    try:
        key = bytes.fromhex(khex)
    except Exception:
        return None

    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Padding
        pt_padded = AES.new(key, AES.MODE_CBC, iv=key).decrypt(data)
        return Padding.unpad(pt_padded, AES.block_size)
    except Exception:
        return None


def serve_voice(decrypted_dir: str, voice_path: str,
                create_time: int = None, local_id: int = None,
                db_dir: str = None):
    """Flask response: serve a voice file (SILK or converted WAV).

    Searches cached voice directories first. If the file isn't found and
    create_time+local_id are provided, attempts on-the-fly extraction from
    the VoiceInfo table in media_0.db.
    """
    if not voice_path:
        abort(404)

    filename = os.path.basename(voice_path)

    # Search both new and old voice cache locations
    search_dirs = [
        os.path.join(decrypted_dir, "media", "voice"),          # migrator + new cache
        os.path.join(os.path.dirname(decrypted_dir), "voice"),  # old _resolve_voice_path cache
    ]

    silk_file = None
    wav_file = None
    for d in search_dirs:
        candidate_silk = os.path.join(d, filename)
        candidate_wav = os.path.splitext(candidate_silk)[0] + '.wav'
        if os.path.isfile(candidate_wav) and os.path.getsize(candidate_wav) > 0:
            wav_file = candidate_wav
            break
        if os.path.isfile(candidate_silk):
            silk_file = candidate_silk
            wav_file = candidate_wav
            break

    # Fallback: extract from VoiceInfo table on-the-fly
    if not silk_file and not wav_file and create_time is not None and local_id is not None:
        silk_file = _extract_voice_from_db(decrypted_dir, create_time, local_id,
                                           db_dir=db_dir)
        if silk_file and os.path.isfile(silk_file):
            wav_file = os.path.splitext(silk_file)[0] + '.wav'

    if wav_file and not silk_file and os.path.isfile(wav_file):
        return send_file(wav_file, mimetype='audio/wav')

    if silk_file:
        wav_path = _silk_to_wav(silk_file, wav_file)
        if wav_path and os.path.isfile(wav_path):
            return send_file(wav_path, mimetype='audio/wav')
        print(f"  [WARN] SILK→WAV conversion failed for: {silk_file}")
        return send_file(silk_file, mimetype='application/octet-stream',
                         as_attachment=True, download_name=os.path.basename(silk_file))

    abort(404)


def _extract_voice_from_db(decrypted_dir: str, create_time: int,
                           local_id: int, db_dir: str = None) -> str:
    """Extract voice data from VoiceInfo table and cache to disk.

    Looks for media_0.db first in the decrypted message directory,
    then (if db_dir given) tries to decrypt it from the source on-the-fly.

    Returns the path to the cached .silk file, or None.
    """
    import sqlite3 as _sqlite3

    candidates = [os.path.join(decrypted_dir, "message", "media_0.db")]

    # If not found in decrypted dir, try to decrypt from source on-the-fly
    if db_dir and (not os.path.isfile(candidates[0])):
        src_db = os.path.join(db_dir, "message", "media_0.db")
        if os.path.isfile(src_db):
            tmp_db = _decrypt_media_db_on_the_fly(src_db, decrypted_dir)
            if tmp_db:
                candidates.insert(0, tmp_db)

    for media_db in candidates:
        if not os.path.isfile(media_db):
            continue
        try:
            conn = _sqlite3.connect(media_db)
            row = conn.execute(
                "SELECT voice_data FROM VoiceInfo WHERE create_time=? AND local_id=?",
                (create_time, local_id)
            ).fetchone()
            conn.close()
        except _sqlite3.Error:
            continue

        if not row or not row[0]:
            continue

        voice_data = row[0]
        if not isinstance(voice_data, bytes) or len(voice_data) < 10:
            continue

        output_dir = os.path.join(decrypted_dir, "media", "voice")
        os.makedirs(output_dir, exist_ok=True)
        silk_file = os.path.join(output_dir, f'{create_time}_{local_id}.silk')
        if not os.path.isfile(silk_file):
            with open(silk_file, 'wb') as f:
                f.write(voice_data)
        return silk_file

    return None


def _decrypt_media_db_on_the_fly(src_db: str, decrypted_dir: str) -> str:
    """Decrypt a single media_*.db from WeChat source to the decrypted message dir.

    Returns path to decrypted file, or None.
    """
    import sqlite3 as _sqlite3
    try:
        from engine.config_file import get_db_keys
        from engine.decrypt import decrypt_database
    except ImportError:
        return None

    keys = get_db_keys()
    if not keys:
        return None

    # Find key: try basename match first, then fallback to any key
    key = None
    basename = os.path.basename(src_db)
    for kpath, kval in keys.items():
        if os.path.basename(kpath) == basename and len(kval) == 64:
            key = bytes.fromhex(kval)
            break
    if key is None:
        for v in keys.values():
            if len(str(v)) == 64:
                key = bytes.fromhex(str(v))
                break
    if key is None:
        return None

    dst = os.path.join(decrypted_dir, "message", basename)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    try:
        ok = decrypt_database(src_db, dst, key)
        return dst if ok else None
    except Exception:
        return None


def _silk_to_wav(silk_path: str, wav_path: str) -> str:
    """Convert a SILK V3 file to WAV using standalone decoder. Returns WAV path or None."""
    import subprocess, sys
    # Find silk_decoder.exe: try PyInstaller _MEIPASS first, then source tree
    decoder = None
    # PyInstaller onefile bundles extract to sys._MEIPASS
    bundle_dir = getattr(sys, '_MEIPASS', None)
    if bundle_dir:
        candidate = os.path.join(bundle_dir, 'tools', 'silk_decoder.exe')
        if os.path.isfile(candidate):
            decoder = candidate
    if not decoder:
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))))
        candidate = os.path.join(project_root, 'tools', 'silk_decoder.exe')
        if os.path.isfile(candidate):
            decoder = candidate
    if not decoder:
        print(f"  [WARN] silk_decoder.exe not found (project_root={project_root}, bundle_dir={bundle_dir})")
        return None
    try:
        pcm_path = wav_path + '.pcm'
        result = subprocess.run(
            [decoder, silk_path, pcm_path],
            capture_output=True, timeout=30
        )
        if result.returncode != 0:
            stderr = result.stderr.decode('utf-8', errors='replace').strip()
            print(f"  [WARN] silk_decoder.exe failed (exit={result.returncode}): {stderr}")
            if os.path.isfile(pcm_path):
                try:
                    os.remove(pcm_path)
                except OSError:
                    pass
            return None
        if not os.path.isfile(pcm_path):
            print(f"  [WARN] silk_decoder.exe produced no output file: {pcm_path}")
            return None
        with open(pcm_path, 'rb') as f:
            pcm_data = f.read()
        os.remove(pcm_path)
        if not pcm_data:
            print(f"  [WARN] silk_decoder.exe produced empty PCM: {pcm_path}")
            return None
        _write_wav(wav_path, pcm_data)
        return wav_path
    except subprocess.TimeoutExpired:
        print(f"  [WARN] silk_decoder.exe timeout after 30s: {silk_path}")
        return None
    except (subprocess.SubprocessError, OSError) as e:
        print(f"  [WARN] silk_decoder.exe error: {e}")
        return None


def transcribe_voice(decrypted_dir: str, voice_path: str) -> str:
    """Convert voice SILK to WAV and transcribe using available speech recognition.

    Returns the transcription text, or raises ValueError with a user-friendly message.
    """
    if not voice_path:
        raise ValueError('voice_path required')

    filename = os.path.basename(voice_path)

    search_dirs = [
        os.path.join(decrypted_dir, "media", "voice"),
        os.path.join(os.path.dirname(decrypted_dir), "voice"),
    ]

    silk_file = None
    for d in search_dirs:
        candidate = os.path.join(d, filename)
        if os.path.isfile(candidate):
            silk_file = candidate
            break

    if not silk_file:
        raise ValueError('语音文件不存在')

    wav_file = os.path.splitext(silk_file)[0] + '.wav'

    if not os.path.isfile(wav_file) or os.path.getsize(wav_file) == 0:
        wav_path = _silk_to_wav(silk_file, wav_file)
        if not wav_path or not os.path.isfile(wav_path):
            raise ValueError('语音解码失败')

    return _transcribe_wav(wav_file)


# Cache whisper model across requests
_whisper_model = None
_whisper_model_name = None


def _get_whisper_model(model_name: str = 'base'):
    """Load and cache a Whisper model. Uses 'base' for good Chinese accuracy/speed balance."""
    global _whisper_model, _whisper_model_name
    if _whisper_model is not None and _whisper_model_name == model_name:
        return _whisper_model

    try:
        import whisper
        _whisper_model = whisper.load_model(model_name)
        _whisper_model_name = model_name
        return _whisper_model
    except ImportError:
        return None
    except Exception:
        return None


def _transcribe_wav(wav_path: str) -> str:
    """Transcribe a WAV file using Whisper (openai-whisper) or WhisperX."""
    errors = []

    # Try openai-whisper first
    try:
        model = _get_whisper_model('base')
        if model is None:
            raise ImportError('whisper not available')
        result = model.transcribe(wav_path, language='zh', fp16=False)
        text = result.get('text', '').strip()
        if text:
            return text
    except ImportError:
        errors.append('openai-whisper 未安装')
    except Exception as e:
        errors.append(f'whisper 识别失败: {e}')

    # Try WhisperX as fallback
    try:
        import whisperx
        import gc
        device = 'cpu'
        model = whisperx.load_model('base', device, compute_type='int8')
        audio = whisperx.load_audio(wav_path)
        result = model.transcribe(audio, language='zh', batch_size=1)
        text = ' '.join(s.get('text', '') for s in result.get('segments', [])).strip()
        # Clean up to free memory
        gc.collect()
        if text:
            return text
    except ImportError:
        errors.append('whisperx 未安装')
    except Exception as e:
        errors.append(f'whisperx 识别失败: {e}')

    if errors:
        raise ValueError(
            '语音识别失败:\n' +
            '\n'.join(f'  - {e}' for e in errors) +
            '\n\n请安装 Whisper:\n  pip install openai-whisper'
        )
    else:
        raise ValueError('未识别到语音内容')


def _write_wav(wav_path: str, pcm_data: bytes, sample_rate: int = 24000):
    """Write raw 16-bit mono PCM data to a WAV file."""
    num_channels = 1
    bits_per_sample = 16
    byte_rate = sample_rate * num_channels * bits_per_sample // 8
    block_align = num_channels * bits_per_sample // 8
    data_size = len(pcm_data)

    with open(wav_path, 'wb') as f:
        # RIFF header
        f.write(b'RIFF')
        f.write((36 + data_size).to_bytes(4, 'little'))
        f.write(b'WAVE')
        # fmt chunk
        f.write(b'fmt ')
        f.write((16).to_bytes(4, 'little'))
        f.write((1).to_bytes(2, 'little'))  # PCM
        f.write(num_channels.to_bytes(2, 'little'))
        f.write(sample_rate.to_bytes(4, 'little'))
        f.write(byte_rate.to_bytes(4, 'little'))
        f.write(block_align.to_bytes(2, 'little'))
        f.write(bits_per_sample.to_bytes(2, 'little'))
        # data chunk
        f.write(b'data')
        f.write(data_size.to_bytes(4, 'little'))
        f.write(pcm_data)
