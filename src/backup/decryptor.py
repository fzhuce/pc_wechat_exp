"""Decrypt WeChat databases for backup, using engine.decrypt."""
import hashlib
import hmac as hmac_mod
import os
import json
import struct
from typing import Callable

# SQLCipher 4 constants (must match engine/constants.py)
PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16


def load_keys(key_file: str = None) -> dict:
    """Load decryption keys from config or a legacy JSON file.

    When key_file is None, reads from .wechat_exp_config.json via get_db_keys().
    Otherwise loads from the given file (legacy all_keys.json format).

    Returns dict mapping db_path -> key (hex string).
    Handles both formats: plain hex strings and {"enc_key": "..."} dicts.
    """
    if key_file is None:
        from engine.config_file import get_db_keys
        return get_db_keys()

    if not os.path.exists(key_file):
        return {}
    try:
        with open(key_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    result = {}
    for k, v in data.items():
        if k.startswith('_'):
            continue
        if isinstance(v, dict):
            hex_key = v.get('enc_key', '')
            if hex_key and len(hex_key) == 64:
                result[k] = hex_key
        elif isinstance(v, str) and len(v) == 64:
            result[k] = v
    return result


def _verify_enc_key(enc_key: bytes, db_page1: bytes) -> bool:
    """Verify an encryption key against page 1 HMAC (SQLCipher 4).

    Args:
        enc_key: raw 32-byte encryption key
        db_page1: first 4096 bytes of the encrypted database

    Returns True if the key's HMAC matches the stored HMAC in page 1.
    """
    salt = db_page1[:SALT_SZ]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)
    hmac_data = db_page1[SALT_SZ: PAGE_SZ - 80 + 16]
    stored_hmac = db_page1[PAGE_SZ - 64: PAGE_SZ]
    hm = hmac_mod.new(mac_key, hmac_data, hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hm.digest() == stored_hmac


def _read_page1(src_path: str) -> bytes:
    """Read the first page of an encrypted database file."""
    with open(src_path, 'rb') as f:
        return f.read(PAGE_SZ)


def _find_key_for_basename(keys: dict, basename: str) -> bytes:
    """Find a decryption key matching a given db basename."""
    for kpath, kval in keys.items():
        if os.path.basename(kpath) == basename:
            return bytes.fromhex(kval)
    return None


def _find_key_by_hmac(keys: dict, src_path: str) -> bytes:
    """Find the correct key for a DB by trying all known keys against page 1 HMAC.

    Reads page 1 of the source DB and verifies each known key's HMAC.
    Returns the first matching key, or None if no key matches.
    """
    try:
        page1 = _read_page1(src_path)
    except OSError:
        return None

    if len(page1) < PAGE_SZ:
        return None

    for kpath, kval in keys.items():
        if len(kval) != 64:
            continue
        try:
            key_bytes = bytes.fromhex(kval)
        except ValueError:
            continue
        if _verify_enc_key(key_bytes, page1):
            return key_bytes
    return None


def _resolve_key(keys: dict, src_path: str) -> bytes:
    """Resolve the correct encryption key for a database file.

    Priority:
      1. Exact basename match (fast path — key was previously matched)
      2. HMAC-based trial of ALL known keys (catches shared keys across shards)
    """
    fname = os.path.basename(src_path)

    # 1) Exact basename match
    key = _find_key_for_basename(keys, fname)
    if key is not None:
        return key

    # 2) HMAC-based trial — try every known key
    return _find_key_by_hmac(keys, src_path)


def _decrypt_one(src: str, dst: str, key: bytes, on_progress, label: str,
                 progress_start: float, progress_end: float) -> bool:
    """Decrypt a single database file. Returns True on success."""
    from engine.decrypt import decrypt_database

    os.makedirs(os.path.dirname(dst), exist_ok=True)
    try:
        success = decrypt_database(src, dst, key,
                                   print_fn=lambda m: on_progress(f"{label}: {m}", progress_start) if on_progress else None)
        return bool(success)
    except Exception:
        return False


def decrypt_for_backup(
    db_storage_path: str,
    output_dir: str,
    keys: dict,
    on_progress: Callable[[str, float], None] = None,
) -> list:
    """Decrypt WeChat databases from db_storage to output_dir.

    Writes decrypted DBs into the same subdirectory structure the chat viewer
    expects: message/*.db, contact/contact.db, hardlink/hardlink.db.

    Args:
        db_storage_path: WeChat db_storage directory
        output_dir: Backup output root
        keys: {db_path_relative: key_hex} mapping
        on_progress: callback(current_db, progress_0_to_1)

    Returns:
        list of decrypted db file paths
    """
    from engine.decrypt import decrypt_database

    msg_src = os.path.join(db_storage_path, 'message')
    msg_out = os.path.join(output_dir, 'message')
    os.makedirs(msg_out, exist_ok=True)

    results = []

    # --- Message & Media databases ---
    if os.path.isdir(msg_src):
        msg_files = sorted(
            [f for f in os.listdir(msg_src) if f.startswith('message_') and f.endswith('.db')]
        )
        media_files = sorted(
            [f for f in os.listdir(msg_src) if f.startswith('media_') and f.endswith('.db')]
        )
        db_files = msg_files + media_files
        total = len(db_files) + 2  # +2 for contact + hardlink
        for i, fname in enumerate(db_files):
            src_path = os.path.join(msg_src, fname)
            dst_path = os.path.join(msg_out, fname)
            key = _resolve_key(keys, src_path)
            if key is None:
                if on_progress:
                    on_progress(f"跳过 {fname} (无密钥)", (i + 1) / total)
                continue

            def _page_progress(cur_pct, detail):
                if on_progress:
                    on_progress(f"解密 {fname} ({detail} 页)", (i + cur_pct / 100.0) / total)

            try:
                success = decrypt_database(src_path, dst_path, key,
                                           print_fn=lambda m, fn=fname: on_progress(f"{fn}: {m}", (i + 0.1) / total) if on_progress else None,
                                           progress_fn=_page_progress)
            except Exception:
                success = False

            if not success:
                if on_progress:
                    on_progress(f"跳过 {fname} (密钥不匹配)", (i + 1) / total)
                continue

            results.append(dst_path)
            if on_progress:
                on_progress(f"已解密: {fname}", (i + 1) / total)
    else:
        total = 2

    # --- Contact database ---
    contact_src = os.path.join(db_storage_path, 'contact', 'contact.db')
    contact_dst = os.path.join(output_dir, 'contact', 'contact.db')
    if os.path.isfile(contact_src):
        ck = _resolve_key(keys, contact_src)
        if ck:
            if on_progress:
                on_progress("解密 contact.db", (total - 1) / total)
            try:
                os.makedirs(os.path.dirname(contact_dst), exist_ok=True)
                ok = decrypt_database(contact_src, contact_dst, ck,
                                      print_fn=lambda m: on_progress(f"contact.db: {m}", (total - 0.5) / total) if on_progress else None)
                if ok:
                    results.append(contact_dst)
            except Exception:
                pass

    # --- Hardlink database ---
    hardlink_src = os.path.join(db_storage_path, 'hardlink', 'hardlink.db')
    hardlink_dst = os.path.join(output_dir, 'hardlink', 'hardlink.db')
    if os.path.isfile(hardlink_src):
        hl_key = _resolve_key(keys, hardlink_src)
        if hl_key:
            if on_progress:
                on_progress("解密 hardlink.db", 0.98)
            try:
                os.makedirs(os.path.dirname(hardlink_dst), exist_ok=True)
                decrypt_database(hardlink_src, hardlink_dst, hl_key,
                                 print_fn=lambda m: on_progress(f"hardlink: {m}", 0.99) if on_progress else None)
                results.append(hardlink_dst)
            except Exception:
                pass

    return results
