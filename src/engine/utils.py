"""
公共工具: 微信路径自动检测、联系人加载、群聊名称解析、消息DB迭代。
"""
import glob as _glob
import os
import re
import shutil
import sqlite3
import hashlib
from collections import defaultdict


def _get_fast_data_roots():
    """Collect candidate data-root directories, skipping slow/network drives.

    Only scans DRIVE_FIXED and DRIVE_REMOVABLE drives; skips DRIVE_REMOTE (network),
    DRIVE_CDROM, DRIVE_RAMDISK, and DRIVE_NO_ROOT_DIR.
    """
    data_roots = []

    # Strategy 1: WeChat config/*.ini files (most reliable)
    appdata = os.environ.get("APPDATA", "")
    config_dir = os.path.join(appdata, "Tencent", "xwechat", "config")
    if os.path.isdir(config_dir):
        for fname in os.listdir(config_dir):
            if not fname.endswith(".ini"):
                continue
            fpath = os.path.join(config_dir, fname)
            try:
                content = None
                for enc in ("utf-8", "gbk"):
                    try:
                        with open(fpath, "r", encoding=enc) as f:
                            content = f.read(1024).strip()
                        break
                    except UnicodeDecodeError:
                        continue
                if content and os.path.isdir(content):
                    data_roots.append(content)
            except OSError:
                continue

    # Strategy 2: Common parent directories
    userprofile = os.environ.get("USERPROFILE", "")
    homedrive = os.environ.get("HOMEDRIVE", "C:")
    common_parents = [
        os.path.join(userprofile, "Documents"),
        homedrive + os.sep,
        "D:\\",
        "C:\\",
        "E:\\",
        "F:\\",
    ]
    for p in common_parents:
        if os.path.isdir(p) and p not in data_roots:
            data_roots.append(p)

    # Strategy 3: All fixed + removable drives (skip network, CD-ROM)
    try:
        import ctypes
        DRIVE_FIXED = 3
        DRIVE_REMOVABLE = 2
        drives_bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if drives_bitmask & (1 << i):
                root = chr(ord('A') + i) + ":\\"
                if root in data_roots:
                    continue
                try:
                    dt = ctypes.windll.kernel32.GetDriveTypeW(root)
                except Exception:
                    dt = 1  # DRIVE_NO_ROOT_DIR
                if dt in (DRIVE_FIXED, DRIVE_REMOVABLE):
                    if os.path.isdir(root):
                        data_roots.append(root)
    except Exception:
        # Fallback: if ctypes fails, at least try common drives
        for root in ("C:\\", "D:\\", "E:\\", "F:\\"):
            if root not in data_roots and os.path.isdir(root):
                data_roots.append(root)

    return data_roots


def _scan_roots_for_wechat(data_roots):
    """Scan data_roots for xwechat_files/*/db_storage.

    Checks if xwechat_files exists before globbing, and returns
    deduplicated list of db_storage paths.
    """
    candidates = []
    seen = set()

    for root in data_roots:
        # Quick pre-check: skip if xwechat_files doesn't exist on this root
        xwechat_dir = os.path.join(root, "xwechat_files")
        if not os.path.isdir(xwechat_dir):
            continue

        pattern = os.path.join(root, "xwechat_files", "*", "db_storage")
        try:
            for match in _glob.glob(pattern):
                norm = os.path.normcase(os.path.normpath(match))
                if norm not in seen and os.path.isdir(match):
                    seen.add(norm)
                    candidates.append(match)
        except OSError:
            continue

    return candidates


def find_wechat_data_dir():
    r"""自动检测微信 db_storage 数据目录。

    检测策略 (按优先级):
      1. 解析 %APPDATA%\Tencent\xwechat\config\*.ini (微信自写配置，最可靠)
      2. 常见数据根目录 + xwechat_files\*\db_storage 定深 glob
      3. 遍历固定/可移动驱动器根目录查找 xwechat_files

    多个账号时优先选 message 目录最近修改过的 (当前活跃账号)。
    Returns: db_storage 目录路径, 或 None
    """
    data_roots = _get_fast_data_roots()
    candidates = _scan_roots_for_wechat(data_roots)

    if not candidates:
        return None

    # ---- 多个账号时选最近活跃的 (message 目录 mtime 最大) ----
    def _activity_score(db_storage_path):
        msg_dir = os.path.join(db_storage_path, "message")
        try:
            return os.path.getmtime(msg_dir) if os.path.isdir(msg_dir) else 0
        except OSError:
            return 0

    candidates.sort(key=_activity_score, reverse=True)
    return candidates[0]


def _get_dir_size_mb(dir_path):
    """Quickly estimate directory size in MB using scandir (breadth-first, one level).
    For db_storage we only need a rough estimate; walking one level is fast and enough.
    """
    try:
        total = 0
        for entry in os.scandir(dir_path):
            try:
                if entry.is_file(follow_symlinks=False):
                    total += entry.stat().st_size
                elif entry.is_dir(follow_symlinks=False):
                    for sub in os.scandir(entry.path):
                        try:
                            if sub.is_file(follow_symlinks=False):
                                total += sub.stat().st_size
                        except OSError:
                            pass
            except OSError:
                pass
        return round(total / (1024 * 1024), 1)
    except OSError:
        return 0


def find_all_wechat_data_dirs():
    """检测所有微信 db_storage 目录，返回列表供用户选择。
    Returns: [{'db_path': str, 'wxid': str, 'mtime': float,
               'db_count': int, 'size_mb': float}, ...] 按活跃度降序
    """
    data_roots = _get_fast_data_roots()
    candidates = _scan_roots_for_wechat(data_roots)

    if not candidates:
        return []

    result = []
    for db_path in candidates:
        parent = os.path.dirname(db_path)
        wxid = os.path.basename(parent)
        msg_dir = os.path.join(db_path, "message")
        try:
            mtime = os.path.getmtime(msg_dir) if os.path.isdir(msg_dir) else 0
        except OSError:
            mtime = 0
        # Count message_N.db files
        try:
            db_count = 0
            if os.path.isdir(msg_dir):
                db_count = sum(1 for f in os.listdir(msg_dir)
                              if f.startswith('message_') and f.endswith('.db'))
        except OSError:
            db_count = 0
        size_mb = _get_dir_size_mb(db_path)
        result.append({
            'db_path': db_path,
            'wxid': wxid,
            'mtime': mtime,
            'db_count': db_count,
            'size_mb': size_mb,
        })

    result.sort(key=lambda x: x['mtime'], reverse=True)
    return result


def is_wechat_running():
    """检查 Weixin.exe 是否在运行。"""
    import subprocess
    try:
        r = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=10
        )
        return "Weixin.exe" in r.stdout
    except (subprocess.SubprocessError, OSError):
        return False


def load_contacts(decrypted_dir):
    """加载联系人映射。
    Returns:
        id_to_name: {contact_id: display_name}
        name_to_id: {username: contact_id}
        usernames: set of all usernames
    """
    id_to_name = {}
    name_to_id = {}
    usernames = set()

    db_path = os.path.join(decrypted_dir, "contact", "contact.db")
    if not os.path.exists(db_path):
        return id_to_name, name_to_id, usernames

    conn = sqlite3.connect(db_path)
    try:
        for r in conn.execute(
            "SELECT id, username, remark, nick_name, alias FROM contact"
        ):
            cid, uname, remark, nick, alias = r
            uname = (uname or "").strip()
            remark_v = (remark or '').strip()
            nick_v = (nick or '').strip()
            alias_v = (alias or '').strip()
            display = remark_v if (remark_v and remark_v != uname) else (nick_v if (nick_v and nick_v != uname) else (alias_v if (alias_v and alias_v != uname) else uname))
            if cid and display:
                id_to_name[cid] = display
            if uname:
                name_to_id[uname] = cid
                usernames.add(uname)
    finally:
        conn.close()
    return id_to_name, name_to_id, usernames


def iter_message_dbs(decrypted_dir):
    """迭代解密后的 message_N.db 文件。"""
    msg_dir = os.path.join(decrypted_dir, "message")
    dbs = []
    if not os.path.isdir(msg_dir):
        return dbs
    for f in os.listdir(msg_dir):
        m = re.match(r'message_(\d+)\.db', f, re.IGNORECASE)
        if m:
            dbs.append((int(m.group(1)), os.path.join(msg_dir, f)))
    return sorted(dbs, key=lambda x: x[0])


def get_msg_table(conn, username):
    """获取指定 username 对应的 Msg_ 表是否存在于此 DB 中。"""
    h = hashlib.md5(username.encode()).hexdigest()
    tname = f"Msg_{h}"
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (tname,)
    ).fetchone()
    return tname if row else None


