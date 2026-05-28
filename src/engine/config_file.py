"""Persistent config file for tracking backup output path across sessions."""
import json
import os

CONFIG_FILENAME = ".wechat_exp_config.json"


def _config_path() -> str:
    """Config file lives at project root (dev) or next to the exe (frozen)."""
    import sys as _sys
    if getattr(_sys, 'frozen', False):
        base = os.path.dirname(_sys.executable)
    else:
        # config_file.py → engine/ → src/ → project_root/
        base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, CONFIG_FILENAME)


def get_backup_data_dir() -> str | None:
    """Return the output directory from the last successful backup, or None."""
    path = _config_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        raw = cfg.get("last_backup_data_dir", "")
        if raw and os.path.isdir(raw):
            return raw
    except (ValueError, OSError):
        pass
    return None


def set_backup_data_dir(data_dir: str, wxid: str | None = None) -> None:
    """Persist the backup data directory for other features to find."""
    path = _config_path()
    cfg = {}
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
    except (ValueError, OSError):
        pass
    cfg["last_backup_data_dir"] = str(data_dir)
    if wxid:
        cfg["last_backup_wxid"] = str(wxid)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def get_backup_wxid() -> str | None:
    """Return the wxid from the last successful backup, or None."""
    path = _config_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        wxid = cfg.get("last_backup_wxid", "")
        if wxid:
            return str(wxid)
    except (ValueError, OSError):
        pass
    return None


def get_latest_backup_dir(base_dir: str) -> str | None:
    """Scan a base backup directory and return the latest backup dir with message/ subdir."""
    if not os.path.isdir(base_dir):
        return None
    candidates = []
    for name in os.listdir(base_dir):
        full = os.path.join(base_dir, name)
        if not os.path.isdir(full):
            continue
        if os.path.isdir(os.path.join(full, "message")):
            candidates.append((name, full))
    if not candidates:
        return None
    candidates.sort(key=lambda x: os.path.getmtime(x[1]), reverse=True)
    return candidates[0][1]


def _get_all_keys_path() -> str:
    """Legacy all_keys.json path — used for one-time migration."""
    import sys as _sys
    if getattr(_sys, 'frozen', False):
        base = os.path.dirname(_sys.executable)
        return os.path.join(base, 'output', 'all_keys.json')
    else:
        # config_file.py → engine/ → src/ → project_root/
        base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return os.path.join(base, 'output', 'all_keys.json')


def _migrate_all_keys(cfg: dict, config_path: str) -> dict:
    """One-time: load keys from legacy output/all_keys.json and persist them in config."""
    legacy_path = _get_all_keys_path()
    if not os.path.isfile(legacy_path):
        return {}
    try:
        with open(legacy_path, 'r', encoding='utf-8') as f:
            legacy = json.load(f)
    except (ValueError, OSError):
        return {}

    keys = {}
    db_dir = ''
    for k, v in legacy.items():
        if k.startswith('_'):
            if k == '_db_dir':
                db_dir = str(v)
            continue
        if isinstance(v, dict):
            hex_key = v.get('enc_key', '')
            if hex_key and len(hex_key) == 64:
                keys[k] = hex_key
        elif isinstance(v, str) and len(v) == 64:
            keys[k] = v

    if not keys:
        return {}

    cfg['db_keys'] = keys
    if db_dir:
        cfg['_db_dir'] = db_dir
    try:
        tmp = config_path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.replace(tmp, config_path)
    except OSError:
        pass
    return keys


def get_db_keys() -> dict:
    """Return database encryption keys from config.

    Returns dict mapping db_rel_path -> 64-char hex enc_key.
    On first call, migrates keys from legacy output/all_keys.json.
    """
    path = _config_path()
    if not os.path.isfile(path):
        # Try migration before creating empty config
        return _migrate_all_keys({}, path)

    try:
        with open(path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except (ValueError, OSError):
        return {}

    keys = cfg.get('db_keys', {})
    if not keys:
        keys = _migrate_all_keys(cfg, path)
    return keys


def set_db_keys(keys: dict, db_dir: str = '') -> None:
    """Persist database encryption keys in the unified config file.

    Args:
        keys: dict mapping db_rel_path -> 64-char hex enc_key
        db_dir: absolute path to WeChat db_storage directory
    """
    path = _config_path()
    cfg = {}
    try:
        if os.path.isfile(path):
            with open(path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
    except (ValueError, OSError):
        pass
    cfg['db_keys'] = {str(k): str(v) for k, v in keys.items()}
    if db_dir:
        cfg['_db_dir'] = str(db_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def get_db_dir() -> str | None:
    """Return the _db_dir (WeChat db_storage path) stored in config, or None."""
    path = _config_path()
    if not os.path.isfile(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        return cfg.get('_db_dir', '')
    except (ValueError, OSError):
        return None
