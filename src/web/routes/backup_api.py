"""Backup API — SSE-streaming endpoints for backup, key scan, and decrypt."""
import os
import sys
import threading
from flask import Blueprint, request, current_app

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

if getattr(sys, 'frozen', False):
    _DATA_ROOT = os.path.dirname(sys.executable)
else:
    _DATA_ROOT = os.path.normpath(os.path.join(_BASE, '..'))

from web.sse import create_sse_progress, sse_response

backup_bp = Blueprint('backup_api', __name__, url_prefix='/api/backup')
_stdout_lock = threading.Lock()



def _safe_path(user_input: str) -> str:
    """Normalize a user-supplied path to resolve .. traversal."""
    return os.path.realpath(os.path.abspath(user_input))


@backup_bp.route('/run', methods=['POST'])
def backup_run():
    """POST /api/backup/run — Full backup pipeline."""
    data = request.get_json(silent=True) or {}
    db_dir = data.get('db_dir') or current_app.config.get('DB_DIR', '')
    if data.get('output_dir'):
        output_dir = _safe_path(data['output_dir'])
    else:
        import datetime as _dt
        output_dir = os.path.join(_DATA_ROOT, 'backup', _dt.datetime.now().strftime('%Y-%m-%d'))
    key_file = _safe_path(data['key_file']) if data.get('key_file') else None
    start_date = data.get('start_date') or None
    end_date = data.get('end_date') or None
    days = data.get('days')
    if not start_date and not end_date and days is not None:
        if int(days) == 0:
            start_date = None
            end_date = None
        else:
            import datetime as _dt
            end_date = _dt.datetime.now().strftime('%Y-%m-%d')
            start_date = (_dt.datetime.now() - _dt.timedelta(days=int(days))).strftime('%Y-%m-%d')

    # Auto-detect WeChat data directory if not provided or invalid
    if not db_dir or not os.path.isdir(db_dir):
        try:
            from engine.utils import find_all_wechat_data_dirs
            dirs = find_all_wechat_data_dirs()
            if len(dirs) == 1:
                db_dir = dirs[0]['db_path']
            elif len(dirs) > 1:
                push, gen = create_sse_progress()
                push.select([{
                    'db_path': d['db_path'],
                    'wxid': d['wxid'],
                    'db_count': d.get('db_count', 0),
                    'size_mb': d.get('size_mb', 0),
                    'mtime': d.get('mtime', 0),
                } for d in dirs])
                return sse_response(gen)
        except Exception:
            pass
    if not db_dir or not os.path.isdir(db_dir):
        push, gen = create_sse_progress()
        push.error("未找到微信数据目录 — 请确认微信已安装并至少登录过一次，或手动填写 db_storage 路径")
        return sse_response(gen)

    push, gen = create_sse_progress()
    flask_app = current_app._get_current_object()

    def _run():
        from backup.pipeline import run_backup
        from engine.config_file import set_backup_data_dir

        def _progress(stage, detail, progress):
            push(stage, detail, progress)

        try:
            result = run_backup(db_dir, output_dir, key_file,
                                start_date=start_date, end_date=end_date,
                                on_progress=_progress)
            if result.get('success'):
                if os.path.isdir(os.path.join(output_dir, 'message')):
                    set_backup_data_dir(output_dir, wxid=result.get('wxid', ''))
                    with flask_app.app_context():
                        flask_app.config['DECRYPTED_DIR'] = output_dir
            push.done(result)
        except Exception as e:
            push.error(str(e))

    threading.Thread(target=_run, daemon=True).start()
    return sse_response(gen)


@backup_bp.route('/scan', methods=['POST'])
def backup_scan():
    """POST /api/backup/scan — Detect WeChat data directories."""
    push, gen = create_sse_progress()

    def _run():
        try:
            from engine.utils import find_all_wechat_data_dirs
            push('scan', '正在检测微信数据目录...', 0.3)
            dirs = find_all_wechat_data_dirs()
            push('scan', f'找到 {len(dirs)} 个账号', 1.0)
            push.done({
                'accounts': [
                    {
                        'db_path': d['db_path'],
                        'wxid': d['wxid'],
                        'mtime': d['mtime'],
                        'db_count': d.get('db_count', 0),
                        'size_mb': d.get('size_mb', 0),
                    }
                    for d in dirs
                ]
            })
        except Exception as e:
            push.error(str(e))

    threading.Thread(target=_run, daemon=True).start()
    return sse_response(gen)


@backup_bp.route('/keyscan', methods=['POST'])
def backup_keyscan():
    """POST /api/backup/keyscan — Extract decryption keys."""
    data = request.get_json(silent=True) or {}
    db_dir = data.get('db_dir') or current_app.config.get('DB_DIR')
    if not db_dir:
        try:
            from engine.utils import find_all_wechat_data_dirs
            dirs = find_all_wechat_data_dirs()
            if dirs:
                db_dir = dirs[0]['db_path']
        except Exception:
            pass
    if not db_dir:
        push, gen = create_sse_progress()
        push.error("未找到微信数据目录 — 请指定 --db-dir 启动服务")
        return sse_response(gen)

    if not os.path.isdir(db_dir):
        push, gen = create_sse_progress()
        push.error(f"微信数据目录不存在或不可访问: {db_dir}")
        return sse_response(gen)

    push, gen = create_sse_progress()

    def _run():
        try:
            from key_scan import run_key_scan
            push('scan', '正在扫描微信进程内存...', 0.2)
            import io
            with _stdout_lock:
                import sys as _sys
                old_stdout = _sys.stdout
                _sys.stdout = io.StringIO()
                try:
                    run_key_scan(db_dir, None)
                    output = _sys.stdout.getvalue()
                finally:
                    _sys.stdout = old_stdout

            result = {'output': output}
            from engine.config_file import get_db_keys
            keys = get_db_keys()
            if keys:
                result['keys'] = len(keys)
            push.done(result)
        except Exception as e:
            push.error(str(e))

    threading.Thread(target=_run, daemon=True).start()
    return sse_response(gen)


@backup_bp.route('/decrypt', methods=['POST'])
def backup_decrypt():
    """POST /api/backup/decrypt — Decrypt databases only."""
    data = request.get_json(silent=True) or {}
    db_dir = data.get('db_dir') or current_app.config.get('DB_DIR')
    if not db_dir:
        try:
            from engine.utils import find_all_wechat_data_dirs
            dirs = find_all_wechat_data_dirs()
            if dirs:
                db_dir = dirs[0]['db_path']
        except Exception:
            pass
    if not db_dir:
        push, gen = create_sse_progress()
        push.error("未找到微信数据目录 — 请指定 --db-dir 启动服务")
        return sse_response(gen)

    if not os.path.isdir(db_dir):
        push, gen = create_sse_progress()
        push.error(f"微信数据目录不存在或不可访问: {db_dir}")
        return sse_response(gen)

    output_dir = _safe_path(data['output_dir']) if data.get('output_dir') else os.path.join(_DATA_ROOT, 'output', 'decrypted')
    key_file = _safe_path(data['key_file']) if data.get('key_file') else None

    push, gen = create_sse_progress()
    flask_app = current_app._get_current_object()

    def _run():
        try:
            from backup.decryptor import load_keys, decrypt_for_backup
            from engine.config_file import set_backup_data_dir
            push('decrypt', '加载密钥...', 0.05)
            keys = load_keys(key_file)
            if not keys:
                push.error("未找到数据库密钥 — 请先执行密钥提取")
                return

            def _on_progress(detail, progress):
                push('decrypt', detail, progress)

            results = decrypt_for_backup(db_dir, output_dir, keys, on_progress=_on_progress)
            if results and os.path.isdir(os.path.join(output_dir, 'message')):
                set_backup_data_dir(output_dir)
                with flask_app.app_context():
                    flask_app.config['DECRYPTED_DIR'] = output_dir
            push.done({'decrypted': len(results), 'files': results})
        except Exception as e:
            push.error(str(e))

    threading.Thread(target=_run, daemon=True).start()
    return sse_response(gen)
