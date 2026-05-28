"""Flask application factory for the chat viewer."""
import os
import sys
import threading
import webbrowser
from flask import Flask, render_template, jsonify


def _resolve_path(relative_path: str) -> str:
    if getattr(sys, 'frozen', False):
        return os.path.join(sys._MEIPASS, 'src', 'web', relative_path)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base, relative_path)


def create_app(decrypted_dir: str, wxid: str = None, db_dir: str = None) -> Flask:
    app = Flask(__name__,
        template_folder=_resolve_path('templates'),
        static_folder=_resolve_path('static'),
    )
    from engine.services.media import _detect_wxid
    app.config['DECRYPTED_DIR'] = decrypted_dir
    app.config['WXID'] = wxid or _detect_wxid(decrypted_dir)
    app.config['DB_DIR'] = db_dir
    app.json.ensure_ascii = False

    # Existing API
    try:
        from .routes.api import api_bp
        app.register_blueprint(api_bp, url_prefix='/api')
    except ImportError as e:
        print(f"[WARN] 无法加载 API 蓝图 (routes.api): {e}")

    # Existing reports
    try:
        from .reports import reports_bp
        app.register_blueprint(reports_bp)
    except ImportError as e:
        print(f"[WARN] 无法加载报告蓝图 (reports): {e}")

    # Wrapped annual report
    try:
        from .reports.wrapped import wrapped_bp
        app.register_blueprint(wrapped_bp)
    except ImportError as e:
        print(f"[WARN] 无法加载年度报告蓝图 (reports.wrapped): {e}")

    # New: Backup API (SSE endpoints)
    try:
        from .routes.backup_api import backup_bp
        app.register_blueprint(backup_bp)
    except ImportError as e:
        print(f"[WARN] 无法加载备份蓝图 (routes.backup_api): {e}")

    # New: Export API (SSE endpoints)
    try:
        from .routes.export_api import export_bp
        app.register_blueprint(export_bp)
    except ImportError as e:
        print(f"[WARN] 无法加载导出蓝图 (routes.export_api): {e}")

    # Avatar API
    try:
        from .routes.avatar_api import avatar_bp
        app.register_blueprint(avatar_bp)
    except ImportError as e:
        print(f"[WARN] 无法加载头像蓝图 (routes.avatar_api): {e}")

    # JSON error handlers — prevent Flask HTML pages for API routes
    @app.errorhandler(404)
    def _json_404(e):
        return jsonify({'error': 'not found'}), 404

    @app.errorhandler(500)
    def _json_500(e):
        return jsonify({'error': 'internal server error'}), 500

    # Dashboard (new home page)
    @app.route('/')
    def dashboard():
        return render_template('dashboard.html')

    # Chat viewer
    @app.route('/chat')
    def chat():
        return render_template('index.html')

    # Wizard pages
    @app.route('/backup')
    def backup_page():
        return render_template('backup.html')

    @app.route('/keyscan')
    def keyscan_page():
        return render_template('keyscan.html')

    @app.route('/decrypt')
    def decrypt_page():
        return render_template('decrypt.html')

    # Export pages
    @app.route('/export')
    def export_page():
        return render_template('export.html')

    @app.route('/wordcloud')
    def wordcloud_page():
        return render_template('wordcloud.html')

    @app.route('/report')
    def report_page():
        return render_template('report.html')

    @app.route('/employee')
    def employee_page():
        return render_template('employee.html')

    @app.route('/wrapped')
    def wrapped_page():
        return render_template('wrapped.html')

    # Serve WeChat built-in expression assets (dev mode only — not bundled in PyInstaller)
    _WXEMOJI_DIR = None
    if not getattr(sys, 'frozen', False):
        from pathlib import Path as _Path
        _WXEMOJI_DIR = _Path(__file__).resolve().parents[4] / 'tempWeChatDataAnalysis' / 'frontend' / 'public' / 'wxemoji'

    @app.route('/wxemoji/<path:filename>')
    def wxemoji(filename):
        from flask import send_from_directory, abort as _abort
        if _WXEMOJI_DIR is None or not os.path.isdir(_WXEMOJI_DIR):
            _abort(404)
        if '..' in filename or filename.startswith('/'):
            _abort(404)
        return send_from_directory(str(_WXEMOJI_DIR), filename)

    return app


def run_server(decrypted_dir: str, wxid: str = None, db_dir: str = None,
               host: str = '127.0.0.1', port: int = 5000, open_url: str = None):
    app = create_app(decrypted_dir, wxid=wxid, db_dir=db_dir)
    url = open_url or f'http://{host}:{port}'
    timer = threading.Timer(1.0, lambda: webbrowser.open(url))
    timer.daemon = True
    timer.start()
    app.run(host=host, port=port, debug=False, use_reloader=False)
