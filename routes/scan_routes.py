# routes/scan_routes.py
"""路由接口层：首页 + /api/scan。"""

from flask import Blueprint, request, jsonify, render_template_string

from core.engine import run_scan
from routes.templates import HTML_TEMPLATE

scan_bp = Blueprint("scan", __name__)


@scan_bp.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@scan_bp.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not target:
        return jsonify({"error": "target 不能为空"}), 400

    print(f"[DEBUG] /api/scan 收到: target={target!r}, "
          f"username={username!r}, password={'***' if password else ''!r}")

    try:
        results = run_scan(target, username, password)
    except Exception as e:
        return jsonify({"error": f"扫描失败: {e}"}), 500

    return jsonify(results or [])