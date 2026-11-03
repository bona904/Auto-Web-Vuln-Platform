# app.py
"""
Auto-Web-Vuln-Platform 启动入口。

⚠️ 合规声明：
    本项目仅用于【授权靶场/自有系统】的教学与安全测试。
    请勿对未授权目标发起扫描，否则可能违反《网络安全法》等法律法规。
"""

from flask import Flask, jsonify, request

import config
from routes.templates import templates_bp
from core.engine import run_scan
from core import logger as scan_logger


def create_app():
    app = Flask(__name__)
    app.register_blueprint(templates_bp)

    # ★ 新增：前端实时日志轮询接口
    @app.route("/api/logs", methods=["GET"])
    def api_logs():
        return jsonify({"code": 0, "data": scan_logger.snapshot()})

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        try:
            payload = request.get_json(silent=True) or {}
            target = (payload.get("target") or request.form.get("target") or "").strip()
            username = (payload.get("username") or request.form.get("username") or "").strip()
            password = payload.get("password") or request.form.get("password") or ""

            print(f"[DEBUG] /api/scan 收到: target={target!r} "
                  f"username={username!r} password={'***' if password else ''}\n")

            if not target:
                return jsonify({"code": 1, "msg": "target 不能为空", "data": []})

            results = run_scan(target, username, password)
            return jsonify({"code": 0, "msg": "ok", "data": results})

        except Exception as e:
            print(f"[ERROR] /api/scan 异常: {e}")
            return jsonify({"code": 2, "msg": f"扫描异常: {e}", "data": []}), 200

    return app


if __name__ == "__main__":
    print("=== 🚀 Web 控制台已启动 ===")
    print("请在浏览器中访问: http://127.0.0.1:5000\n")

    app = create_app()
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        threaded=True,
    )