# routes/templates.py
"""
Flask 页面路由与模板渲染（异步扫描 + 实时日志 + 证据弹窗 + HTML 报告导出）。

⚠️ 合规声明：
    本项目仅用于【授权靶场/自有系统】的教学与安全测试。

职责：
    /                  : 首页（表单 + 结果区 + 日志面板 + 证据弹窗）
    /scan              : 同步扫描（旧接口，保留兼容）
    /api/scan_async    : 异步扫描（前端调用，立即返回）
    /api/scan_status   : 扫描状态轮询
    /download          : HTML 报告导出（真实实现）

关键行为：
    - 点击"开始扫描" -> 自动打开日志面板 -> 后台线程跑 -> 结果自动渲染
    - 扫描进行中禁止重复发起
    - 扫描完成自动停轮询，显示耗时
"""

import time
import threading
import html as html_lib

from flask import (
    Blueprint, render_template_string, request, jsonify, Response,
)

from core.engine import run_scan

templates_bp = Blueprint("templates_bp", __name__)

# =====================================================================
# 全局扫描状态（单进程 Flask 够用；不要用多 worker 部署）
# =====================================================================
_scan_state = {
    "running": False,
    "results": [],
    "error": "",
    "started_at": 0.0,
    "finished_at": 0.0,
    "target": "",
}
_scan_lock = threading.Lock()


HOME_HTML = r"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Auto-Web-Vuln-Platform</title>
<style>
  :root{
    --bg:#0f1115; --panel:#171a21; --panel-2:#1e222b; --border:#2a2f3a;
    --text:#e6e8ee; --muted:#9aa3b2; --accent:#4f8cff;
    --high:#ff5c5c; --mid:#ffb84d; --low:#5ad469;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font-family:-apple-system,"Segoe UI","Microsoft YaHei",Arial,sans-serif;
    min-height:100vh}
  .wrap{max-width:1280px;margin:0 auto;padding:28px 20px 120px}

  .header{display:flex;align-items:center;gap:12px;margin-bottom:24px}
  .logo{width:38px;height:38px;border-radius:10px;
    background:linear-gradient(135deg,var(--accent),#8b5cf6);
    display:flex;align-items:center;justify-content:center;
    font-weight:800;color:#fff;font-size:18px;
    box-shadow:0 4px 14px rgba(79,140,255,.4)}
  .header h1{font-size:20px;margin:0;font-weight:700;letter-spacing:.3px}
  .header .sub{color:var(--muted);font-size:12px;margin-top:2px}

  .card{background:var(--panel);border:1px solid var(--border);
    border-radius:14px;padding:20px;box-shadow:0 6px 24px rgba(0,0,0,.25)}
  .form-grid{display:grid;grid-template-columns:2fr 1fr 1fr auto;
    gap:12px;align-items:end}
  .field label{display:block;font-size:12px;color:var(--muted);margin-bottom:6px}
  .field input{width:100%;padding:10px 12px;border-radius:9px;
    border:1px solid var(--border);background:var(--panel-2);
    color:var(--text);outline:none;transition:border-color .15s,box-shadow .15s}
  .field input:focus{border-color:var(--accent);
    box-shadow:0 0 0 3px rgba(79,140,255,.18)}

  .btn{padding:10px 20px;border-radius:9px;border:none;
    font-weight:600;cursor:pointer;font-size:14px;transition:filter .15s}
  .btn:disabled{opacity:.6;cursor:not-allowed}
  .btn-primary{background:linear-gradient(135deg,var(--accent),#6b5cff);
    color:#fff;box-shadow:0 4px 14px rgba(79,140,255,.35)}
  .btn-primary:hover:not(:disabled){filter:brightness(1.08)}
  .btn-ghost{background:transparent;color:var(--text);border:1px solid var(--border)}
  .btn-ghost:hover{border-color:var(--accent);color:var(--accent)}

  .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}
  .stat{background:var(--panel);border:1px solid var(--border);
    border-radius:12px;padding:16px 18px}
  .stat .label{font-size:12px;color:var(--muted);margin-bottom:6px}
  .stat .value{font-size:28px;font-weight:800}
  .stat.high .value{color:var(--high)}
  .stat.mid .value{color:var(--mid)}
  .stat.low .value{color:var(--low)}
  .stat.total .value{color:var(--accent)}

  .table-wrap{background:var(--panel);border:1px solid var(--border);
    border-radius:14px;overflow:hidden}
  table{width:100%;border-collapse:collapse}
  thead th{text-align:left;font-size:12px;color:var(--muted);font-weight:600;
    padding:14px 16px;background:var(--panel-2);
    border-bottom:1px solid var(--border);letter-spacing:.3px}
  tbody td{padding:13px 16px;border-bottom:1px solid var(--border);
    font-size:13px;vertical-align:top;word-break:break-all}
  tbody tr:hover{background:rgba(79,140,255,.06)}
  tbody tr:last-child td{border-bottom:none}

  .badge{display:inline-block;padding:3px 10px;border-radius:20px;
    font-size:11px;font-weight:700;letter-spacing:.3px}
  .badge.risk-高{background:rgba(255,92,92,.16);color:var(--high)}
  .badge.risk-中{background:rgba(255,184,77,.16);color:var(--mid)}
  .badge.risk-低{background:rgba(90,212,105,.16);color:var(--low)}
  .badge.status-确认{background:rgba(255,92,92,.16);color:var(--high)}
  .badge.status-疑似{background:rgba(255,184,77,.16);color:var(--mid)}

  .type{font-weight:600;color:var(--text)}
  .muted{color:var(--muted)}

  .empty{text-align:center;padding:60px 20px;color:var(--muted)}
  .empty .icon{font-size:40px;margin-bottom:12px}

  .toolbar{display:flex;justify-content:space-between;align-items:center;
    margin-bottom:14px}
  .toolbar h2{margin:0;font-size:16px}

  .error-bar{margin-top:14px;background:rgba(255,92,92,.12);
    border:1px solid rgba(255,92,92,.4);color:#ff8080;
    border-radius:10px;padding:12px 16px;font-size:13px}

  .scan-status{margin-top:12px;font-size:13px;color:var(--muted)}
  .scan-status.running{color:var(--mid)}
  .scan-status.done{color:var(--low)}
  .scan-status.fail{color:var(--high)}

  .evbtn{padding:4px 10px;font-size:12px;border-radius:6px;
    border:1px solid var(--border);background:transparent;
    color:var(--text);cursor:pointer}
  .evbtn:hover{border-color:var(--accent);color:var(--accent)}

  #log-panel{position:fixed;left:0;right:0;bottom:0;max-height:320px;
    overflow:auto;background:#0b0d11;border-top:1px solid var(--border);
    font-family:Consolas,"Courier New",monospace;font-size:12px;
    padding:8px 14px;color:#cfd6e4;z-index:999;display:none}
  #log-panel .log-head{position:sticky;top:0;background:#0b0d11;
    padding:4px 0 8px;display:flex;justify-content:space-between;
    border-bottom:1px solid var(--border)}
  #log-panel .log-head strong{color:var(--accent)}
  #log-panel .log-head span{cursor:pointer;color:var(--muted)}
  #log-panel .log-head span:hover{color:var(--high)}
  #log-lines > div{line-height:1.6}

  #log-btn{position:fixed;right:20px;bottom:20px;z-index:1000;
    padding:10px 16px;border-radius:22px;
    background:linear-gradient(135deg,var(--accent),#6b5cff);
    color:#fff;border:none;cursor:pointer;font-weight:600;
    box-shadow:0 4px 14px rgba(79,140,255,.4)}

  #ev-modal{position:fixed;top:6%;left:8%;width:84%;max-height:86%;
    overflow:auto;background:var(--panel);color:var(--text);
    border:1px solid var(--border);border-radius:14px;padding:20px;
    z-index:2000;box-shadow:0 10px 40px rgba(0,0,0,.6);display:none}
  #ev-modal h3{margin:12px 0 6px;font-size:14px;color:var(--accent)}
  #ev-modal pre{background:#0b0d11;border:1px solid var(--border);
    border-radius:8px;padding:12px;overflow:auto;font-size:12px;
    max-height:350px;white-space:pre-wrap;word-break:break-all}
  #ev-close{float:right;padding:6px 14px;border-radius:8px;
    background:transparent;border:1px solid var(--border);
    color:var(--text);cursor:pointer}
  #ev-close:hover{border-color:var(--high);color:var(--high)}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="logo">A</div>
    <div>
      <h1>Auto-Web-Vuln-Platform</h1>
      <div class="sub">Web 漏洞扫描平台 · 仅限授权靶场学习使用</div>
    </div>
  </div>

  <div class="card">
    <div class="form-grid">
      <div class="field">
        <label>目标 URL</label>
        <input type="text" id="target" placeholder="http://127.0.0.1/dvwa/"
               value="{{ target or '' }}" autocomplete="off">
      </div>
      <div class="field">
        <label>用户名（可选）</label>
        <input type="text" id="username" value="{{ username or '' }}" autocomplete="off">
      </div>
      <div class="field">
        <label>密码（可选）</label>
        <input type="password" id="password" value="{{ password or '' }}" autocomplete="off">
      </div>
      <div>
        <button type="button" id="btn-scan" class="btn btn-primary"
                onclick="startScan()">开始扫描</button>
      </div>
    </div>
    <div id="scan-status" class="scan-status"></div>
  </div>

  {% if error_msg %}
  <div class="error-bar">⚠️ {{ error_msg }}</div>
  {% endif %}

  <div id="result-wrap">
  {% if results is defined and results %}
    {% set high_n = results|selectattr('风险等级','equalto','高')|list|length %}
    {% set mid_n  = results|selectattr('风险等级','equalto','中')|list|length %}
    {% set low_n  = results|selectattr('风险等级','equalto','低')|list|length %}
    <div class="stats">
      <div class="stat total"><div class="label">漏洞总数</div><div class="value">{{ results|length }}</div></div>
      <div class="stat high"><div class="label">高危</div><div class="value">{{ high_n }}</div></div>
      <div class="stat mid"><div class="label">中危</div><div class="value">{{ mid_n }}</div></div>
      <div class="stat low"><div class="label">低危</div><div class="value">{{ low_n }}</div></div>
    </div>
    <div class="toolbar">
      <h2>扫描结果</h2>
      <button type="button" class="btn btn-ghost" onclick="downloadReport()">下载 HTML 报告</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th style="width:15%">漏洞类型</th>
          <th style="width:7%">风险等级</th>
          <th style="width:7%">验证状态</th>
          <th style="width:7%">参数</th>
          <th style="width:6%">置信度</th>
          <th style="width:22%">URL</th>
          <th style="width:16%">Payload</th>
          <th style="width:14%">证据</th>
          <th style="width:8%">操作</th>
        </tr></thead>
        <tbody>
        {% for f in results %}
          <tr>
            <td><span class="type">{{ f['类型'] }}</span></td>
            <td><span class="badge risk-{{ f['风险等级'] }}">{{ f['风险等级'] }}</span></td>
            <td><span class="badge status-{{ f['验证状态'] }}">{{ f['验证状态'] }}</span></td>
            <td>{{ f['参数'] }}</td>
            <td>{{ f['置信度'] }}</td>
            <td class="muted">{{ f['URL'] }}</td>
            <td class="muted">{{ f['Payload'] }}</td>
            <td class="muted">{{ f['证据'] }}</td>
            <td>
              <button class="evbtn"
                data-req="{{ f.get('请求快照','')|e }}"
                data-resp="{{ f.get('响应片段','')|e }}"
                onclick="showEvidence(this)">查看证据</button>
            </td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  {% endif %}
  </div>
</div>

<div id="log-panel">
  <div class="log-head">
    <strong>📋 实时日志</strong>
    <span onclick="closeLog()">关闭 ✕</span>
  </div>
  <div id="log-lines"></div>
</div>

<button id="log-btn" onclick="startLog()">📋 实时日志</button>

<div id="ev-modal">
  <button id="ev-close" onclick="closeEvidence()">关闭 ✕</button>
  <h3>请求快照</h3>
  <pre id="ev-req">(无)</pre>
  <h3>响应片段</h3>
  <pre id="ev-resp">(无)</pre>
</div>

<script>
function escapeHtml(s){
  return String(s == null ? "" : s).replace(/[&<>"']/g, function(c){
    return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];
  });
}

// ---------------- 实时日志 ----------------
let _logTimer = null;
function startLog(){
  document.getElementById("log-panel").style.display = "block";
  if (_logTimer) return;
  _logTimer = setInterval(pollLogs, 1000);
  pollLogs();
}
function closeLog(){
  document.getElementById("log-panel").style.display = "none";
  if (_logTimer){ clearInterval(_logTimer); _logTimer = null; }
}
async function pollLogs(){
  try{
    const r = await fetch("/api/logs");
    const j = await r.json();
    const logs = (j && j.data) || [];
    const colorMap = {DEBUG:"#7a8599",INFO:"#5ad469",WARN:"#ffb84d",ERROR:"#ff5c5c"};
    const html = logs.map(function(l){
      const c = colorMap[l.level] || "#cfd6e4";
      return "<div>" +
        '<span style="color:#6b7280">[' + escapeHtml(l.ts) + "]</span> " +
        '<span style="color:' + c + ';font-weight:700">[' + escapeHtml(l.level) + "]</span> " +
        '<span style="color:#4f8cff">[' + escapeHtml(l.tag) + "]</span> " +
        escapeHtml(l.msg) + "</div>";
    }).join("");
    const el = document.getElementById("log-lines");
    el.innerHTML = html || '<div style="color:#6b7280">（暂无日志）</div>';
    const panel = document.getElementById("log-panel");
    panel.scrollTop = panel.scrollHeight;
  }catch(e){}
}

// ---------------- 证据弹窗 ----------------
function showEvidence(btn){
  document.getElementById("ev-req").textContent = btn.getAttribute("data-req") || "(无)";
  document.getElementById("ev-resp").textContent = btn.getAttribute("data-resp") || "(无)";
  document.getElementById("ev-modal").style.display = "block";
}
function showEvidenceFromData(idx){
  const r = (window._lastResults || [])[idx];
  if (!r) return;
  document.getElementById("ev-req").textContent = r["请求快照"] || "(无)";
  document.getElementById("ev-resp").textContent = r["响应片段"] || "(无)";
  document.getElementById("ev-modal").style.display = "block";
}
function closeEvidence(){
  document.getElementById("ev-modal").style.display = "none";
}

// ---------------- 扫描控制 ----------------
let _scanTimer = null;
function setScanStatus(text, cls){
  const el = document.getElementById("scan-status");
  el.textContent = text;
  el.className = "scan-status" + (cls ? " " + cls : "");
}
async function startScan(){
  const target = document.getElementById("target").value.trim();
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  if (!target){ setScanStatus("⚠️ 请填写目标 URL", "fail"); return; }

  document.getElementById("log-lines").innerHTML = "";
  startLog();

  const btn = document.getElementById("btn-scan");
  btn.disabled = true; btn.textContent = "扫描中...";
  setScanStatus("⏳ 扫描进行中，日志实时滚动...", "running");
  document.getElementById("result-wrap").innerHTML = "";

  try{
    const r = await fetch("/api/scan_async", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target, username, password}),
    });
    const j = await r.json();
    if (j.code !== 0){
      setScanStatus("⚠️ " + (j.msg || "启动失败"), "fail");
      _resetScanUI(); return;
    }
  }catch(e){
    setScanStatus("⚠️ 请求失败: " + e, "fail"); _resetScanUI(); return;
  }
  if (_scanTimer) clearInterval(_scanTimer);
  _scanTimer = setInterval(pollScanStatus, 1000);
}
async function pollScanStatus(){
  try{
    const r = await fetch("/api/scan_status");
    const j = await r.json();
    const d = j.data || {};
    if (d.running) return;

    clearInterval(_scanTimer); _scanTimer = null;
    _resetScanUI();

    if (d.error){
      setScanStatus("❌ 扫描异常: " + d.error, "fail");
      setTimeout(closeLog, 2000);   // ★ 新增：失败 2 秒后自动关面板
      return;
    }

    const results = d.results || [];
    const cost = (d.finished_at && d.started_at)
      ? (d.finished_at - d.started_at).toFixed(1) : "?";
    setScanStatus("✅ 扫描完成，共 " + results.length + " 条，耗时 " + cost + " 秒", "done");
    renderResults(results);
    setTimeout(closeLog, 3000);      // ★ 新增：成功 3 秒后自动关面板
  }catch(e){}
}
function _resetScanUI(){
  const btn = document.getElementById("btn-scan");
  btn.disabled = false; btn.textContent = "开始扫描";
}

// ---------------- 结果渲染 ----------------
function renderResults(results){
  window._lastResults = results || [];
  const wrap = document.getElementById("result-wrap");
  if (!results || results.length === 0){
    wrap.innerHTML =
      '<div class="card empty"><div class="icon">🛡️</div><div>未发现漏洞</div>' +
      '<div style="margin-top:8px;font-size:12px" class="muted">' +
      '可尝试确认 DVWA Security 是否为 Low 级别</div></div>';
    return;
  }
  let high = 0, mid = 0, low = 0;
  results.forEach(function(r){
    const lvl = r["风险等级"];
    if (lvl === "高") high++; else if (lvl === "中") mid++; else if (lvl === "低") low++;
  });
  let html = '';
  html += '<div class="stats">' +
    '<div class="stat total"><div class="label">漏洞总数</div><div class="value">' + results.length + '</div></div>' +
    '<div class="stat high"><div class="label">高危</div><div class="value">' + high + '</div></div>' +
    '<div class="stat mid"><div class="label">中危</div><div class="value">' + mid + '</div></div>' +
    '<div class="stat low"><div class="label">低危</div><div class="value">' + low + '</div></div>' +
    '</div>';
  html += '<div class="toolbar"><h2>扫描结果</h2>' +
    '<button type="button" class="btn btn-ghost" onclick="downloadReport()">下载 HTML 报告</button></div>';
  html += '<div class="table-wrap"><table><thead><tr>' +
    '<th style="width:15%">漏洞类型</th><th style="width:7%">风险等级</th>' +
    '<th style="width:7%">验证状态</th><th style="width:7%">参数</th>' +
    '<th style="width:6%">置信度</th><th style="width:22%">URL</th>' +
    '<th style="width:16%">Payload</th><th style="width:14%">证据</th>' +
    '<th style="width:8%">操作</th></tr></thead><tbody>';
  results.forEach(function(f, i){
    html += '<tr>' +
      '<td><span class="type">' + escapeHtml(f["类型"]) + '</span></td>' +
      '<td><span class="badge risk-' + escapeHtml(f["风险等级"]) + '">' + escapeHtml(f["风险等级"]) + '</span></td>' +
      '<td><span class="badge status-' + escapeHtml(f["验证状态"]) + '">' + escapeHtml(f["验证状态"]) + '</span></td>' +
      '<td>' + escapeHtml(f["参数"]) + '</td>' +
      '<td>' + (f["置信度"] == null ? "" : f["置信度"]) + '</td>' +
      '<td class="muted">' + escapeHtml(f["URL"]) + '</td>' +
      '<td class="muted">' + escapeHtml(f["Payload"]) + '</td>' +
      '<td class="muted">' + escapeHtml(f["证据"]) + '</td>' +
      '<td><button class="evbtn" onclick="showEvidenceFromData(' + i + ')">查看证据</button></td>' +
      '</tr>';
  });
  html += '</tbody></table></div>';
  wrap.innerHTML = html;
}

// ---------------- 报告下载 ----------------
function downloadReport(){
  const target = document.getElementById("target").value.trim();
  window.open("/download?target=" + encodeURIComponent(target || "unknown"), "_blank");
}
</script>
</body>
</html>
"""


# =====================================================================
# 路由
# =====================================================================
@templates_bp.route("/", methods=["GET"])
def home():
    return render_template_string(HOME_HTML, error_msg="")


@templates_bp.route("/scan", methods=["POST"])
def scan():
    """同步扫描（旧接口，保留兼容）。"""
    target = (request.form.get("target") or "").strip()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    print(f"\n[DEBUG] /scan 收到表单: {dict(request.form)}")
    print(f"[DEBUG] target={target!r} username={username!r}")

    results = []
    error_msg = ""
    if not target:
        error_msg = "目标 URL 不能为空，请输入完整 http:// 或 https:// 地址"
        print(f"[DEBUG] {error_msg}\n")
    else:
        try:
            results = run_scan(target, username, password)
            print(f"[DEBUG] run_scan 返回 {len(results)} 条\n")
        except Exception as e:
            import traceback
            traceback.print_exc()
            error_msg = f"扫描异常: {e}"
            print(f"[DEBUG] run_scan 异常: {e}\n")

    return render_template_string(
        HOME_HTML, target=target, username=username, password=password,
        results=results, error_msg=error_msg,
    )


@templates_bp.route("/api/scan_async", methods=["POST"])
def api_scan_async():
    """异步扫描：立即返回，扫描在后台线程跑。"""
    global _scan_state

    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not target:
        return jsonify({"code": 1, "msg": "target 不能为空"})

    with _scan_lock:
        if _scan_state["running"]:
            return jsonify({"code": 2, "msg": "已有扫描进行中，请等待完成"})
        _scan_state = {
            "running": True,
            "results": [],
            "error": "",
            "started_at": time.time(),
            "finished_at": 0.0,
            "target": target,
        }

    def _worker():
        global _scan_state
        try:
            res = run_scan(target, username, password)
            with _scan_lock:
                _scan_state["results"] = res or []
                _scan_state["running"] = False
                _scan_state["finished_at"] = time.time()
        except Exception as e:
            import traceback
            traceback.print_exc()
            with _scan_lock:
                _scan_state["error"] = str(e)
                _scan_state["running"] = False
                _scan_state["finished_at"] = time.time()

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"code": 0, "msg": "started"})


@templates_bp.route("/api/scan_status", methods=["GET"])
def api_scan_status():
    """扫描状态轮询。"""
    with _scan_lock:
        return jsonify({
            "code": 0,
            "data": {
                "running": _scan_state["running"],
                "results": _scan_state["results"],
                "error": _scan_state["error"],
                "started_at": _scan_state["started_at"],
                "finished_at": _scan_state["finished_at"],
                "target": _scan_state["target"],
            },
        })


@templates_bp.route("/download", methods=["GET"])
def download_report():
    """HTML 报告导出（真实实现）。"""
    with _scan_lock:
        results = list(_scan_state.get("results") or [])
        state_target = _scan_state.get("target") or ""
    target = request.args.get("target") or state_target or "unknown"

    rows_html = ""
    for f in results:
        lvl = html_lib.escape(str(f.get('风险等级', '')))
        lvl_cls = ("high" if lvl == "高" else "mid" if lvl == "中" else "low")
        rows_html += (
            "<tr>"
            f"<td>{html_lib.escape(str(f.get('类型','')))}</td>"
            f"<td class=\"risk-{lvl_cls}\">{lvl}</td>"
            f"<td>{html_lib.escape(str(f.get('验证状态','')))}</td>"
            f"<td><code>{html_lib.escape(str(f.get('参数','')))}</code></td>"
            f"<td>{html_lib.escape(str(f.get('置信度','')))}</td>"
            f"<td><code>{html_lib.escape(str(f.get('URL','')))}</code></td>"
            f"<td><code>{html_lib.escape(str(f.get('Payload','')))}</code></td>"
            f"<td>{html_lib.escape(str(f.get('证据','')))}</td>"
            "</tr>"
        )

    high = sum(1 for r in results if r.get("风险等级") == "高")
    mid = sum(1 for r in results if r.get("风险等级") == "中")
    low = sum(1 for r in results if r.get("风险等级") == "低")
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    if not rows_html:
        rows_html = ('<tr><td colspan="8" style="text-align:center;'
                     'color:#9aa3b2;padding:40px;">未发现漏洞</td></tr>')

    report_html = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<title>漏洞扫描报告 · {html_lib.escape(target)}</title>
<style>
  body{{font-family:-apple-system,"Microsoft YaHei",sans-serif;
       background:#f4f5f7;margin:0;padding:30px;color:#1a1d24}}
  .container{{max-width:1200px;margin:0 auto;background:#fff;
             border-radius:12px;padding:36px;box-shadow:0 4px 20px rgba(0,0,0,.08)}}
  h1{{margin:0 0 8px;font-size:24px}}
  h2{{margin:24px 0 12px;font-size:16px;color:#4a5468;
     border-left:4px solid #4f8cff;padding-left:10px}}
  .meta{{color:#6b7280;font-size:13px;margin-bottom:24px}}
  .meta span{{margin-right:20px}}
  .stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;
         margin:20px 0 28px}}
  .stat{{padding:16px;border-radius:10px;background:#f8f9fb;
        border:1px solid #e5e8ef}}
  .stat .label{{font-size:12px;color:#6b7280}}
  .stat .value{{font-size:26px;font-weight:800;margin-top:4px}}
  .stat.high .value{{color:#e03e3e}}
  .stat.mid .value{{color:#d97706}}
  .stat.low .value{{color:#16a34a}}
  .stat.total .value{{color:#4f8cff}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  thead th{{background:#f0f2f6;text-align:left;padding:12px;
           border-bottom:2px solid #e5e8ef;font-weight:600;color:#4a5468}}
  tbody td{{padding:11px 12px;border-bottom:1px solid #eef0f5;
           vertical-align:top;word-break:break-all}}
  tbody tr:hover{{background:#f8fafc}}
  code{{background:#f0f2f6;padding:2px 6px;border-radius:4px;
       font-family:Consolas,monospace;font-size:12px}}
  .risk-high{{color:#e03e3e;font-weight:700}}
  .risk-mid{{color:#d97706;font-weight:700}}
  .risk-low{{color:#16a34a;font-weight:700}}
  .footer{{margin-top:36px;padding-top:20px;border-top:1px solid #eef0f5;
          color:#9aa3b2;font-size:12px;text-align:center}}
</style></head><body>
<div class="container">
  <h1>🛡️ Web 漏洞扫描报告</h1>
  <div class="meta">
    <span><strong>目标：</strong>{html_lib.escape(target)}</span>
    <span><strong>生成时间：</strong>{now_str}</span>
    <span><strong>漏洞总数：</strong>{len(results)}</span>
  </div>
  <div class="stats">
    <div class="stat total"><div class="label">漏洞总数</div><div class="value">{len(results)}</div></div>
    <div class="stat high"><div class="label">高危</div><div class="value">{high}</div></div>
    <div class="stat mid"><div class="label">中危</div><div class="value">{mid}</div></div>
    <div class="stat low"><div class="label">低危</div><div class="value">{low}</div></div>
  </div>
  <h2>漏洞明细</h2>
  <table>
    <thead><tr>
      <th>漏洞类型</th><th>风险等级</th><th>验证状态</th><th>参数</th>
      <th>置信度</th><th>URL</th><th>Payload</th><th>证据</th>
    </tr></thead>
    <tbody>{rows_html}</tbody>
  </table>
  <div class="footer">
    本报告由 Auto-Web-Vuln-Platform 生成 · 仅限授权靶场/自有系统使用<br>
    生成时间 {now_str}
  </div>
</div>
</body></html>"""

    filename = f"scan_report_{int(time.time())}.html"
    return Response(
        report_html,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )