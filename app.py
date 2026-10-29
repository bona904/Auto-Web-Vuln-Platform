from flask import Flask, render_template_string, request, jsonify
import scanner
import threading
import time

# 初始化 Flask 应用
app = Flask(__name__)

# 全局变量，记录扫描状态和结果 (预留变量，方便后续扩展如进度条、异步后台任务等功能)
scan_status = {"running": False, "results": []}

# =====================================================================
# 【第一部分：前端 UI 代码说明区】
# 1. 这是一个内嵌的 HTML 模板，利用 Jinja2 引擎直接渲染，省去了创建 templates 文件夹的麻烦。
# 2. 如果你想让网页一打开就默认扫描其他靶场，请往下看 HTML 代码里的 input 标签。
# =====================================================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>🛡️ Web 漏洞扫描平台</title>
    <style>
        /* 整体页面深色黑客风背景 */
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px; }
        /* 居中的主面板卡片 */
        .container { max-width: 900px; margin: 0 auto; background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 8px 30px rgba(0,0,0,0.5); }
        /* 顶部标题样式 */
        h1 { color: #38bdf8; text-align: center; margin-bottom: 30px; }
        /* 表单组容器 */
        .form-group { margin-bottom: 20px; }
        /* 标签文字样式 */
        label { display: block; margin-bottom: 8px; color: #94a3b8; }
        /* 输入框样式 */
        input[type="text"], input[type="password"] { width: 100%; padding: 12px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: white; box-sizing: border-box;}
        /* 扫描按钮基本样式 */
        button { width: 100%; padding: 14px; background: #3b82f6; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; transition: 0.3s; font-weight: bold;}
        /* 按钮悬浮与禁用状态 */
        button:hover { background: #2563eb; }
        button:disabled { background: #475569; cursor: not-allowed; }
        /* 扫描加载提示文字 */
        #loading { display: none; text-align: center; margin-top: 20px; color: #f59e0b; font-weight: bold;}
        /* 结果展示区外框（默认隐藏） */
        #results { margin-top: 30px; display: none; }
        /* 结果表格样式 */
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }
        th { background: #0f172a; color: #38bdf8; }
        /* 高危漏洞文字颜色 */
        .high { color: #f87171; font-weight: bold; }
        /* 中危漏洞文字颜色 */
        .mid { color: #fbbf24; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Web 漏洞扫描平台</h1>
        
        <div class="form-group">
            <label>目标网址 (URL)</label>
            <!-- 【靶场修改点 1】：如果想让平台默认扫描别的靶场，在这里修改 value 属性的值 -->
            <input type="text" id="target" value="http://127.0.0.1/dvwa/" placeholder="http://...">
        </div>
        
        <div class="form-group">
            <label>登录账号 (可选)</label>
            <!-- 【靶场修改点 2】：其他靶场的默认账号 -->
            <input type="text" id="username" value="admin">
        </div>
        
        <div class="form-group">
            <label>登录密码 (可选)</label>
            <!-- 【靶场修改点 3】：其他靶场的默认密码 -->
            <input type="password" id="password" value="password">
        </div>
        
        <button id="scanBtn" onclick="startScan()">🚀 启动深度扫描</button>
        <div id="loading">⏳ 正在发起多线程并发渗透，请稍候... (预计 30-80 秒)</div>
        
        <div id="results">
            <h2 id="summary"></h2>
            <table id="resultTable">
                <thead>
                    <tr><th>漏洞类型</th><th>URL</th><th>参数</th><th>Payload</th></tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </div>

    <script>
        // 前端点击“启动扫描”触发的 JavaScript 函数
        function startScan() {
            // 获取输入框里的目标、账号、密码
            const target = document.getElementById('target').value;
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            // 获取页面上的各类元素（按钮、加载圈、结果框、表格体）
            const btn = document.getElementById('scanBtn');
            const loading = document.getElementById('loading');
            const results = document.getElementById('results');
            const tbody = document.querySelector('#resultTable tbody');

            // 更改 UI 状态：禁用按钮、显示加载动画、清空上次结果
            btn.disabled = true;
            loading.style.display = 'block';
            results.style.display = 'none';
            tbody.innerHTML = '';

            // 向后端 API 发送 POST 请求，把参数传过去
            fetch('/api/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target: target, username: username, password: password})
            })
            .then(response => response.json()) // 将后端返回的数据解析为 JSON
            .then(data => {
                // 恢复 UI 状态：隐藏加载动画，恢复按钮
                loading.style.display = 'none';
                btn.disabled = false;
                
                // 如果发现了漏洞，渲染表格
                if (data.length > 0) {
                    results.style.display = 'block';
                    document.getElementById('summary').innerHTML = `发现漏洞总数: <span class="high">${data.length}</span>`;
                    
                    // 遍历后端返回的漏洞列表，动态生成 HTML 表格行
                    data.forEach(vuln => {
                        const row = `<tr>
                            <td class="high">${vuln['类型']}</td>
                            <td>${vuln['URL']}</td>
                            <td>${vuln['参数']}</td>
                            <td style="font-family: monospace; color: #a78bfa;">${vuln['Payload']}</td>
                        </tr>`;
                        tbody.innerHTML += row;
                    });
                } else {
                    alert('扫描完成，未发现漏洞。');
                }
            })
            .catch(err => {
                // 如果发生网络错误或后端崩溃，弹出提示
                loading.style.display = 'none';
                btn.disabled = false;
                alert('扫描请求失败，请检查后台终端！');
                console.error(err);
            });
        }
    </script>
</body>
</html>
"""

# =====================================================================
# 【第二部分：路由与后端接口】
# =====================================================================

@app.route('/')
def index():
    """
    访问网站首页时，直接把上面的 HTML_TEMPLATE 渲染出来
    """
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """
    前端点击“启动扫描”后调用的核心 API 接口。
    """
    # 接收前端传过来的 JSON 数据
    data = request.json
    target = data.get('target')
    username = data.get('username', '')
    password = data.get('password', '')
    
    # =================================================================
    # 🚀【靶场替换指南 4：其他靶场的特殊登录逻辑】
    # 如果扫描其他需要登录的靶场（比如 testphp.vulnweb.com），
    # 往往它们的登录 URL 不叫 login.php，或者表单字段名不是 username。
    # 
    # 解决方法：打开你的 scanner.py 文件，找到 run_scan_for_web 函数。
    # 在那个函数里面，你可以判断 target 地址，动态修改 LOGIN_URL。
    # 例如：
    #   if "testphp" in target:
    #       LOGIN_URL = target + "login.php"
    #   elif "zero" in target:
    #       LOGIN_URL = target + "login.html"
    # =================================================================

    # 调用 scanner.py 里的核心扫描函数，开始深度扫描
    results = scanner.run_scan_for_web(target, username, password)
    
    # 将扫描结果返回给前端
    if results:
        return jsonify(results)
    else:
        return jsonify([])


# 启动入口
if __name__ == '__main__':
    print("=== 🚀 Web 控制台已启动 ===")
    print("请在浏览器中访问: http://127.0.0.1:5000")
    # host='0.0.0.0' 允许局域网内的其他设备（如手机）访问
    # threaded=True 允许 Flask 开启多线程处理请求，防止扫描时把页面卡死
    app.run(host='0.0.0.0', port=5000, threaded=True)