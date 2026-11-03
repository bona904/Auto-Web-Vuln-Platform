# core/crawler.py
"""
通用爬虫 + 注入点解析 + 每页检测调度（含重活页识别 + 只读高危跳过）。

v1.2.3 修复：
    - _HEAVY_PATTERNS 加 Pikachu 盲注页（sqli_blind_t / sqli_blind_b）和 RCE 页
      避免多线程同时发 sleep(5) 把数据库连接池打挂

v1.2.2 修复：
    - 种子路径拼接改为"基于根"，修复 /vul/vul/xxx 重复拼接问题
    - 新增 _is_404_page() 识别靶场 200 兜底 404
    - 种子失败静默，避免 80 条日志噪音

v1.2.1 新增：
    - 启动时把 config.CRAWLER_PATH_SEEDS 中的已知漏洞路径加入 BFS 队列
      绕过 JS 动态菜单限制，能覆盖 Pikachu / DVWA 等靶场的 SQL 注入页

关键能力：
    1. is_heavy_url()：识别"PHP 层做重活"的页面（captcha/exec/fi 等）
    2. analyze_target 返回值带 is_heavy 标记，供 engine 分组
    3. 只读模式：命中高危路径 / 参数一律跳过并告警
    4. 使用 core.logger 分级日志（前端可实时查看）
"""

from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from bs4 import BeautifulSoup

import config
from core.http_client import safe_request, read_text, is_static
from core.detectors import DETECTORS, test_json
from core import logger


# =====================================================================
# 重活页识别（PHP 层执行命令 / 生成图片 / 文件包含 / 盲注 sleep 等）
# =====================================================================
_HEAVY_PATTERNS = (
    # DVWA
    "/vulnerabilities/captcha",
    "/vulnerabilities/exec",
    "/vulnerabilities/fi",
    # ★ v1.2.3：Pikachu 盲注页（sleep 锁数据库连接，必须串行）
    "/sqli_blind_t",
    "/sqli_blind_b",
    # ★ v1.2.3：Pikachu 命令执行页（外部 ping，慢）
    "/rce_ping",
    "/rce_eval",
)


def is_heavy_url(url):
    """判断 URL 是否"PHP 层重活页"，engine 会单独串行跑。"""
    low = (url or "").lower()
    return any(p in low for p in _HEAVY_PATTERNS)


# =====================================================================
# 靶场兜底 404 识别
# =====================================================================
_NOT_FOUND_SIGNALS = (
    "404", "not found", "页面不存在", "页面未找到",
    "the page you requested", "can't find", "does not exist",
)


def _is_404_page(res):
    """判断"返回 200 但页面不存在"的靶场兜底页。"""
    if res is None:
        return True
    try:
        text = read_text(res)[:2000].lower()
    except Exception:
        return True
    return any(s in text for s in _NOT_FOUND_SIGNALS)


# =====================================================================
# 过滤工具
# =====================================================================
def _is_ignored(url):
    return is_static(url)


def _is_blacklisted(url):
    low = url.lower()
    return any(b in low for b in config.BLACKLIST)


def _domain_forbidden(url):
    host = urlparse(url).hostname or ""
    for bad in config.DOMAIN_BLACKLIST:
        if host.endswith(bad) or bad in host:
            return True
    return False


def _has_query(url):
    return bool(parse_qs(urlparse(url).query))


def _normalize_url(url):
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))


def _is_skippable_for_inject(url):
    low = url.lower()
    return any(p.lower() in low for p in config.SKIP_INJECT_PATTERNS)


def _is_dangerous_path(url):
    """只读模式：命中高危路径直接跳过。"""
    if not getattr(config, "READ_ONLY_MODE", True):
        return False
    low = (url or "").lower()
    return any(h in low for h in getattr(config, "DANGEROUS_PATH_HINTS", ()))


# =====================================================================
# 爬虫
# =====================================================================
def crawl(session, start_url, failed_urls):
    """BFS 爬取同域页面。返回待扫描 URL 列表。"""
    print("[*] 启动通用爬虫...")
    logger.info("CRAWL", f"启动通用爬虫 {start_url}")
    if _domain_forbidden(start_url):
        print(f"[!] 目标域名命中禁止列表，拒绝扫描: {start_url}\n")
        logger.error("CRAWL", f"目标域名命中禁止列表: {start_url}")
        return []

    # 种子始终基于"根"拼接，避免 /vul/vul/ 重复
    root_p = urlparse(start_url)
    root_base = f"{root_p.scheme}://{root_p.netloc}"

    queue = [(start_url, 0)]

    seeds = getattr(config, "CRAWLER_PATH_SEEDS", ())
    if seeds:
        print(f"[*] 加载路径字典: {len(seeds)} 个种子路径")
        logger.info("CRAWL", f"加载路径字典 {len(seeds)} 个种子")
        for seed in seeds:
            if not seed:
                continue
            seed_path = "/" + seed.lstrip("/")
            full = root_base + seed_path
            queue.append((full, 1))

    visited = set()
    urls_to_scan = []
    start_netloc = urlparse(start_url).netloc
    seed_hits = 0

    while queue:
        if len(urls_to_scan) >= config.CRAWL_MAX_PAGES:
            print(f"[*] 达到最大爬取页数 {config.CRAWL_MAX_PAGES}，停止。")
            logger.warn("CRAWL", f"达到最大爬取页数 {config.CRAWL_MAX_PAGES}")
            break

        current, depth = queue.pop(0)
        norm = _normalize_url(current)
        if norm in visited:
            continue
        if _is_dangerous_path(current):
            logger.warn("CRAWL", f"只读模式跳过高危接口: {current}")
            continue
        if _is_blacklisted(current) or _is_ignored(current):
            continue
        if failed_urls.get(current, 0) >= config.FAILED_URL_MAX:
            continue

        visited.add(norm)
        urls_to_scan.append(current)

        if depth >= config.CRAWL_MAX_DEPTH:
            continue

        res, _ = safe_request(session, "GET", current)
        if not res:
            failed_urls[current] = failed_urls.get(current, 0) + 1
            if depth != 1:
                print(f"  [※] 页面请求失败: {current}")
            continue

        # 种子显式 404 静默丢弃
        if depth == 1:
            if _is_404_page(res):
                continue
            seed_hits += 1

        if len(urls_to_scan) <= 1:
            text = read_text(res)
            print(f"[CRAWL-DEBUG] 首页 URL: {current}")
            print(f"[CRAWL-DEBUG] 响应状态: {res.status_code}  长度: {len(text)}")
            print(f"[CRAWL-DEBUG] 最终跳转 URL: {res.url}")
            print(f"[CRAWL-DEBUG] 前 600 字符: {text[:600]!r}")
            print(f"[CRAWL-DEBUG] 是否含 vulnerabilities: "
                  f"{'vulnerabilities' in text.lower()}")

        soup = BeautifulSoup(read_text(res), "html.parser")

        # ---- 提取 a[href] ----
        for a in soup.find_all("a", href=True):
            next_url = urljoin(current, a["href"])
            np = urlparse(next_url)
            if np.netloc and np.netloc != start_netloc:
                continue
            if np.scheme and np.scheme not in ("http", "https"):
                continue
            if _normalize_url(next_url) in visited:
                continue
            if _is_ignored(next_url) or _is_blacklisted(next_url):
                continue
            queue.append((next_url, depth + 1))

        # ---- 提取 form[action] ----
        for form in soup.find_all("form"):
            action = form.get("action")
            if not action:
                continue
            next_url = urljoin(current, action)
            np = urlparse(next_url)
            if np.netloc and np.netloc != start_netloc:
                continue
            if _normalize_url(next_url) in visited:
                continue
            queue.append((next_url, depth + 1))

    if seed_hits:
        print(f"[*] 路径字典真正命中 {seed_hits} 个种子页")
        logger.info("CRAWL", f"路径字典真正命中 {seed_hits} 个种子页")

    with_query = [u for u in urls_to_scan if _has_query(u)]
    print(f"[*] 爬虫完成：共 {len(urls_to_scan)} 个页面，"
          f"其中带 GET 参数 {len(with_query)} 个。开始并发检测...\n")
    logger.info("CRAWL", f"爬虫完成：{len(urls_to_scan)} 页，"
                          f"带 GET 参数 {len(with_query)} 个")
    return urls_to_scan


# =====================================================================
# 单页检测调度
# =====================================================================
def analyze_target(session, target_url, scanned_params, failed_urls,
                   per_request_timeout=None):
    """
    对单个 URL 解析表单/GET 参数，逐个注入点调用检测器。

    返回：
        (findings, checked_points, is_heavy)
    """
    findings = []
    checked = 0
    heavy = is_heavy_url(target_url)

    if _is_ignored(target_url):
        return findings, checked, heavy

    if _is_skippable_for_inject(target_url):
        print(f"  [-] 白名单跳过: {target_url}")
        return findings, checked, heavy

    if _is_dangerous_path(target_url):
        logger.warn("CRAWL", f"只读模式跳过高危注入点: {target_url}")
        return findings, checked, heavy

    res, _ = safe_request(session, "GET", target_url,
                          timeout=per_request_timeout)
    if not res:
        failed_urls[target_url] = failed_urls.get(target_url, 0) + 1
        print(f"  [※] 页面请求失败: {target_url}")
        return findings, checked, heavy

    soup = BeautifulSoup(read_text(res), "html.parser")

    # ---------------- 表单注入点 ----------------
    for form in soup.find_all("form"):
        action = urljoin(target_url, form.get("action", ""))
        method = (form.get("method") or "get").lower()
        inputs = form.find_all(["input", "textarea", "select"])

        form_data = {}
        targets = []

        for inp in inputs:
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            if itype in ("text", "search", "textarea", "password", None):
                targets.append(name)
            if itype in ("checkbox", "radio"):
                if inp.has_attr("checked"):
                    form_data[name] = inp.get("value", "on")
                continue
            form_data[name] = inp.get("value", "")

        for t in targets:
            key = f"{method.upper()}|{_normalize_url(action)}|{t}"
            if key in scanned_params:
                continue
            scanned_params.add(key)
            checked += 1
            print(f"  [+] 表单注入点 [{method.upper()}]: {t} @ {action}")
            for det in DETECTORS:
                try:
                    fs = det(session, action, form_data, t)
                    print(f"  [※] {det.__name__} 返回 {len(fs)} 条 @ {action}?{t}")
                    findings.extend(fs)
                except Exception as e:
                    print(f"  [※] {det.__name__} 异常 @ {action}: {e}")

    # ---------------- GET 注入点 ----------------
    parsed = urlparse(target_url)
    qs = parse_qs(parsed.query)
    if qs:
        flat_data = {k: v[0] for k, v in qs.items()}
        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                parsed.params, "", ""))

        for param in qs:
            key = f"GET|{_normalize_url(clean_url)}|{param}"
            if key in scanned_params:
                continue
            scanned_params.add(key)
            checked += 1
            print(f"  [+] GET 注入点: {param} @ {target_url}")
            for det in DETECTORS:
                try:
                    fs = det(session, clean_url, flat_data, param)
                    print(f"  [※] {det.__name__} 返回 {len(fs)} 条 "
                          f"@ {clean_url}?{param}")
                    findings.extend(fs)
                except Exception as e:
                    print(f"  [※] {det.__name__} 异常 @ {clean_url}: {e}")

    # ---------------- JSON 端点 ----------------
    if any(k in target_url.lower() for k in ["api", "json", "graphql"]):
        findings.extend(test_json(session, target_url))

    return findings, checked, heavy