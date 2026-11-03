# core/engine.py
"""
扫描引擎层（业务编排 + 对外统一入口）。

⚠️ 合规声明：
    本项目仅用于【授权靶场/自有系统】的教学与安全测试。

本轮关键改动：
    ★ 页面分级并发：
        normal 页（sqli / xss / brute / csrf / xss_d ...）→ 并发，优先跑
        heavy  页（exec / captcha / fi ...）           → 串行 + 短超时 + 不重试
    这样即使重活页拖崩，也不影响轻活页拿结果。

    新增：会话失效（session_dead）优雅停机 + 分级日志（core.logger）。
"""

import time
import requests
import concurrent.futures
from urllib.parse import urlparse

import config
from core.auth import apply_auth, is_session_alive
from core.crawler import crawl, analyze_target, is_heavy_url
from core.http_client import session_dead, reset_session_state
from core import logger
from storage.result_store import ResultStore


_DEBUG_ENGINE = getattr(config, "DEBUG_ENGINE", True)

# 重活页使用的短超时（避免单页拖 20s）
_HEAVY_TIMEOUT = 8
# 轻活页使用配置的正常超时
_NORMAL_TIMEOUT = None    # None => 使用 config.REQUEST_TIMEOUT


def run_scan(target_url, username="", password=""):
    print(f"\n=== 开始扫描: {target_url} ===\n")
    reset_session_state()
    logger.info("ENGINE", f"开始扫描 {target_url}")

    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print(f"[!] 目标地址不合法: {target_url}\n")
        logger.error("ENGINE", f"目标地址不合法: {target_url}")
        return []

    host = parsed.hostname or ""
    for bad in config.DOMAIN_BLACKLIST:
        if host.endswith(bad) or bad in host:
            print(f"[!] 目标域名命中禁止列表（{bad}），拒绝扫描。\n")
            logger.error("ENGINE", f"目标域名命中禁止列表（{bad}）")
            return []

    username = (username or "").strip()
    password = password or ""
    if username:
        config.AUTH_FORM_USERNAME = username
    if password:
        config.AUTH_FORM_PASSWORD = password

    base_url = target_url if target_url.endswith("/") else target_url + "/"

    session = requests.Session()
    auth_mode = apply_auth(session, base_url)
    print(f"[*] 本次鉴权方式: {auth_mode}\n")

    failed_urls = {}
    urls_to_scan = crawl(session, target_url, failed_urls)
    if not urls_to_scan:
        print("[!] 未发现可扫描的页面。\n")
        logger.warn("ENGINE", "未发现可扫描的页面")
        return []

    # ★ 分级：normal 先、heavy 后
    normal_urls = [u for u in urls_to_scan if not is_heavy_url(u)]
    heavy_urls = [u for u in urls_to_scan if is_heavy_url(u)]
    print(f"[*] 页面分级：轻活 {len(normal_urls)} 个（并发），"
          f"重活 {len(heavy_urls)} 个（串行，短超时）\n")
    logger.info("ENGINE", f"页面分级：轻活 {len(normal_urls)} / 重活 {len(heavy_urls)}")

    scanned_params = set()
    all_findings = []
    total_checked = 0
    stop_event = False
    heartbeat_counter = 0
    heartbeat_every = max(1, int(getattr(config, "SESSION_HEARTBEAT_EVERY", 30)))

    # ---------------- 第一阶段：轻活页并发跑 ----------------
    def _run_normal(u):
        try:
            return analyze_target(session, u, scanned_params, failed_urls,
                                  per_request_timeout=_NORMAL_TIMEOUT)
        except Exception as e:
            print(f"    [!] 页面分析异常 @ {u}: {e}")
            return ([], 0, False)

    if normal_urls:
        print(f"[*] 第一阶段：扫描 {len(normal_urls)} 个轻活页（并发）")
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=config.THREAD_WORKERS) as executor:
            futures = [executor.submit(_run_normal, u) for u in normal_urls]
            for fut in concurrent.futures.as_completed(futures):
                if stop_event:
                    continue
                if session_dead():
                    logger.warn("ENGINE", "检测到会话失效，停止剩余任务")
                    stop_event = True
                    for f2 in futures:
                        f2.cancel()
                    continue

                try:
                    res_findings, checked, _ = fut.result()
                except Exception as e:
                    print(f"    [!] 检测任务异常: {e}")
                    continue

                total_checked += checked
                if res_findings:
                    all_findings.extend(res_findings)
                    for r in res_findings:
                        print(f"    🎉 [发现] {r['类型']} | 参数: {r['参数']} "
                              f"| 置信度: {r.get('置信度', '')}")
                        logger.info("FIND", f"🎉 {r['类型']} | 参数: {r['参数']} "
                                            f"| 置信度: {r.get('置信度','')}")

                heartbeat_counter += checked
                if heartbeat_counter >= heartbeat_every:
                    heartbeat_counter = 0
                    if auth_mode in ("form", "auto", "cookie", "bearer"):
                        if not is_session_alive(session, base_url):
                            print("\n[!] 会话已失效（疑似掉登录），终止扫描！\n")
                            logger.warn("ENGINE", "会话已失效（掉登录），终止扫描")
                            stop_event = True
                            for f2 in futures:
                                f2.cancel()

    # ---------------- 第二阶段：重活页串行跑 ----------------
    if heavy_urls and not stop_event:
        print(f"\n[*] 第二阶段：扫描 {len(heavy_urls)} 个重活页（串行，短超时）")
        for u in heavy_urls:
            if stop_event:
                break
            if session_dead():
                logger.warn("ENGINE", "会话失效，第二阶段提前终止")
                break
            print(f"  [~] 重活页: {u}")
            try:
                res_findings, checked, _ = analyze_target(
                    session, u, scanned_params, failed_urls,
                    per_request_timeout=_HEAVY_TIMEOUT)
            except Exception as e:
                print(f"    [!] 重活页分析异常 @ {u}: {e}")
                res_findings, checked = [], 0
            total_checked += checked
            if res_findings:
                all_findings.extend(res_findings)
                for r in res_findings:
                    print(f"    🎉 [发现] {r['类型']} | 参数: {r['参数']} "
                          f"| 置信度: {r.get('置信度', '')}")
                    logger.info("FIND", f"🎉 {r['类型']} | 参数: {r['参数']} "
                                        f"| 置信度: {r.get('置信度','')}")

    if stop_event:
        print("[!] 扫描已提前终止（会话失效）。\n")
        logger.warn("ENGINE", "扫描提前终止")

    # ---------------- 去重 + 统计 ----------------
    if _DEBUG_ENGINE:
        print(f"\n[DEBUG-ENGINE] 去重前 all_findings 条数: {len(all_findings)}")
        for i, f in enumerate(all_findings):
            print(f"[DEBUG-ENGINE]   #{i}: 类型={f.get('类型')} "
                  f"参数={f.get('参数')} 风险={f.get('风险等级')} "
                  f"置信={f.get('置信度')}")

    store = ResultStore()
    store.add_many(all_findings)
    final = store.unique()

    if _DEBUG_ENGINE:
        print(f"[DEBUG-ENGINE] 去重后 final 条数: {len(final)}")
        print(f"[DEBUG-ENGINE] 总检测注入点: {total_checked}\n")

    stats = {"高": 0, "中": 0, "低": 0}
    for f in final:
        lvl = f.get("风险等级", "低")
        stats[lvl] = stats.get(lvl, 0) + 1

    print(f"\n[*] 扫描结束，去重后共 {len(final)} 条 "
          f"(高 {stats['高']} / 中 {stats['中']} / 低 {stats['低']})\n")
    logger.info("ENGINE",
                f"扫描结束：共 {len(final)} 条 "
                f"(高 {stats['高']} / 中 {stats['中']} / 低 {stats['低']})")
    return final