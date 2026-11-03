# core/http_client.py
"""
HTTP 请求封装层：统一重试 / 编码 / 限速 / 慢页跳过 / 自动降速 / 会话失效检测。

v1.2.1 新增：
    - safe_request 入口过滤非法 URL 协议（修复 javascript:alert(1) 类崩溃日志）

v1.2 新增：
    - 全局限速 + 单域名限速（合并进 _rate_limit，兼容旧的自适应降速）
"""

import time
import random
import re
import threading
from urllib.parse import urljoin, urlparse

import config
from core import logger


_rate_lock = threading.Lock()
_last_req_time = 0.0
_last_call_host = {}   # host -> 上次请求时间戳

_SECURITY_LOW_ENABLED = False

_skip_urls = set()
_url_timeout_counts = {}
_skip_lock = threading.Lock()

_effective_interval = float(getattr(config, "REQUEST_INTERVAL", 0.15))
_interval_lock = threading.Lock()

_session_dead = False
_session_dead_lock = threading.Lock()


def enable_security_low():
    global _SECURITY_LOW_ENABLED
    _SECURITY_LOW_ENABLED = True


def disable_security_low():
    global _SECURITY_LOW_ENABLED
    _SECURITY_LOW_ENABLED = False


def is_security_low_enabled():
    return _SECURITY_LOW_ENABLED


def mark_session_dead():
    global _session_dead
    if _session_dead:
        return
    with _session_dead_lock:
        _session_dead = True


def session_dead():
    with _session_dead_lock:
        return _session_dead


def reset_session_state():
    global _session_dead
    with _session_dead_lock:
        _session_dead = False


def _bump_interval_on_timeout():
    if not getattr(config, "SLOWDOWN_AUTO", True):
        return
    global _effective_interval
    with _interval_lock:
        cap = float(getattr(config, "SLOWDOWN_MAX_INTERVAL", 2.0))
        new_val = min(_effective_interval * 2.0, cap)
        if new_val > _effective_interval:
            _effective_interval = new_val
            logger.warn("SLOWDOWN", f"检测到超时，全局间隔 -> {_effective_interval:.2f}s")


def _mark_url_failure(url):
    if not getattr(config, "SLOW_URL_SKIP_ENABLED", True):
        return
    with _skip_lock:
        c = _url_timeout_counts.get(url, 0) + 1
        _url_timeout_counts[url] = c
        if c >= int(getattr(config, "SLOW_URL_SKIP_THRESHOLD", 3)):
            if url not in _skip_urls:
                _skip_urls.add(url)
                logger.warn("SLOWDOWN", f"已跳过慢页: {url}")


def is_url_skipped(url):
    return url in _skip_urls


# ---------------- 静态后缀 / MIME 过滤 ----------------
_STATIC_SUFFIX = tuple(getattr(config, "IGNORE_SUFFIX", ()))
_IGNORE_MIME_PREFIX = tuple(getattr(config, "IGNORE_MIME_PREFIX", ()))


def is_static(url):
    low = (url or "").lower()
    return any(low.endswith(s) for s in _STATIC_SUFFIX)


def is_static_mime(res):
    try:
        ct = (res.headers.get("Content-Type") or "").lower()
    except Exception:
        return False
    if not ct:
        return False
    return any(ct.startswith(p) for p in _IGNORE_MIME_PREFIX)


# ---------------- UA / 变异 ----------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0 Safari/537.36",
]

_XSS_VARIANTS = [
    lambda p: p,
    lambda p: p.replace("<", "%3C").replace(">", "%3E"),
    lambda p: p.replace("script", "ScRiPt"),
    lambda p: p.replace("alert", "a\\u006cert"),
    lambda p: p.replace(" ", "/**/"),
]


def get_stealth_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Connection": "close",
    }


def mutate_payload(payload, index=0):
    if not getattr(config, "ENABLE_PAYLOAD_MUTATE", False):
        return payload
    if index <= 0:
        return payload
    fn = _XSS_VARIANTS[index % len(_XSS_VARIANTS)]
    try:
        return fn(payload)
    except Exception:
        return payload


def read_text(res):
    if res is None:
        return ""
    if not getattr(config, "FORCE_TEXT_DECODE", True):
        return res.text or ""
    try:
        enc = (res.encoding or "").lower().strip()
        if enc and enc not in ("iso-8859-1",):
            try:
                return res.content.decode(enc, errors="replace")
            except Exception:
                pass
        head = res.content[:2048].decode("ascii", errors="ignore")
        m = re.search(r'charset=["\']?([\w\-]+)', head, re.I)
        if m:
            enc = m.group(1).lower()
            try:
                return res.content.decode(enc, errors="replace")
            except Exception:
                pass
        return res.content.decode("utf-8", errors="replace")
    except Exception:
        return res.text or ""


# ---------------- 会话失效检测 ----------------
def _is_login_like_url(url):
    low = (url or "").lower()
    for p in getattr(config, "SESSION_DEAD_SAFE_URL_PATTERNS", ()):
        if p and p.lower() in low:
            return True
    return False


def _has_password_input(res_text):
    low = (res_text or "").lower()
    return ('type="password"' in low) or ("type='password'" in low)


def _detect_session_dead(res, url):
    if not getattr(config, "SESSION_DEAD_CHECK", True):
        return
    if res is None:
        return
    if _is_login_like_url(url):
        return

    try:
        text = read_text(res) or ""
    except Exception:
        return
    text_low = text[:6000].lower()

    if _has_password_input(text_low):
        return

    try:
        if res.is_redirect:
            loc = (res.headers.get("Location") or "").lower()
            for p in getattr(config, "SESSION_DEAD_REDIRECT_PATHS", ()):
                if p and p.lower() in loc:
                    mark_session_dead()
                    logger.warn("SESSION", f"会话失效（302 → {loc}），终止扫描")
                    return

        for hint in getattr(config, "SESSION_DEAD_HINTS", ()):
            h = (hint or "").lower()
            if not h:
                continue
            if h in text_low:
                mark_session_dead()
                logger.warn("SESSION", f"会话失效（页面含关键字 {hint!r}），终止扫描")
                return
    except Exception:
        pass


# ---------------- 限速（全局限速 + 单域名限速 + 自适应降速） ----------------
def _rate_limit(url):
    global _last_req_time
    global_qps = getattr(config, "GLOBAL_RATE_LIMIT", 20)
    host_qps = getattr(config, "RATE_LIMIT_PER_HOST", 5)
    global_iv = 1.0 / max(1, global_qps)
    host_iv = 1.0 / max(1, host_qps)

    host = urlparse(url or "").netloc.lower()

    with _rate_lock:
        now = time.time()
        wait = 0.0

        gap = now - _last_req_time
        need_gap = max(global_iv, _effective_interval)
        if gap < need_gap:
            wait = max(wait, need_gap - gap)

        gap_h = now - _last_call_host.get(host, 0.0)
        if gap_h < host_iv:
            wait = max(wait, host_iv - gap_h)

        if wait > 0:
            time.sleep(wait)
            now = time.time()

        _last_req_time = now
        _last_call_host[host] = now


def _do_once(session, method, url, params, data, headers, timeout, allow_redirects):
    h = get_stealth_headers()
    if headers:
        h.update(headers)
    started = time.time()
    try:
        m = (method or "GET").upper()
        if m == "GET":
            res = session.get(url, params=params, headers=h, timeout=timeout,
                              verify=config.VERIFY_TLS,
                              allow_redirects=allow_redirects)
        elif m == "POST":
            res = session.post(url, data=data, headers=h, timeout=timeout,
                               verify=config.VERIFY_TLS,
                               allow_redirects=allow_redirects)
        elif m == "JSON":
            res = session.post(url, json=data, headers=h, timeout=timeout,
                               verify=config.VERIFY_TLS,
                               allow_redirects=allow_redirects)
        else:
            res = session.request(m, url, params=params, data=data,
                                  headers=h, timeout=timeout,
                                  verify=config.VERIFY_TLS,
                                  allow_redirects=allow_redirects)
    except Exception as e:
        return None, time.time() - started, str(e)
    return res, time.time() - started, None


def safe_request(session, method, url, params=None, data=None, headers=None,
                 timeout=None, allow_redirects=None, force_security_low=None,
                 allow_static=False, skip_session_check=False):
    """
    统一请求入口。

    v1.2.1：入口处过滤非法 URL 协议
      - javascript: / data: / file: 等非 http(s) 协议直接返回 None
      - 防止 requests 抛 "No connection adapters" 污染日志
    """
    # ★ v1.2.1：非法 URL 协议直接跳过
    if not url or not url.lower().startswith(("http://", "https://")):
        return None, 0.0

    if session_dead():
        return None, 0.0
    if is_url_skipped(url):
        return None, 0.0
    if not allow_static and is_static(url):
        return None, 0.0

    # ★ 限速（全局 + 单域名 + 自适应）
    _rate_limit(url)

    timeout = timeout or config.REQUEST_TIMEOUT
    allow_redirects = (
        config.FOLLOW_REDIRECTS if allow_redirects is None else allow_redirects
    )

    inject_low = _SECURITY_LOW_ENABLED if force_security_low is None else bool(force_security_low)
    if inject_low:
        try:
            session.cookies.update({"security": "low"})
        except Exception:
            pass

    retry_times = max(0, int(getattr(config, "RETRY_TIMES", 0)))
    retry_interval = float(getattr(config, "RETRY_INTERVAL", 0.4))
    retry_on_status = tuple(getattr(config, "RETRY_ON_STATUS", ()) or ())

    total_started = time.time()
    res = None
    last_err = None

    for attempt in range(retry_times + 1):
        res, elapsed, last_err = _do_once(session, method, url, params, data,
                                          headers, timeout, allow_redirects)
        if res is not None and (res.status_code not in retry_on_status):
            break
        if attempt < retry_times:
            reason = "异常" if res is None else f"HTTP {res.status_code}"
            logger.warn("RETRY", f"{url} {reason}，第 {attempt + 1} 次重试")
            time.sleep(retry_interval)
            continue
        break

    total_elapsed = time.time() - total_started

    if res is None:
        logger.error("HTTP", f"请求失败 {url}: {last_err}")
        _bump_interval_on_timeout()
        _mark_url_failure(url)
        return None, total_elapsed

    if not skip_session_check:
        _detect_session_dead(res, url)

    if not allow_static and is_static_mime(res):
        return None, total_elapsed

    return res, total_elapsed