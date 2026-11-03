# core/auth.py
"""
鉴权 + 会话强化层（通用版）。

⚠️ 合规声明：
    本项目仅用于【授权靶场/自有系统】的教学与安全测试。

职责：
    apply_auth()            : 按 AUTH_MODE 应用鉴权
    _detect_dvwa_security() : 探测是否为 DVWA
    set_target_level()      : DVWA 专用，切低难度
    is_session_alive()      : 供 engine 心跳检测用；返回布尔

【通用性】
    仅识别到 DVWA 才启用 security=low 注入；普通站点零副作用。

【CSRF token】
    登录时抓取登录页所有 <input type="hidden"> 并原样带回 POST。

【本轮新增 / 修复】
    _register_dvwa_skip_patterns()：
        识别到 DVWA 时把 open_redirect/source、captcha 两个 DVWA 专属路径
        注册到 SKIP_INJECT_PATTERNS；普通网站不注册，通用性零影响。

    ★ 修复：所有登录/探测阶段的 safe_request 一律传 skip_session_check=True，
      彻底避免登录页本身被 _detect_session_dead 误判为"会话失效"。
"""

from urllib.parse import urljoin
import re

from bs4 import BeautifulSoup

import config
from core.http_client import (
    safe_request,
    enable_security_low,
    disable_security_low,
    read_text,
)
from core import logger


_LOGIN_TITLE_HINTS = ("login ::", "<title>login", "sign in", "登录")
_LOGIN_FAIL_HINTS = (
    "incorrect username",
    "incorrect password",
    "username or password",
    "wrong password",
    "login failed",
    "invalid username",
    "invalid password",
    "invalid csrf",
    "invalid token",
    "csrf token",
    "please login",
    "请先登录",
)


def _looks_like_login(res):
    if not res:
        return True
    url = (res.url or "").lower()
    if "login.php" in url:
        return True
    text = read_text(res).lower()
    for hint in _LOGIN_TITLE_HINTS:
        if hint in text:
            return True
    if 'type="password"' in text and "logout" not in text:
        return True
    return False


def _is_authenticated(session, base_url):
    # ★ 鉴权探测：跳过会话失效判断，避免把登录页判定为"掉登录"
    res, _ = safe_request(session, "GET", base_url,
                          force_security_low=False,
                          skip_session_check=True)
    if not res:
        return False
    return not _looks_like_login(res)


def is_session_alive(session, base_url):
    """供 engine 心跳检测：True=仍登录态，False=掉了/访问失败。"""
    return _is_authenticated(session, base_url)


def _extract_hidden_fields(html):
    hidden = {}
    try:
        soup = BeautifulSoup(html, "html.parser")
        for inp in soup.find_all("input"):
            if (inp.get("type") or "").lower() == "hidden":
                name = inp.get("name")
                if name:
                    hidden[name] = inp.get("value", "") or ""
    except Exception:
        pass
    return hidden


# =====================================================================
# DVWA 专属：注册跳过规则（仅 DVWA 目标生效）
# =====================================================================
def _register_dvwa_skip_patterns():
    """仅当识别到 DVWA 时，追加 DVWA 专属跳过规则。通用站零影响。"""
    dvwa_only = [
        "open_redirect/source",       # DVWA 该路径每次返回 500
        "/vulnerabilities/captcha/",  # DVWA 验证码页 GD 库压垮 PHP
    ]
    added = []
    for p in dvwa_only:
        if p not in config.SKIP_INJECT_PATTERNS:
            config.SKIP_INJECT_PATTERNS.append(p)
            added.append(p)
    if added:
        print(f"  [+] DVWA 专属跳过规则已注册: {added}")
        logger.info("AUTH", f"DVWA 专属跳过规则已注册: {added}")


def apply_auth(session, base_url):
    mode = (getattr(config, "AUTH_MODE", "auto") or "auto").lower()
    print(f"[*] 鉴权模式: {mode}" + ("（自动探测）" if mode == "auto" else ""))
    logger.info("AUTH", f"鉴权模式: {mode}")

    used = "none"
    if mode == "cookie" and getattr(config, "AUTH_COOKIE", ""):
        used = _apply_cookie(session)
    elif mode == "bearer" and getattr(config, "AUTH_BEARER_TOKEN", ""):
        used = _apply_bearer(session)
    elif mode == "form":
        used = _apply_form_login(session, base_url)
    elif mode == "auto":
        used = _auto_auth(session, base_url)

    is_dvwa = False
    try:
        is_dvwa = _detect_dvwa_security(session, base_url)
    except Exception:
        is_dvwa = False

    if not is_dvwa:
        print("  [-] 非 DVWA 目标，跳过难度设置（完全通用模式）")
        logger.info("AUTH", "非 DVWA 目标，完全通用模式")
        return used

    print("  [+] 识别到 DVWA，启用 security=low 注入")
    logger.info("AUTH", "识别到 DVWA，启用 security=low 注入")
    enable_security_low()

    # ★ 仅 DVWA 目标追加专属跳过规则
    _register_dvwa_skip_patterns()

    try:
        set_target_level(session, base_url, level="low")
    except Exception as e:
        print(f"  [!] 设置难度异常（可忽略）: {e}")

    if used in ("form", "auto") and not _is_authenticated(session, base_url):
        print("  [!] 切换难度后会话失效，重新登录一次...")
        disable_security_low()
        relogin = _apply_form_login(session, base_url)
        enable_security_low()
        try:
            session.cookies.update({"security": "low"})
        except Exception:
            pass
        if relogin == "form" and _is_authenticated(session, base_url):
            print("  [+] 重新登录成功，会话已恢复正常")
        else:
            print("  [!] 重新登录后仍未恢复（请确认账号密码）")
    else:
        print("  [+] 会话正常，准备开始扫描")

    return used


def _apply_cookie(session):
    cookie_str = getattr(config, "AUTH_COOKIE", "")
    for pair in cookie_str.split(";"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            session.cookies.set(k.strip(), v.strip())
    print(f"  [+] 已注入 Cookie: {list(session.cookies.keys())}")
    return "cookie"


def _apply_bearer(session):
    token = getattr(config, "AUTH_BEARER_TOKEN", "")
    session.headers.update({"Authorization": f"Bearer {token}"})
    print("  [+] 已注入 Bearer Token")
    return "bearer"


def _auto_auth(session, base_url):
    username = getattr(config, "AUTH_FORM_USERNAME", "")
    password = getattr(config, "AUTH_FORM_PASSWORD", "")
    print(f"[DEBUG] apply_auth 检查账号: username={username!r} "
          f"password={'***' if password else ''}")

    if username and password:
        mode = _apply_form_login(session, base_url)
        if mode == "form":
            return "form"

    if getattr(config, "AUTH_COOKIE", ""):
        return _apply_cookie(session)

    print("  [-] 未使用鉴权（匿名访问）")
    return "none"


def _apply_form_login(session, base_url):
    login_url = _find_login_url(session, base_url)
    if not login_url:
        print("  [-] 未探测到登录表单，跳过表单登录")
        return "none"

    print(f"[*] 探测到登录表单: {login_url}")

    # ★ 登录阶段：跳过会话失效判断
    page_res, _ = safe_request(session, "GET", login_url,
                               force_security_low=False,
                               skip_session_check=True)
    if not page_res:
        print("  [!] 登录页打开失败")
        return "none"

    hidden_fields = _extract_hidden_fields(read_text(page_res))
    if hidden_fields:
        print(f"  [~] 检测到隐藏字段（CSRF token 等）: {list(hidden_fields.keys())}")
    else:
        print("  [~] 登录页无隐藏字段（无 CSRF token）")

    user_field = getattr(config, "AUTH_FORM_USERNAME_FIELD", "username")
    pass_field = getattr(config, "AUTH_FORM_PASSWORD_FIELD", "password")

    page_text = read_text(page_res)
    for mt in re.finditer(r'<input[^>]*type=["\']text["\'][^>]*name=["\']([^"\']+)["\']',
                          page_text, re.I):
        cand = mt.group(1)
        if cand.lower() not in ("search", "q"):
            user_field = cand
            break
    for mt in re.finditer(r'<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']+)["\']',
                          page_text, re.I):
        pass_field = mt.group(1)
        break

    payload = {
        user_field: getattr(config, "AUTH_FORM_USERNAME", ""),
        pass_field: getattr(config, "AUTH_FORM_PASSWORD", ""),
    }
    payload.update(dict(getattr(config, "AUTH_FORM_EXTRA", {}) or {}))
    payload.update(hidden_fields)

    print(f"  [~] 即将提交登录表单字段: {list(payload.keys())}")

    cookie_before = {c.name: c.value for c in session.cookies}
    # ★ 登录 POST 阶段：跳过会话失效判断
    res, _ = safe_request(session, "POST", login_url, data=payload,
                          force_security_low=False,
                          skip_session_check=True)
    if not res:
        print("  [!] 登录请求失败（无响应）")
        return "none"

    cookie_after = {c.name: c.value for c in session.cookies}
    updated = (cookie_before != cookie_after)
    final_url = res.url or ""
    text_low = read_text(res).lower()

    print(f"  [~] 登录响应: status={res.status_code} len={len(text_low)} "
          f"final_url={final_url}")

    fail_hit = None
    for hint in _LOGIN_FAIL_HINTS:
        if hint in text_low:
            fail_hit = hint
            break
    if fail_hit:
        print(f"  [!] 登录失败：页面出现提示“{fail_hit}”")
        logger.warn("AUTH", f"登录失败：{'login failed'}")
        return "none"

    if updated:
        print("  [+] 登录信号: cookie 已更新")
    if "logout" in text_low:
        print("  [+] 登录信号: 页面出现 logout 链接")

    if _is_authenticated(session, base_url):
        print("  [+] 登录成功：首页已可访问")
        print("  [+] 自动鉴权采用: 表单登录")
        return "form"

    if _looks_like_login(res):
        print("  [!] 登录后仍停留在登录页（token 无效或账号密码错误）")
        return "none"

    print("  [!] 登录未检测到成功信号，继续以匿名方式扫描")
    return "none"


def _find_login_url(session, base_url):
    configured = getattr(config, "AUTH_FORM_LOGIN_URL", "")
    if configured:
        return configured if configured.startswith("http") else urljoin(base_url, configured)

    for cand in getattr(config, "LOGIN_PATH_CANDIDATES", []):
        url = urljoin(base_url, cand)
        # ★ 探测登录路径：跳过会话失效判断
        res, _ = safe_request(session, "GET", url,
                              force_security_low=False,
                              skip_session_check=True)
        if not res:
            continue
        text = read_text(res)
        if "<form" in text and re.search(r'type=["\']?password', text, re.I):
            return url
    return None


def _detect_dvwa_security(session, base_url):
    sec_url = urljoin(base_url, "security.php")
    # ★ DVWA 探测：跳过会话失效判断
    res, _ = safe_request(session, "GET", sec_url,
                          force_security_low=False,
                          skip_session_check=True)
    if not res:
        return False
    text = read_text(res)
    return ('name="security"' in text) and ("seclev_submit" in text)


def set_target_level(session, base_url, level="low"):
    session.cookies.update({"security": level})

    sec_url = urljoin(base_url, "security.php")
    # ★ 难度设置：跳过会话失效判断
    res, _ = safe_request(session, "GET", sec_url,
                          force_security_low=False,
                          skip_session_check=True)
    if res and 'name="security"' in read_text(res) and "seclev_submit" in read_text(res):
        hidden = _extract_hidden_fields(read_text(res))
        payload = {"security": level, "seclev_submit": "Submit"}
        payload.update(hidden)
        safe_request(session, "POST", sec_url, data=payload,
                     force_security_low=False,
                     skip_session_check=True)
        session.cookies.update({"security": level})

    print(f"  [+] 已设置 security cookie = {level.upper()}")
    return True