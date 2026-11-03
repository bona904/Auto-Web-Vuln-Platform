# core/detectors.py
"""
漏洞检测层（v1.2.3：盲注命中上报修复 + 布尔盲注兼容 Pikachu）。

v1.2.3 改动：
    - _sqli_time_based：命中必打 [BLIND-HIT] + logger.info("FIND")
    - _sqli_boolean_blind：适配 Pikachu（vince' AND 1=1# 等 payload）
    - 布尔盲注特征词放宽（you are in / not in）
    - BLIND_SQLI_BOOL_LEN_DIFF 下降至 50（Pikachu 差异小）

历史能力：
    - SQL 报错注入（三重判定 + 二次校验）
    - SQL 时间盲注（独立超时）
    - SQL 布尔盲注（三条件两命中）
    - XSS（反射/存储/Header，DOM 上下文）
    - CMD 跨平台（Linux sleep / Windows ping）
"""

import re
import time
from bs4 import BeautifulSoup

import config
from core.http_client import (
    safe_request, get_stealth_headers, mutate_payload, read_text,
)
from core.payloads import PAYLOADS, XSS_MARKER
from core import logger


# =====================================================================
# 公共
# =====================================================================
def _is_dangerous_param(param):
    if not getattr(config, "READ_ONLY_MODE", True):
        return False
    p = (param or "").lower()
    return any(h in p for h in getattr(config, "DANGEROUS_PARAM_HINTS", ()))


def _is_dangerous_url(url):
    if not getattr(config, "READ_ONLY_MODE", True):
        return False
    low = (url or "").lower()
    return any(h in low for h in getattr(config, "DANGEROUS_PATH_HINTS", ()))


def _clean_data(data, exclude_param=None):
    ex = (exclude_param or "").lower()
    out = {}
    for k, v in data.items():
        kl = k.lower()
        if _is_dangerous_param(kl):
            continue
        if ex and kl == ex:
            continue
        out[k] = v
    return out


def _snap_request(method, url, payload, headers=None):
    lines = [f"{method} {url}"]
    if headers:
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(f"payload={payload!r}")
    return "\n".join(lines)


def _snap_response(res):
    try:
        text = read_text(res)
        return text[: getattr(config, "EVIDENCE_RESPONSE_MAX", 2000)]
    except Exception:
        return ""


def _make_finding(vuln_type, url, param, payload, evidence,
                  confidence, risk_level, verify_status,
                  request_snapshot="", response_snippet=""):
    """统一构造漏洞字典（自动带修复建议）。"""
    return {
        "类型": vuln_type,
        "URL": url,
        "参数": param,
        "Payload": payload,
        "证据": evidence,
        "置信度": confidence,
        "风险等级": risk_level,
        "验证状态": verify_status,
        "修复建议": config.get_fix_suggestion(vuln_type),
        "请求快照": request_snapshot,
        "响应片段": response_snippet,
    }


def _measure_baseline(session, url, clean_data, rounds=2, method="GET"):
    samples = []
    for _ in range(rounds):
        if method == "GET":
            res, elapsed = safe_request(session, "GET", url, params=clean_data)
        else:
            res, elapsed = safe_request(session, "POST", url, data=clean_data)
        if not res:
            return None
        samples.append(elapsed)
    return min(samples) if samples else None


# =====================================================================
# XSS
# =====================================================================
def _xss_context(res_text, marker):
    if marker not in res_text:
        return None
    soup = BeautifulSoup(res_text, "html.parser")
    for tag in soup.find_all("script"):
        if tag.string and marker in tag.string:
            return "executable"
    for tag in soup.find_all(True):
        for attr, val in tag.attrs.items():
            if isinstance(val, str) and marker in val:
                a = attr.lower()
                if a.startswith("on") or a in ("href", "src", "action", "formaction"):
                    return "executable"
    if "&lt;script" in res_text.lower() or "&lt;img" in res_text.lower():
        return "encoded"
    return "reflected"


def _record_xss(typ, url, param, payload, res):
    text = read_text(res)
    ctx = _xss_context(text, payload)
    snippet = text[: getattr(config, "EVIDENCE_LEN", 400)]
    req_snap = _snap_request("GET/POST", url, payload)
    if ctx == "executable":
        return _make_finding(typ, url, param, payload,
                             "payload 在可执行上下文（script/事件属性）中解析",
                             80, "高", "确认", req_snap, snippet)
    if ctx == "encoded":
        return _make_finding(typ, url, param, payload,
                             "payload 被转义回显（疑似 XSS，需人工确认）",
                             45, "中", "疑似", req_snap, snippet)
    return _make_finding(typ, url, param, payload,
                         "payload 原样文本回显（未确认可执行，疑似误报）",
                         60, "中", "疑似", req_snap, snippet)


def _verify_xss_twice(session, method, url, test_data, mutated):
    rounds = getattr(config, "VERIFY_ROUNDS_XSS", 2)
    for _ in range(rounds):
        if method == "GET":
            res, _ = safe_request(session, "GET", url, params=test_data)
        else:
            res, _ = safe_request(session, "POST", url, data=test_data)
        if not res or mutated not in read_text(res):
            return False
    return True


def test_xss(session, url, data, param):
    findings = []
    if _is_dangerous_param(param) or _is_dangerous_url(url):
        return findings

    clean = _clean_data(data, exclude_param=param)
    rounds = getattr(config, "VERIFY_ROUNDS_XSS", 2)

    for idx, payload in enumerate(PAYLOADS["XSS"]):
        mutated = mutate_payload(payload, index=idx)

        # --- GET 反射 ---
        td = dict(clean); td[param] = mutated
        if _verify_xss_twice(session, "GET", url, td, mutated):
            res, _ = safe_request(session, "GET", url, params=td)
            if res:
                findings.append(_record_xss("反射 XSS", url, param, mutated, res))
                return findings

        # --- POST 存储 ---
        td = dict(clean); td[param] = mutated
        if _verify_xss_twice(session, "POST", url, td, mutated):
            res, _ = safe_request(session, "POST", url, data=td)
            if res:
                findings.append(_record_xss("存储 XSS", url, param, mutated, res))
                return findings

        # --- Header XSS ---
        header_ok = True
        res_head = None
        for _ in range(rounds):
            headers = get_stealth_headers()
            headers["X-Forwarded-For"] = mutated
            res_head, _ = safe_request(session, "GET", url, headers=headers)
            if not res_head or mutated not in read_text(res_head):
                header_ok = False
                break
        if header_ok and res_head is not None:
            findings.append(_record_xss("Header XSS", url, "X-Forwarded-For",
                                        mutated, res_head))
            return findings
    return findings


# =====================================================================
# SQLi
# =====================================================================
def _match_keywords(text, kws):
    low = text.lower()
    for kw in kws:
        if kw.lower() in low:
            return kw
    return None


def _sqli_error_three_way(session, url, param, clean, method="GET"):
    findings = []
    if method == "GET":
        base_res, _ = safe_request(session, "GET", url, params=clean)
    else:
        base_res, _ = safe_request(session, "POST", url, data=clean)
    if not base_res:
        logger.debug("SQL", f"{method} {url} param={param} 基线失败")
        return findings

    base_text = read_text(base_res)
    base_len = len(base_text)
    base_strong = _match_keywords(base_text, config.SQLI_ERROR_KEYWORDS)
    base_weak = _match_keywords(base_text, config.SQLI_ERROR_WEAK_KEYWORDS)

    harmless_data = dict(clean)
    harmless_data[param] = config.SQLI_HARMLESS_PAYLOAD
    if method == "GET":
        harmless_res, _ = safe_request(session, "GET", url, params=harmless_data)
    else:
        harmless_res, _ = safe_request(session, "POST", url, data=harmless_data)
    harmless_text = read_text(harmless_res) if harmless_res else ""
    harmless_strong = _match_keywords(harmless_text, config.SQLI_ERROR_KEYWORDS)

    logger.debug("SQL", f"{method} {url} param={param} "
                        f"base_len={base_len} base_strong={base_strong}")

    verify_rounds = getattr(config, "VERIFY_ROUNDS_SQLI", 2)

    for ep in ["'", "\"", "')", "';", "\\"]:
        inj_data = dict(clean)
        inj_data[param] = ep
        if method == "GET":
            inj_res, _ = safe_request(session, "GET", url, params=inj_data)
        else:
            inj_res, _ = safe_request(session, "POST", url, data=inj_data)
        if not inj_res:
            continue

        text = read_text(inj_res)
        cur_len = len(text)
        kw_s = _match_keywords(text, config.SQLI_ERROR_KEYWORDS)
        kw_w = _match_keywords(text, config.SQLI_ERROR_WEAK_KEYWORDS)

        logger.debug("SQL", f"ep={ep!r} cur_len={cur_len} 强={kw_s} 弱={kw_w}")

        # ---- 强命中 → 二次校验后判"确认" ----
        if kw_s and not base_strong:
            confirmed = True
            for _ in range(max(0, verify_rounds - 1)):
                if method == "GET":
                    r2, _ = safe_request(session, "GET", url, params=inj_data)
                else:
                    r2, _ = safe_request(session, "POST", url, data=inj_data)
                if not r2 or not _match_keywords(read_text(r2), config.SQLI_ERROR_KEYWORDS):
                    confirmed = False
                    break
            if confirmed:
                findings.append(_make_finding(
                    f"{method} SQL 注入（报错）", url, param, ep,
                    f"命中强报错关键字: {kw_s}（基线无强命中，已二次校验）",
                    90, "高", "确认",
                    _snap_request(method, url, ep),
                    _snap_response(inj_res)))
                return findings
            else:
                findings.append(_make_finding(
                    f"{method} SQL 注入（报错·疑似）", url, param, ep,
                    f"强关键字 {kw_s} 复现失败，疑似偶发",
                    65, "中", "疑似",
                    _snap_request(method, url, ep),
                    _snap_response(inj_res)))
                return findings

        # ---- 弱线索 ----
        if kw_w and not base_weak and not base_strong:
            if abs(cur_len - base_len) >= config.SQLI_LEN_DIFF_THRESHOLD:
                findings.append(_make_finding(
                    f"{method} SQL 注入（弱线索）", url, param, ep,
                    f"命中弱报错关键字: {kw_w}，长度 {base_len}→{cur_len}",
                    55, "中", "疑似",
                    _snap_request(method, url, ep),
                    _snap_response(inj_res)))
                return findings

    return findings


# ---------------------------------------------------------------------
# SQL 时间盲注（v1.2.3：命中必打日志，避免被 try 静默吞）
# ---------------------------------------------------------------------
def _sqli_time_based(session, url, param, clean, method="GET"):
    findings = []
    if not getattr(config, "ENABLE_BLIND_SQLI", False):
        return findings

    sleep_s = int(getattr(config, "BLIND_SQLI_SLEEP", 5))
    threshold = float(getattr(config, "BLIND_SQLI_DELAY_THRESHOLD", 4.0))
    blind_timeout = int(getattr(config, "BLIND_SQLI_TIMEOUT", 15))
    confidence = int(getattr(config, "BLIND_SQLI_TIME_CONFIDENCE", 55))

    payloads = PAYLOADS.get("SQLI_TIME") or []
    if not payloads:
        print("  [BLIND-SKIP] PAYLOADS['SQLI_TIME'] 为空，跳过盲注")
        return findings

    base = _measure_baseline(session, url, clean, rounds=2, method=method)
    if base is None:
        print(f"  [BLIND-SKIP] {method} {param} 基线测量失败")
        return findings
    print(f"  [BLIND-BASE] {method} {param} baseline={base:.2f}s "
          f"sleep={sleep_s}s threshold={threshold}s timeout={blind_timeout}s")

    for idx, payload in enumerate(payloads):
        data = dict(clean)
        data[param] = payload
        if method == "GET":
            res, elapsed = safe_request(session, "GET", url, params=data,
                                        timeout=blind_timeout)
        else:
            res, elapsed = safe_request(session, "POST", url, data=data,
                                        timeout=blind_timeout)

        delay = elapsed - base
        status = "None" if res is None else f"HTTP {res.status_code}"
        print(f"  [BLIND] {method} {param} [{idx+1}/{len(payloads)}] "
              f"payload={payload!r} base={base:.2f}s cur={elapsed:.2f}s "
              f"delta={delay:.2f}s {status}")

        if res is None:
            continue

        cond1 = delay >= threshold
        cond2 = elapsed >= sleep_s * 0.6
        if cond1 and cond2:
            # ★ v1.2.3：先打日志再构造 finding，避免被异常静默
            print(f"  [BLIND-HIT] ✅ 命中！delta={delay:.2f}s")
            finding = _make_finding(
                "SQL 注入（时间盲注）", url, param, payload,
                f"时间延迟 基线 {base:.2f}s → 注入 {elapsed:.2f}s (delta={delay:.2f}s)",
                confidence, "高", "疑似",
                _snap_request(method, url, payload),
                f"elapsed={elapsed:.2f}s")
            findings.append(finding)
            logger.info("FIND", f"🎉 {method} SQL 时间盲注 | "
                                f"参数 {param} | 置信度 {confidence}")
            return findings

    return findings


# ---------------------------------------------------------------------
# SQL 布尔盲注（v1.2.3：适配 Pikachu，多 payload + 特征词）
# ---------------------------------------------------------------------
_TRUE_TOKENS = (
    "your username exists", "username exists", "you are in",
    "welcome", "success", "1 rows", "1 row",
    "存在", "登录成功",
)
_FALSE_TOKENS = (
    "not exists", "doesn't exist", "does not exist", "no result",
    "404", "error", "0 rows", "0 row", "invalid",
    "you are not in", "不存在", "错误", "失败",
)


def _sqli_boolean_blind(session, url, param, clean, method="GET"):
    """
    v1.2.3 布尔盲注：多 payload + 特征词 + 长度三条件，命中 2 条即报。
    适配 Pikachu（sqli_blind_b.php?name=xxx）：
      - TRUE:  vince' AND 1=1#
      - FALSE: vince' AND 1=2#
    页面响应特征：
      - TRUE:  "your username exists, You are in ..."
      - FALSE: "your username does not exist"
    """
    findings = []
    if not getattr(config, "ENABLE_BLIND_SQLI", False):
        return findings

    len_diff = int(getattr(config, "BLIND_SQLI_BOOL_LEN_DIFF", 50))
    confidence = int(getattr(config, "BLIND_SQLI_BOOL_CONFIDENCE", 75))

    if method == "GET":
        base_res, _ = safe_request(session, "GET", url, params=clean)
    else:
        base_res, _ = safe_request(session, "POST", url, data=clean)
    if not base_res:
        return findings
    base_text = read_text(base_res)
    base_low = base_text.lower()
    base_len = len(base_text)

    # ★ v1.2.3 扩充 payload，含 Pikachu 专用（vince' AND 1=1#）
    pairs = [
        # Pikachu 专用（sqli_blind_b，用户名已知 vince）
        ("vince' AND 1=1#",          "vince' AND 1=2#"),
        ("vince' AND '1'='1",         "vince' AND '1'='2"),
        ("vince' AND 1=1-- -",        "vince' AND 1=2-- -"),
        # 通用数字型
        ("1 AND 1=1",                 "1 AND 1=2"),
        ("1 AND 1=1#",                "1 AND 1=2#"),
        # 通用字符型
        ("1' AND '1'='1",             "1' AND '1'='2"),
        ("1' AND '1'='1'#",           "1' AND '1'='2'#"),
        ("1' OR '1'='1",              "1' OR '1'='2"),
    ]

    for true_p, false_p in pairs:
        t_data = dict(clean); t_data[param] = true_p
        f_data = dict(clean); f_data[param] = false_p

        if method == "GET":
            t_res, _ = safe_request(session, "GET", url, params=t_data)
            f_res, _ = safe_request(session, "GET", url, params=f_data)
        else:
            t_res, _ = safe_request(session, "POST", url, data=t_data)
            f_res, _ = safe_request(session, "POST", url, data=f_data)
        if not t_res or not f_res:
            continue

        t_text = read_text(t_res)
        f_text = read_text(f_res)
        t_low = t_text.lower()
        f_low = f_text.lower()

        # 条件 1：TRUE/FALSE 长度差
        cond_len = abs(len(t_text) - len(f_text)) >= len_diff

        # 条件 2：特征词切换（TRUE 命中真词 / FALSE 命中假词）
        t_true = any(tok in t_low for tok in _TRUE_TOKENS)
        t_false = any(tok in t_low for tok in _FALSE_TOKENS)
        f_true = any(tok in f_low for tok in _TRUE_TOKENS)
        f_false = any(tok in f_low for tok in _FALSE_TOKENS)
        cond_tok = (t_true and f_false) or (t_true and not f_true)

        # 条件 3：TRUE 与基线接近，FALSE 与基线远离
        cond_base = (abs(len(t_text) - base_len) <= 20
                     and abs(len(f_text) - base_len) >= len_diff)

        hits = sum([cond_len, cond_tok, cond_base])
        print(f"  [BLIND-B] {method} {param} true={true_p!r} "
              f"t_len={len(t_text)}B f_len={len(f_text)}B base={base_len}B "
              f"len={int(cond_len)} tok={int(cond_tok)} base_hit={int(cond_base)} "
              f"→ {hits}/3")

        if hits >= 2:
            print(f"  [BLIND-B-HIT] ✅ 布尔盲注命中 hits={hits}/3")
            finding = _make_finding(
                "SQL 注入（布尔盲注）", url, param,
                f"TRUE={true_p} / FALSE={false_p}",
                f"True长度={len(t_text)} / False长度={len(f_text)} / "
                f"基线={base_len} / 命中判定={hits}/3",
                confidence, "高", "疑似",
                _snap_request(method, url,
                              f"TRUE={true_p}\nFALSE={false_p}"),
                f"true_len={len(t_text)}, false_len={len(f_text)}")
            findings.append(finding)
            logger.info("FIND", f"🎉 {method} SQL 布尔盲注 | "
                                f"参数 {param} | 置信度 {confidence}")
            return findings

    return findings


def test_sqli(session, url, data, param):
    """
    v1.2.3 分流策略：
    1) 报错注入：GET → POST
    2) 时间盲注：GET
    3) 布尔盲注：GET
    """
    findings = []
    if _is_dangerous_param(param) or _is_dangerous_url(url):
        return findings
    clean = _clean_data(data, exclude_param=param)

    # 1) 报错注入
    for method in ("GET", "POST"):
        findings = _sqli_error_three_way(session, url, param, clean, method=method)
        if findings:
            return findings

    # 2) 时间盲注
    findings = _sqli_time_based(session, url, param, clean, method="GET")
    if findings:
        return findings

    # 3) 布尔盲注
    return _sqli_boolean_blind(session, url, param, clean, method="GET")


# =====================================================================
# CMD（跨平台：Linux sleep → Windows ping）
# =====================================================================
def _cmd_try_linux(session, url, clean, param, method):
    base = _measure_baseline(session, url, clean, rounds=2, method=method)
    if base is None:
        return None
    baseline_confirm = _measure_baseline(session, url, clean, rounds=1, method=method)
    if baseline_confirm is None or abs(baseline_confirm - base) >= 0.8:
        logger.debug("CMD", f"基线不稳定 base={base:.2f}s")
        return None

    for payload in PAYLOADS.get("CMD_LINUX", config.CMD_PAYLOADS_LINUX):
        data = dict(clean)
        data[param] = payload
        if method == "GET":
            res, elapsed = safe_request(session, "GET", url, params=data,
                                        timeout=config.REQUEST_TIMEOUT + 5)
        else:
            res, elapsed = safe_request(session, "POST", url, data=data,
                                        timeout=config.REQUEST_TIMEOUT + 5)
        if not res:
            continue
        logger.debug("CMD-L", f"{payload!r} base={base:.2f}s cur={elapsed:.2f}s")
        if elapsed - base >= config.CMD_LINUX_DELAY_THRESHOLD:
            return _make_finding(
                f"{method} 命令注入（Linux sleep）", url, param, payload,
                f"延时 基线 {base:.2f}s → 注入 {elapsed:.2f}s",
                95, "高", "确认",
                _snap_request(method, url, payload),
                f"elapsed={elapsed:.2f}s")
    return None


def _cmd_try_windows(session, url, clean, param, method):
    base = _measure_baseline(session, url, clean, rounds=2, method=method)
    if base is None:
        return None
    baseline_confirm = _measure_baseline(session, url, clean, rounds=1, method=method)
    if baseline_confirm is None or abs(baseline_confirm - base) >= 0.8:
        return None

    for payload in PAYLOADS.get("CMD_WIN", config.CMD_PAYLOADS_WIN):
        data = dict(clean)
        data[param] = payload
        if method == "GET":
            res, elapsed = safe_request(session, "GET", url, params=data,
                                        timeout=config.REQUEST_TIMEOUT + 6)
        else:
            res, elapsed = safe_request(session, "POST", url, data=data,
                                        timeout=config.REQUEST_TIMEOUT + 6)
        if not res:
            continue
        logger.debug("CMD-W", f"{payload!r} base={base:.2f}s cur={elapsed:.2f}s")
        if elapsed - base >= config.CMD_WIN_DELAY_THRESHOLD:
            return _make_finding(
                f"{method} 命令注入（Windows ping）", url, param, payload,
                f"延时 基线 {base:.2f}s → 注入 {elapsed:.2f}s",
                90, "高", "确认",
                _snap_request(method, url, payload),
                f"elapsed={elapsed:.2f}s")
    return None


def test_cmd(session, url, data, param):
    findings = []
    if _is_dangerous_param(param) or _is_dangerous_url(url):
        return findings

    pl = (param or "").lower()
    hints = getattr(config, "CMD_PARAM_HINTS", ())
    if not any(h in pl for h in hints):
        return findings

    clean = _clean_data(data, exclude_param=param)

    for method in ("GET", "POST"):
        f = _cmd_try_linux(session, url, clean, param, method)
        if f:
            findings.append(f)
            return findings
        f = _cmd_try_windows(session, url, clean, param, method)
        if f:
            findings.append(f)
            return findings
    return findings


# =====================================================================
# JSON 接口检测
# =====================================================================
def test_json(session, url):
    """针对 /api、/json、/graphql 端点做基础探测。"""
    findings = []
    if not getattr(config, "ENABLE_JSON_INJECT", True):
        return findings

    for payload in PAYLOADS.get("XSS", [])[:2]:
        data = {"q": payload}
        res, _ = safe_request(session, "JSON", url, data=data)
        if res and payload in read_text(res):
            findings.append(_make_finding(
                "JSON XSS", url, "q", payload,
                "JSON 接口回显 payload", 60, "中", "疑似",
                _snap_request("POST(JSON)", url, payload),
                _snap_response(res)))
            return findings
    return findings


# =====================================================================
# 检测器注册表
# =====================================================================
DETECTORS = [test_xss, test_sqli, test_cmd]