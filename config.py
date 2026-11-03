# config.py
"""
全局配置层（通用 Web 扫描器 · v1.2.3 盲注 & 限流 & 二次校验 & 路径字典爬虫）。

⚠️ 合规声明：
    本项目仅用于【授权靶场/自有系统】的教学与安全测试。
    请勿对未授权目标发起扫描，否则可能违反《网络安全法》等法律法规。

v1.2.3 新增：
    - BLIND_SQLI_BOOL_LEN_DIFF 从 100 降到 50（Pikachu 布尔盲注差异小）
    - get_fix_suggestion 增加 SQL 盲注/布尔盲注匹配

v1.2.2 新增：
    - 非法 URL 协议过滤
    - RETRY_ON_STATUS 去掉 500
    - CRAWLER_PATH_SEEDS 已知漏洞路径字典
"""

# =====================================================================
# 调试开关
# =====================================================================
DEBUG_SQLI = False
DEBUG_ENGINE = False
DEBUG_VERBOSE = False

# =====================================================================
# 日志分级
# =====================================================================
LOG_LEVEL = "INFO"
LOG_KEEP_LINES = 800

# =====================================================================
# 爬虫
# =====================================================================
BLACKLIST = ["logout", "signout", "exit", "setup", "phpinfo"]
IGNORE_SUFFIX = [
    ".md", ".txt", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg",
    ".ico", ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".rar", ".tar", ".gz", ".7z", ".mp4", ".mp3", ".avi",
    ".bmp", ".webp", ".map",
    ".dist", ".bak", ".old", ".orig", ".swp", ".swo",
]
IGNORE_MIME_PREFIX = (
    "image/", "font/", "audio/", "video/", "text/css", "text/javascript",
    "application/javascript", "application/x-javascript",
)
CRAWL_MAX_PAGES = 80
CRAWL_MAX_DEPTH = 3
FAILED_URL_MAX = 3
PARSE_ROBOTS_TXT = True

# =====================================================================
# 已知漏洞路径种子字典
# =====================================================================
CRAWLER_PATH_SEEDS = [
    # ---- Pikachu：分类目录 ----
    "/vul/sqli/", "/vul/xss/", "/vul/rce/", "/vul/fileinclude/",
    "/vul/ssrf/", "/vul/xxe/", "/vul/dir/", "/vul/urlredirect/",
    "/vul/unserilization/", "/vul/overpermission/",
    "/vul/csrf/", "/vul/unsafedownload/", "/vul/unsafeupload/",
    "/vul/brute/", "/vul/bac/",
    # ---- Pikachu：已知具体文件 ----
    "/vul/sqli/sqli_str.php",
    "/vul/sqli/sqli_id.php",
    "/vul/sqli/sqli_blind_b.php",
    "/vul/sqli/sqli_blind_t.php",
    "/vul/sqli/sqli_search.php",
    "/vul/sqli/sqli_x.php",
    # ---- DVWA ----
    "/vulnerabilities/sqli/", "/vulnerabilities/sqli_blind/",
    "/vulnerabilities/xss_r/", "/vulnerabilities/xss_s/",
    "/vulnerabilities/xss_d/", "/vulnerabilities/exec/",
    "/vulnerabilities/fi/", "/vulnerabilities/brute/",
    "/vulnerabilities/upload/", "/vulnerabilities/csrf/",
    # ---- bWAPP ----
    "/sqli_1.php", "/sqli_2.php", "/sqli_3.php", "/sqli_4.php",
    "/xss_get.php", "/xss_post.php", "/xss_stored_1.php",
    "/commandi.php", "/commandi_blind.php",
    "/lfi.php", "/rfi.php",
    # ---- 通用 ----
    "/sqli/", "/xss/", "/rce/", "/cmd/", "/ssrf/", "/xxe/",
]

# =====================================================================
# 并发与限速
# =====================================================================
THREAD_WORKERS = 3
MAX_CONCURRENT = 1
REQUEST_INTERVAL = 0.08
REQUESTS_PER_SECOND = 20
REQUEST_TIMEOUT = 20
FOLLOW_REDIRECTS = True

GLOBAL_RATE_LIMIT = 20
RATE_LIMIT_PER_HOST = 5
MIN_REQUEST_INTERVAL = 0.05

# =====================================================================
# 慢页自动跳过 + 全局自动降速
# =====================================================================
SLOW_URL_SKIP_ENABLED = True
SLOW_URL_SKIP_THRESHOLD = 3
SLOWDOWN_AUTO = True
SLOWDOWN_MAX_INTERVAL = 2.0

# =====================================================================
# 会话失效主动检测
# =====================================================================
SESSION_DEAD_HINTS = (
    "please log in", "please login", "you must login", "you must log in",
    "请先登录", "登录已失效", "登录超时", "会话已过期",
    "session expired", "session has expired",
    "not logged in", "not authenticated",
)
SESSION_DEAD_REDIRECT_PATHS = ("login", "signin", "sign-in")
SESSION_DEAD_CHECK = True
SESSION_DEAD_SAFE_URL_PATTERNS = (
    "login", "signin", "sign-in", "sign_in", "signout", "logout",
    "/auth/", "action=login", "action=signin", "?login", "&login",
)

# =====================================================================
# 只读模式
# =====================================================================
READ_ONLY_MODE = True
DANGEROUS_PARAM_HINTS = (
    "delete", "del", "remove", "drop", "destroy", "truncate",
    "logout", "signout", "signin", "login", "exit", "quit",
    "shutdown", "reboot", "reset", "clear", "update", "edit",
)
DANGEROUS_PATH_HINTS = (
    "/delete", "/remove", "/drop", "/reset", "/del", "/clear",
    "/destroy", "?action=delete", "?action=drop",
)

# =====================================================================
# 请求重试
# =====================================================================
RETRY_TIMES = 1
RETRY_INTERVAL = 0.4
RETRY_ON_STATUS = (502, 503, 504)

# =====================================================================
# 响应编码
# =====================================================================
FORCE_TEXT_DECODE = True

# =====================================================================
# 网络安全
# =====================================================================
VERIFY_TLS = False
USE_PROXY = False
PROXY_URL = "http://127.0.0.1:8080"
DOMAIN_BLACKLIST = [".gov", ".gov.cn", ".edu", ".edu.cn", ".bank", ".mil"]

# =====================================================================
# 鉴权
# =====================================================================
AUTH_MODE = "auto"
AUTH_COOKIE = ""
AUTH_BEARER_TOKEN = ""
AUTH_FORM_USERNAME = ""
AUTH_FORM_PASSWORD = ""
AUTH_FORM_LOGIN_URL = ""
AUTH_FORM_USERNAME_FIELD = "username"
AUTH_FORM_PASSWORD_FIELD = "password"
AUTH_FORM_EXTRA = {"Login": "Login"}
LOGIN_PATH_CANDIDATES = [
    "login", "login.php", "login.html", "signin", "signin.php",
    "admin", "admin/login", "wp-login.php", "user/login", "account/login",
]
LOGIN_SUCCESS_HINTS = [
    "dashboard", "welcome", "logout", "sign out", "my account",
    "profile", "控制台", "退出", "欢迎",
]

# =====================================================================
# 会话心跳
# =====================================================================
SESSION_HEARTBEAT_EVERY = 30
SESSION_HEARTBEAT_SLEEP = 0.0

# =====================================================================
# 检测阈值
# =====================================================================
XSS_CHECK_PARSE = True
ENABLE_PAYLOAD_MUTATE = False
BYPASS_VARIANTS = ("url", "url2", "case", "comment")

# ---- 二次校验 ----
VERIFY_ROUNDS_XSS = 2
VERIFY_ROUNDS_SQLI = 2
VERIFY_ROUNDS_CMD = 3

# ---- JSON 参数检测 ----
ENABLE_JSON_INJECT = True

# ---- SQL 报错关键字 ----
SQLI_ERROR_KEYWORDS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "warning: mysqli",
    "warning: mysql_fetch",
    "warning: mysql_num_rows",
    "warning: mysql_result",
    "warning: pg_",
    "postgresql query failed",
    "sqlite error",
    "ora-00933", "ora-00921", "ora-01756",
    "microsoft odbc sql server driver",
    "system.data.sqlclient",
    "mysqli_sql_exception",
]
SQLI_ERROR_WEAK_KEYWORDS = [
    "syntax error", "sql syntax", "database error", "mysql error", "odbc",
]
SQLI_HARMLESS_PAYLOAD = "1"
SQLI_SLEEP_SECONDS = 5
SQLI_DELAY_THRESHOLD = 4.0
SQLI_BASELINE_ROUNDS = 2
SQLI_BOOL_DIFF_RATIO = 0.15
SQLI_LEN_DIFF_THRESHOLD = 200

# ---- SQL 盲注（独立开关 + 独立超时）----
ENABLE_BLIND_SQLI = True
BLIND_SQLI_TIMEOUT = 15
BLIND_SQLI_SLEEP = 5
BLIND_SQLI_DELAY_THRESHOLD = 4.0
BLIND_SQLI_BOOL_LEN_DIFF = 50         # ★ v1.2.3：100→50，适配 Pikachu
BLIND_SQLI_BOOL_CONFIDENCE = 75
BLIND_SQLI_TIME_CONFIDENCE = 55

# ---- CMD 跨平台 payload ----
CMD_PAYLOADS_LINUX = [ ";sleep 3;", "|sleep 3", "&&sleep 3" ]
CMD_PAYLOADS_WIN = [
    "|ping -n 4 127.0.0.1",
    "&ping -n 4 127.0.0.1",
    "&&ping -n 4 127.0.0.1",
]
CMD_WIN_DELAY_THRESHOLD = 2.5
CMD_LINUX_SLEEP = 3
CMD_LINUX_DELAY_THRESHOLD = 2.0
CMD_SLEEP_SECONDS = 3
CMD_DELAY_THRESHOLD = 2.0
CMD_PARAM_HINTS = (
    "ip", "host", "cmd", "command", "exec", "target",
    "query", "domain", "address", "addr", "ping",
    "url", "search", "q", "file", "path", "dir", "name", "site",
)

# =====================================================================
# 证据快照 / 报告
# =====================================================================
EVIDENCE_LEN = 400
REQUEST_SNAPSHOT_LEN = 400
EVIDENCE_STORE_FULL_REQUEST = True
EVIDENCE_RESPONSE_MAX = 2000

# =====================================================================
# 白名单
# =====================================================================
SKIP_INJECT_PATTERNS = [
    "instructions.php", "about.php", "setup.php",
    "/docs/", "/help/", "/readme", "/manual/", "/faq/",
]

# =====================================================================
# 报告
# =====================================================================
REPORT_CSV_FILENAME = "scan_report.csv"
REPORT_HTML_FILENAME = "scan_report.html"
REPORT_JSON_FILENAME = "scan_report.json"

# =====================================================================
# 修复建议词库
# =====================================================================
FIX_SUGGESTIONS = {
    "SQL 注入": (
        "1) 使用参数化查询（PreparedStatement），禁止 SQL 字符串拼接；"
        "2) 对数字型参数做强类型转换（intval / parseInt）；"
        "3) 使用 ORM 框架（SQLAlchemy / MyBatis）减少手写 SQL；"
        "4) 数据库账号最小权限；"
        "5) 关闭 SQL 报错详情返回（不返回堆栈）。"
    ),
    "XSS": (
        "1) 输出转义：HTML 上下文用 htmlspecialchars，JS 上下文用 JSON 编码；"
        "2) 输入过滤：对富文本用白名单过滤（DOMPurify）；"
        "3) 设置 CSP 头（Content-Security-Policy）；"
        "4) Cookie 设置 HttpOnly 防 JS 读取；"
        "5) 避免 innerHTML / document.write。"
    ),
    "命令注入": (
        "1) 禁止直接拼接用户输入到 shell 命令；"
        "2) 使用参数化调用（subprocess.run(list, shell=False)）；"
        "3) 输入白名单校验（IP / 域名用正则强校验）；"
        "4) 命令执行账号最小权限；"
        "5) 使用安全库（shlex.quote 谨慎使用）。"
    ),
    "JSON 注入": (
        "1) 服务端严格校验 JSON 字段类型；"
        "2) 使用 JSON Schema 校验请求结构；"
        "3) 对注入风险字段按类型做白名单校验；"
        "4) 输出端转义，避免 JSON 注入导致 XSS。"
    ),
}


def get_fix_suggestion(vuln_type):
    """
    按漏洞类型返回修复建议（模糊匹配）。
    v1.2.3：时间盲注/布尔盲注也走 SQL 修复建议。
    """
    t = (vuln_type or "").upper()
    if "SQL" in t:
        return FIX_SUGGESTIONS.get("SQL 注入", "")
    if "盲注" in t:
        return FIX_SUGGESTIONS.get("SQL 注入", "")
    if "XSS" in t:
        return FIX_SUGGESTIONS.get("XSS", "")
    if "命令" in t or "CMD" in t or "RCE" in t:
        return FIX_SUGGESTIONS.get("命令注入", "")
    if "JSON" in t:
        return FIX_SUGGESTIONS.get("JSON 注入", "")
    return "请参考 OWASP Top 10 对应条目的修复建议。"