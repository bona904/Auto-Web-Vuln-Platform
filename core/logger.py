# core/logger.py
"""
分级日志（内存环形缓冲 + 标准输出）。

⚠️ 合规声明：
    仅用于授权靶场/自有系统的安全测试。

用法：
    from core import logger
    logger.info("AUTH", "登录成功")
    logger.warn("CRAWL", "跳过慢页")
    logger.error("HTTP", "请求失败")

前端通过 /api/logs 轮询 snapshot() 实时展示。
"""

import time
import threading
from collections import deque

import config


_LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
_lock = threading.Lock()
_buffer = deque(maxlen=int(getattr(config, "LOG_KEEP_LINES", 800)))


def _should(level):
    cur = _LEVELS.get(getattr(config, "LOG_LEVEL", "INFO"), 20)
    return _LEVELS.get(level, 20) >= cur


def _push(level, tag, msg):
    entry = {
        "ts": time.strftime("%H:%M:%S"),
        "level": level,
        "tag": tag or "-",
        "msg": str(msg),
    }
    with _lock:
        _buffer.append(entry)
    # 终端同步打印（保留你原来的视觉体验）
    print(f"[{entry['ts']}][{level}][{tag}] {msg}")


def debug(tag, msg):
    if _should("DEBUG"):
        _push("DEBUG", tag, msg)


def info(tag, msg):
    if _should("INFO"):
        _push("INFO", tag, msg)


def warn(tag, msg):
    if _should("WARN"):
        _push("WARN", tag, msg)


def error(tag, msg):
    if _should("ERROR"):
        _push("ERROR", tag, msg)


def snapshot():
    with _lock:
        return list(_buffer)


def clear():
    with _lock:
        _buffer.clear()