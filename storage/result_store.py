# core/result_store.py
"""
结果存储层：内存去重 + 保留最强证据。

⚠️ 合规声明：
    仅用于授权靶场/自有系统的安全学习，禁止对未授权目标使用。

去重 key：类型|URL|参数（同一注入点的同类漏洞只保留一条最强）
保留规则：置信度高者优先；相同则保留最早一条（避免重复覆盖证据）。
"""

import re
from urllib.parse import urlparse, urlunparse


def _norm_url(url):
    try:
        p = urlparse(url or "")
        return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))
    except Exception:
        return url or ""


def _key(f):
    return (f.get("类型", ""),
            _norm_url(f.get("URL", "")),
            f.get("参数", ""))


class ResultStore:
    def __init__(self):
        self._items = {}   # key -> finding

    def add(self, finding):
        if not finding:
            return
        k = _key(finding)
        old = self._items.get(k)
        if old is None:
            self._items[k] = finding
        else:
            try:
                if int(finding.get("置信度", 0)) > int(old.get("置信度", 0)):
                    self._items[k] = finding
            except Exception:
                pass

    def add_many(self, findings):
        for f in findings or []:
            self.add(f)

    def unique(self):
        """返回去重后列表，按风险等级(高→中→低)排序。"""
        order = {"高": 0, "中": 1, "低": 2}
        items = list(self._items.values())
        items.sort(key=lambda f: (
            order.get(f.get("风险等级", "低"), 3),
            -int(f.get("置信度", 0)),
        ))
        return items