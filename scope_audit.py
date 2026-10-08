# -*- coding: utf-8 -*-
"""scope_audit.py — 把"上游自证"从**纯信任**变成**可抽样、可撤销、可量化**的机制

═══════════════════════════════════════════════════════════════════════════
背景（第五轮红队实测的**可达漏判**）
═══════════════════════════════════════════════════════════════════════════
契约 v1.2 用 `consent_scope` 打破"真无个人信息"与"信号字段被改名"的不可区分性。
但 `consent_scope: []` 是**上游的自称**。红队给出 100% 成功的最小复现：

    stack: 未收录 SDK（无语义提示）
    params: {"consent_scope": [], "event": "13800138000", "ts": 1712345678}
    → 修复前：自动判 NONE||COMPLIANT、needs_review=False   ← **真漏判**

`rules_engine` 已加两道**内容级**阻断（空声明的值级 PII 形态印证、
已识别类型与声明矛盾）。但它们都是**静态规则**：攻击者只要把值编码得更隐蔽
（多层编码、自定义字符集）或换用未知形态，静态规则就可能再次失守。

本模块提供**两道与"内容"正交的机制**，二者都不依赖"我们猜得到攻击形态"：

  1. **确定性抽样审计（不可重投）**
     以服务端密钥 `PC_SCOPE_AUDIT_KEY` 对请求做 HMAC，按概率 p 强制转人工。
     · 上游**无法**通过重投/改随机种子来躲开（抽样由服务端密钥决定，上游不可预测）。
     · 漏判被**上界**约束：每条"空声明"逃逸路径最多只能稳定通过 (1−p) 的比例，
       即漏判数 ≤ 违约数 × (1−p)；抽到的那 p 还能**估计**上游的违约率。
     · 默认关闭（p=0）；`PC_SCOPE_CONTRACT=1` 且未配密钥时由 C10 记 `!!`
       —— 即"只敢开契约、不敢配审计"的部署必须**响亮**。
     工程注：若想把界做**硬**（不是期望），可用 Jackson 的"从两端抽"技巧，
       把选择集大小 |S| 提升到 n：Pr[漏掉 ≥k 个坏项] ≤ (1−p)^{n−k}。

  2. **撤销回路（持久化）**
     一旦**任何**检测器（值级形态、声明矛盾）在本条请求上触发，就把该上游的
     **声明指纹**记入 `models/scope_revoked.json`；此后凡指纹相同者**一律**转人工。
     这给了系统"一次被骗、永久不信任该形态"的能力 —— 而抽样本身**只有检出**、
     不撤销的话只能把漏判降到 (1−p)，无法收敛到 0。
     存储用单文件 JSON，不依赖数据库/Redis，进程重启后依然有效。

诚实边界
------------------------------------------------
- 抽样**不能**把漏判降到 0（除非 p=1 且撤销已收敛）；它是**泄漏上界 + 检出手段**。
- 撤销的粒度是"声明指纹"，上游**轮换形态**（改键名/改平台标记）即可绕过 ⇒
  它拦的是"同一形态的复发"，不是"同一个攻击者"。
- 因此本模块是**纵深防御**，不是保证来源。保证仍来自 `calibrate.py` 的 CRC 校准。
"""
import hashlib
import hmac
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
REVOKE_PATH_DEFAULT = os.path.join(HERE, "models", "scope_revoked.json")

# 【第六轮对抗复核 V6】旧正则要求键名以字母/下划线开头，**数字开头的键名**
# （`"138":"…"` 这类键/值分片形态）被排除在指纹外 ⇒ 与 docstring"键名集合"语义
# 不符，且对分片家族的撤销粒度失真（方向是多撤销，保守，但仍应语义正确）。
# 放宽为"任意非空键名"（JSON 键必为字符串，`[^"]+` 已足够）。
_KEYS_RE = re.compile(r'"([^"]+)"\s*:')
_PLAT_RE = re.compile(r"\[platform=(\w+)\]", re.I)


AUDIT_PERMILLE_DEFAULT = 50        # 50‰ = 5% 抽样（密钥已配时的缺省值）
AUDIT_PERMILLE_MIN = 50            # env 只能**收紧**到 ≥50‰；放松须 PC_ALLOW_RELAX=1


def audit_key():
    """服务端审计密钥（**必须保密**：上游知道它就能预测抽样、从而选择性逃避）。"""
    return os.environ.get("PC_SCOPE_AUDIT_KEY") or ""


def _allow_relax():
    """全项目**唯一**的放松闸门（与 calib_runtime 同一语义）。"""
    return os.environ.get("PC_ALLOW_RELAX") == "1"


def audit_permille():
    """抽样率（千分比）。env 只能**收紧**（≥AUDIT_PERMILLE_MIN）。

    红队 P1 同源问题：`PC_SCOPE_AUDIT_PERMILLE=0` 可把抽样率归 0，
    于是"抽样 + 熔断"**同时静默失效**，漏判回到 100%。
    故与 λ 一样，采样率也**只能收紧不能放松**，除非显式 PC_ALLOW_RELAX=1。
    """
    raw = os.environ.get("PC_SCOPE_AUDIT_PERMILLE")
    if raw is None:
        return AUDIT_PERMILLE_DEFAULT
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return AUDIT_PERMILLE_DEFAULT
    if v >= AUDIT_PERMILLE_MIN or _allow_relax():
        return max(v, 0)
    return AUDIT_PERMILLE_DEFAULT


def audit_p():
    """抽样概率 p ∈ [0,1]。"""
    return min(max(audit_permille() / 1000.0, 0.0), 1.0)


def status():
    """安全网健康状态（比照 `rules_engine.guard_status`：**绝不静默降级**）。

    没有密钥时 `available=False` —— 由 `rules_engine` 据此对"空声明"fail-closed，
    并由 `check_runtime.py` 在启用契约时记 `!!`。这正是 P0-A 的教训：
    **安全网失效必须响亮**，不能表现成"运行正常但其实没在防"。
    """
    pm = audit_permille()
    p = audit_p()
    has_key = bool(audit_key())
    if has_key and pm > 0:
        avail, reason = True, "ok"
    elif _allow_relax():
        avail, reason = False, "disabled_by_PC_ALLOW_RELAX"
    elif not has_key:
        avail, reason = False, "missing_PC_SCOPE_AUDIT_KEY"
    else:
        avail, reason = False, "sampling_rate_zero"
    return {
        "available": avail, "reason": reason, "key_configured": has_key,
        "permille": pm, "p": p,
        "enabled": avail,
        "revoked_count": len(_load()),
        "revoke_path": _path(),
        # 空声明逃逸路径的**泄漏上界**（期望口径，见模块 docstring）
        "max_escape_ratio": (1.0 - p) if avail else 1.0,
        "note": ("抽样把空声明的漏判限制在 (1-p) 比例内，并能检出上游违约率；"
                 "撤销回路负责收敛。二者都不能替代 CRC 保证。"),
    }


def fingerprint(text):
    """声明指纹：`平台 + 参数键名集合（排序）+ 是否声明空`。

    刻意**不含值**：指纹要刻画"上游这一种声明形态"，值会变但形态稳定。
    这也意味着上游**轮换键名即可换指纹** —— 已知局限，见模块 docstring。
    """
    plat = (_PLAT_RE.search(text).group(1).lower() if _PLAT_RE.search(text) else "?")
    keys = sorted(set(_KEYS_RE.findall(text.split("params:", 1)[-1])))
    empty = bool(re.search(r'"consent_scope"\s*:\s*\[\s*\]', text, re.I))
    return "%s|empty=%d|%s" % (plat, 1 if empty else 0, ",".join(keys[:24]))


def selected_for_audit(text, p=None):
    """确定性抽样：由服务端密钥决定，上游不可预测、不可重投改善。

    用 HMAC(key, fingerprint) 的前 4 字节做均匀映射到 [0,1)。
    """
    key = audit_key()
    pp = audit_p() if p is None else p
    if not key or pp <= 0.0:
        return False
    if pp >= 1.0:
        return True
    d = hmac.new(key.encode("utf-8", "ignore"),
                 fingerprint(text).encode("utf-8", "ignore"), hashlib.sha256).digest()
    u = int.from_bytes(d[:4], "big") / float(1 << 32)
    return u < pp


# ── 撤销回路（持久化，进程重启有效）─────────────────────────────────────────
_REVOKED = None


def _path():
    return os.environ.get("PC_SCOPE_REVOKE_PATH") or REVOKE_PATH_DEFAULT


def _load():
    global _REVOKED
    if _REVOKED is not None:
        return _REVOKED
    p = _path()
    _REVOKED = set()
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f:
                obj = json.load(f)
            if isinstance(obj, list):
                _REVOKED = set(str(x) for x in obj)
            elif isinstance(obj, dict) and isinstance(obj.get("revoked"), list):
                _REVOKED = set(str(x) for x in obj["revoked"])
        except Exception:                                  # noqa: BLE001
            _REVOKED = set()
    return _REVOKED


def is_revoked(text_or_fp):
    fp = text_or_fp if "|empty=" in str(text_or_fp) else fingerprint(text_or_fp)
    return fp in _load()


def revoke(text_or_fp, reason=""):
    """把该声明指纹永久拉黑（写盘）。返回是否为**新增**撤销。

    生产卫生（与"红队不得污染生产"同源）：**审计未启用**（未配 `PC_SCOPE_AUDIT_KEY`）
    且未显式指定 `PC_SCOPE_REVOKE_PATH` 时**不落盘**，只返回 False。
    这样评测 / 红队 / 压力测试运行不会把攻击形态写进生产的 `models/scope_revoked.json`。
    需要持久化的部署配 `PC_SCOPE_AUDIT_KEY` 即可；测试可显式设 `PC_SCOPE_REVOKE_PATH`。

    注意：`is_revoked()` **始终**读取（不设门控）—— 已部署的撤销表必须继续生效。
    """
    if not audit_key() and not os.environ.get("PC_SCOPE_REVOKE_PATH"):
        return False
    fp = text_or_fp if "|empty=" in str(text_or_fp) else fingerprint(text_or_fp)
    s = _load()
    if fp in s:
        return False
    s.add(fp)
    p = _path()
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(sorted(s), f, ensure_ascii=False, indent=1)
        os.replace(tmp, p)
    except Exception:                                      # noqa: BLE001
        pass
    return True


def reload():
    global _REVOKED
    _REVOKED = None
    return _load()


if __name__ == "__main__":
    import pprint
    os.environ.setdefault("PC_SCOPE_AUDIT_KEY", "demo-key")
    os.environ.setdefault("PC_SCOPE_AUDIT_PERMILLE", "100")
    t = ('[platform=android]\nstack: com.demo.X.y(F.java:1)\n'
         'params: {"consent_scope":[],"event":"13800138000"}')
    print("== 默认（密钥已配、100‰）==")
    pprint.pprint({"status": status(), "fingerprint": fingerprint(t),
                   "selected": selected_for_audit(t)})
    # 收紧测试：env 想归 0，应被抬回 DEFAULT(50‰)，且不因 PC_ALLOW_RELAX 缺席而放行
    os.environ["PC_SCOPE_AUDIT_PERMILLE"] = "0"
    print("== PC_SCOPE_AUDIT_PERMILLE=0（无 PC_ALLOW_RELAX，应被拒/抬回）==")
    print("permille =", audit_permille(), "(期望 50)")
    os.environ["PC_ALLOW_RELAX"] = "1"
    print("== + PC_ALLOW_RELAX=1（显式放松，应生效）==")
    pprint.pprint({"permille": audit_permille(), "status": status()})
