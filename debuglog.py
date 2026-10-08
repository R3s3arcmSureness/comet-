# -*- coding: utf-8 -*-
"""debuglog.py — 结构化调试日志（生产可观测性，**默认完全关闭**）

存在意义
--------
把"在别的服务器上跑真实数据 → 回传日志 → 据此定位瓶颈 → 再优化"变成可闭环的工程流程。
本模块就是这条闭环的**采集端**；配套的**分析端**是 `dbg_summary.py`。

三条硬纪律
----------
1. **默认零开销**：`PC_DEBUG_LOG` 未设或为 `0` → 所有函数立即 return，不建目录、不开文件、
   不做任何字符串处理，行为与加入本模块前**逐位一致**。日志故障也绝不冒泡影响判定
   （所有入口都包了 try/except，异常被吞并退化为"无日志"）。
2. **默认不落原始 PII**：默认 `safe` 级——**保留** API 名 / 类名 / 栈帧 / 字段名（这些是
   定位目录缺口与契约违约的必要信息），**抹掉**其值（手机号、身份证、token、长编码串…）。
   需要原始明文时须显式 `PC_DEBUG_LOG_LEVEL=full`（**明文可能含个人信息，仅限内网**）。
3. **可拼接、可聚合**：JSONL 一行一事件，带 `run`(本次运行 id) / `seq` / `sid`(样本 id) /
   单调耗时 `ms`，因此回传后可按阶段、按原因、按 API、按置信区间直接聚合。

环境变量
--------
    PC_DEBUG_LOG=1                 开启（默认关）
    PC_DEBUG_LOG_PATH=<路径>       默认 <项目>/logs/debug.jsonl
    PC_DEBUG_LOG_LEVEL=meta|safe|full   默认 safe
    PC_DEBUG_LOG_MAX_MB=<N>        单个文件上限，超出轮转为 .1（默认 64）
    PC_DEBUG_LOG_STDERR=1          同时把每样本一行摘要打到 stderr（交互排查方便）
    PC_DEBUG_LOG_KEEP_TEXT=1       等价于 LEVEL=safe，但**保留** params 的值骨架

事件类型（`ev` 字段）
--------------------
    run_start      本次运行开始（含 env 快照、后端选择结果、目录指纹）
    backend        后端选择/降级（哪一级可用、闸门值）
    sample         单条样本的完整判定轨迹（**主事件**）
    error          任一阶段的异常（含 traceback 摘要）
    run_end        本次运行汇总（计数、耗时、输出路径）

约定：本模块**只读**运行时状态，**不参与任何判定**。删除本模块不会改变任何结论。
"""
import os
import re
import sys
import json
import time
import hashlib
import platform
import threading
import datetime
import traceback

# ----------------------------------------------------------------- 配置
_TRUE = ("1", "true", "yes", "on")

HERE = os.path.dirname(os.path.abspath(__file__))


def _flag(name, default=False):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in _TRUE


def _env_int(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


ENABLED = _flag("PC_DEBUG_LOG", False)
LEVEL = (os.environ.get("PC_DEBUG_LOG_LEVEL") or "safe").strip().lower()
if LEVEL not in ("meta", "safe", "full"):
    LEVEL = "safe"
if _flag("PC_DEBUG_LOG_KEEP_TEXT") and LEVEL == "meta":
    LEVEL = "safe"
PATH = os.environ.get("PC_DEBUG_LOG_PATH") or os.path.join(HERE, "logs", "debug.jsonl")
MAX_BYTES = _env_int("PC_DEBUG_LOG_MAX_MB", 64) * 1024 * 1024
TO_STDERR = _flag("PC_DEBUG_LOG_STDERR", False)
# 单条事件的输入文本落盘上限（防止超大输入把日志撑爆）
TEXT_CAP = _env_int("PC_DEBUG_LOG_TEXT_CAP", 2000)

_lock = threading.Lock()
_state = {"fh": None, "seq": 0, "bytes": 0, "run": None, "t0": None,
          "path": None, "broken": False, "count": 0}

# ----------------------------------------------------------------- 脱敏
# 值**保留**的判定：短、字符集干净（标识符/枚举/数字 id/空串/布尔），才算"非敏感"
_KEEP_VALUE_RE = re.compile(r"^[A-Za-z0-9_\-\.\[\]{}\"]{0,24}$")
_LONG_DIGITS_RE = re.compile(r"\d{6,}")
# 与 L4a 外送脱敏同口径的强 PII 形态（命中即必然替换）
#
# ★ 单一事实来源：`debuglog.scrub_str`（脱敏）与 `dbg_summary.pii_scan`（回传前自查）
#   共用这一张表，避免出现"脱敏认为没问题、自查却告警"或反之的自相矛盾。
#
# ★ 边界必须用 `(?<!\d)…(?!\d)` 而非 `\b`：
#   真实日志里有 13 位毫秒时间戳（如 `1790220775396`），`\b1[3-9]\d{9}\b`
#   会把它的前 10 位误判成手机号（实测 160 处误报，且脱敏会**破坏**该字段）。
PII_PATTERNS = [
    ("手机号", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "<PHONE>"),
    ("身份证", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"), "<IDCARD>"),
    ("银行卡", re.compile(r"(?<!\d)\d{16,19}(?!\d)"), "<BANKCARD>"),
    # ★ 邮箱必须要求 `@` 前紧邻一个字母/数字/下划线：否则会把鸿蒙模块名
    #   `@ohos.identifier.oaid`、`-@ohos.payment` 这类**框架命名**误当邮箱抹掉，
    #   而那恰恰是我们要用来补目录的关键信息（实测 `[\w.+-]+@…` 会吃掉前导 `-`）。
    ("邮箱", re.compile(r"(?<![\w.+-])[A-Za-z0-9_][\w.+-]*@[A-Za-z0-9][\w-]*\.[A-Za-z]{2,}"),
     "<EMAIL>"),
    ("经纬度", re.compile(r"(?<!\d)\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}(?!\d)"), "<GEO>"),
    ("密钥", re.compile(r"(?i)\b(sk|ak|pk|ghp|xox[baprs])[-_][A-Za-z0-9_\-]{16,}"), "<KEY>"),
    ("凭证字段",
     re.compile(r"(?i)\b(token|access_token|sessionid|authorization)\s*[=:]\s*[^\s,}\"]+"),
     r"\1=<REDACTED>"),
    ("URL", re.compile(r"https?://[^\s\"']+"), "<URL>"),
    ("超长数字串", re.compile(r"(?<!\d)\d{20,}(?!\d)"), "<LONGNUM>"),
]
# 向后兼容别名
_PII_PATTERNS = [(pat, rep) for _n, pat, rep in PII_PATTERNS]
# 键名里含这些词 → 值必定脱敏（即使很短）
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(phone|mobile|tel|idcard|id_card|card|bank|email|mail|addr|address|"
    r"lat|lng|lon|gps|geo|token|secret|password|passwd|pwd|key|session|"
    r"imei|imsi|mac|oaid|aaid|idfa|androidid|openid|unionid|uid|userid|user_id)")


def _digest(s):
    return hashlib.sha1(str(s).encode("utf-8", "replace")).hexdigest()[:10]


_ALPHABET_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def looks_like_blob(s, minlen=20):
    """判断一个长串是否**像编码/密钥**（而不是驼峰类名、包路径、栈帧标识符）。

    这条判据被两处共用（单一事实来源）：
      ① `scrub_str` / `scrub_value` —— 决定 `safe` 级是否把它打码；
      ② `dbg_summary.pii_scan` —— 决定是否在回传前告警。
    纯字母的长串（`RIVERViewControllerBridgeLegacy`、`getLastKnownLocationInternal`）
    是**栈帧标识符**，是我们要保留的诊断信息，绝不能因为"长"就被当成密钥抹掉。

    ★ 为什么不用"信息熵阈值"判别（这是实测踩坑后的结论）：
      实测熵值 **无法** 区分二者 —— 标识符可达 4.16
      （`RIVERViewControllerBridgeLegacy`），而十六进制密钥低至 2.34。
      有效的判别量是**结构**：数字占比、字母表、base64 标记：
        · 数字占比：标识符 ≤ 0.04（`…V2` 只有一个 `2`），编码串 ≥ 0.10~0.5；
        · 含 `+`/`=`：base64 特征；
        · 全十六进制 + 长度 ≥ 32：哈希/密钥；
        · 以 `eyJ` 开头：base64 的 `{"`，即 JWT/JSON 载荷。
      含 `.`/`;`/空格等分隔符的片段一律**不判为编码串**（那是包路径或栈帧行）。

    `minlen` 的存在是为了覆盖 JWT 头这类**较短**的 base64 片段（如
    `eyJhbGciOiJIUzI1NiJ9`，20 字符）；凭据值用更小的阈值，文本流用较大阈值。
    """
    if len(s) < minlen:
        return False
    if not _ALPHABET_RE.match(s):                 # 含分隔符 ⇒ 包路径/栈帧行，非编码串
        return False
    if s.isdigit():                               # 长纯数字（订单号/设备号/时间戳串）
        return True
    if "=" in s or "+" in s:                      # base64 padding/特征
        return True
    if len(s) >= 32 and _HEX_RE.match(s):         # 十六进制哈希/密钥
        return True
    if s.startswith("eyJ"):                       # base64('{"') ⇒ JWT/JSON
        return True
    return sum(c.isdigit() for c in s) / len(s) >= 0.10


_BLOB_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")


def scrub_str(s, cap=None):
    """对**一个字符串**做安全化：强 PII 形态必替换 + 高熵/长数字串替换 + 截断。"""
    if not isinstance(s, str):
        s = str(s)
    out = s
    for pat, rep in _PII_PATTERNS:
        out = pat.sub(rep, out)
    # 长编码/密钥串 → 打码；但**长标识符（类名/栈帧）保留**
    out = _BLOB_RE.sub(
        lambda m: ("<blob:%d:%s>" % (len(m.group(0)), _digest(m.group(0)))
                   if looks_like_blob(m.group(0)) else m.group(0)), out)
    if cap and len(out) > cap:
        out = out[:cap] + "…<trunc:%d>" % len(s)
    return out


def scrub_value(v):
    """对 params 里**一个值**做安全化：短标识符/枚举保留原值，其余打码。"""
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, str):
        s = scrub_str(v, cap=120)
        if len(v) <= 24 and _KEEP_VALUE_RE.match(v) and not _LONG_DIGITS_RE.search(v) \
                and not looks_like_blob(v, minlen=16):
            return s                      # 干净短值：保留（API 名/枚举/空串/数字 id）
        return "<redacted:len=%d:sha1=%s>" % (len(v), _digest(v))
    if isinstance(v, list):
        return [scrub_value(x) for x in v[:20]] + (["…"] if len(v) > 20 else [])
    if isinstance(v, dict):
        return {k: scrub_value(x) for k, x in list(v.items())[:40]}
    return scrub_str(str(v), cap=120)


def _scrub_params_json(s):
    """把一个 `{...}` JSON 文本按"键保留、值安全化"重写；解析失败则整体强脱敏。"""
    try:
        o = json.loads(s)
    except Exception:
        return scrub_str(s, cap=TEXT_CAP)
    if not isinstance(o, dict):
        return scrub_value(o)
    out = {}
    for k, v in list(o.items())[:60]:
        if _SENSITIVE_KEY_RE.search(str(k)):
            out[k] = "<redacted:len=%d:sha1=%s>" % (len(str(v)), _digest(v))
        else:
            out[k] = scrub_value(v)
    return out


_PARAMS_RE = re.compile(r"params:\s*(\{.*\})\s*$", re.S)


def scrub_text(text):
    """按当前 LEVEL 处理输入文本。

    meta : 完全不落文本（只留长度/摘要）
    safe : 保留平台行/栈帧/**params 的键**，params 的**值**安全化（默认）
    full : 原样（截断到 TEXT_CAP）—— 明文可能含个人信息，仅限内网
    """
    if not isinstance(text, str):
        return None
    if LEVEL == "meta":
        return None
    if LEVEL == "full":
        return text[:TEXT_CAP] + ("…<trunc>" if len(text) > TEXT_CAP else "")
    # safe
    head, sep, tail = text.partition("\nparams:")
    body = text
    if sep:
        m = _PARAMS_RE.search(text)
        if m:
            body = head + "\nparams: " + json.dumps(_scrub_params_json(m.group(1)),
                                                    ensure_ascii=False)
        else:
            body = head + "\nparams: " + scrub_str(tail, cap=TEXT_CAP)
    else:
        body = scrub_str(head, cap=TEXT_CAP)
    return body[:TEXT_CAP]


def frame_api(text):
    """尽力从三段文本里抽出"本次调用的 API 名"，便于按 API 聚合（仅用于日志标注）。"""
    if not isinstance(text, str):
        return None
    m = re.search(r'"(?:_api|api)"\s*:\s*"([^"]{1,80})"', text)
    if m:
        return m.group(1)
    m = re.search(r"params:\s*\{\s*([A-Za-z0-9_\.\$\[\]]{1,80})\s*:", text)
    if m:
        return m.group(1)
    m = re.search(r"stack:\s*([^<\n]{1,80})", text)
    if m:
        return m.group(1).strip()[:80]
    return None


def input_digest(text):
    if not isinstance(text, str):
        return None
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:16]


# ----------------------------------------------------------------- 写入
def _open():
    if _state["fh"] is not None or _state["broken"]:
        return _state["fh"]
    try:
        d = os.path.dirname(PATH)
        if d:
            os.makedirs(d, exist_ok=True)
        if MAX_BYTES > 0 and os.path.exists(PATH) and os.path.getsize(PATH) >= MAX_BYTES:
            bak = PATH + ".1"
            try:
                if os.path.exists(bak):
                    os.remove(bak)
                os.rename(PATH, bak)
            except Exception:
                pass
        _state["fh"] = open(PATH, "a", encoding="utf-8")
        _state["path"] = PATH
    except Exception:
        _state["broken"] = True
        _state["fh"] = None
    return _state["fh"]


def run_id():
    if _state["run"] is None:
        _state["run"] = "%s-%d" % (datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
                                   os.getpid() % 10000)
    return _state["run"]


def _now():
    return datetime.datetime.now().astimezone().isoformat(timespec="milliseconds")


def _t_mono():
    if _state["t0"] is None:
        _state["t0"] = time.monotonic()
    return round((time.monotonic() - _state["t0"]) * 1000, 3)


def log(ev, **fields):
    """写一条事件。**永不抛异常**——日志故障不得影响判定。"""
    if not ENABLED:
        return
    try:
        fh = _open()
        if fh is None:
            return
        with _lock:
            _state["seq"] += 1
            rec = {"seq": _state["seq"], "ts": _now(), "ms": _t_mono(),
                   "t_wall": round(time.time(), 3), "run": run_id(),
                   "pid": os.getpid(), "thread": threading.current_thread().name,
                   "ev": ev}
            # 刻意**保留 None**：让同一 `ev` 的事件 schema 恒定（可直接读成表/DataFrame），
            # 也便于聚合时区分"字段缺失"与"字段为空"。
            for k, v in fields.items():
                rec[k] = v
            line = json.dumps(rec, ensure_ascii=False, default=str)
            fh.write(line + "\n")
            _state["bytes"] += len(line) + 1
            _state["count"] += 1
            if _state["count"] % 20 == 0:
                fh.flush()
        if TO_STDERR and ev in ("run_start", "sample", "run_end", "error"):
            sys.stderr.write("[dbg] " + json.dumps(
                {k: fields.get(k) for k in ("sid", "api", "final", "review_reason", "ms")},
                ensure_ascii=False) + "\n")
    except Exception:
        pass


def error(stage, exc, text=None, sid=None):
    """记录一次异常（含类型 + 截断 traceback），用于定位上游/环境问题。"""
    if not ENABLED:
        return
    log("error", stage=stage, sid=sid, err_type=type(exc).__name__,
        err=str(exc)[:300],
        tb="".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[-1200:],
        api=frame_api(text), text_len=len(text) if isinstance(text, str) else None,
        input_sha1=input_digest(text))


def env_snapshot():
    """采集与本系统行为相关的环境变量（**密钥类值已打码**），供回传后复现配置。"""
    keys = ["PC_SCOPE_CONTRACT", "PC_STRICT_NONE", "PC_INDIRECT_AUTOPASS", "PC_LLM",
            "PC_LLM_MODEL", "PC_DTYPE_GUARD", "PC_EXPANDED_APIS", "PC_REQUIRE_CALIB",
            "PC_ALLOW_REAL", "PC_ALLOW_RELAX", "PC_FORCE_MODEL", "PC_MODEL_DIR",
            "PC_REVIEW_THRESHOLD", "PC_UNCALIB_THRESHOLD", "PC_MAXLEN", "PC_MAX_TEXT_CHARS",
            "PC_SCOPE_AUDIT_KEY", "PC_SCOPE_REVOKE_PATH", "PC_DEBUG_LOG",
            "PC_DEBUG_LOG_LEVEL"]
    snap = {}
    for k in keys:
        v = os.environ.get(k)
        if v is None:
            continue
        if re.search(r"(?i)(key|token|secret|passwd|password)", k):
            snap[k] = "<set:redacted>" if v else ""
        else:
            snap[k] = v
    snap["_python"] = sys.version.split()[0]
    snap["_platform"] = platform.platform()
    snap["_cwd"] = os.getcwd()
    return snap


def start(tool, extra=None):
    """一次批处理/服务运行开始时调用。"""
    if not ENABLED:
        return run_id()
    fields = {"tool": tool, "env": env_snapshot(), "log_level": LEVEL,
              "log_path": PATH}
    if extra:
        fields.update(extra)
    log("run_start", **fields)
    return run_id()


def finish(tool, counts=None, path=None, elapsed_ms=None):
    if not ENABLED:
        return
    log("run_end", tool=tool, counts=counts, output=path,
        elapsed_ms=elapsed_ms, events=_state["count"])


# ----------------------------------------------------------------- 计时
class stage(object):
    """`with debuglog.stage(d, "l1"):` —— 把该段耗时累加进 d["ms"]["l1"]。"""

    __slots__ = ("d", "key", "_t")

    def __init__(self, acc, key):
        self.d = acc
        self.key = key

    def __enter__(self):
        self._t = time.perf_counter()
        return self

    def __exit__(self, *exc):
        if self.d is None:
            return False
        dt = round((time.perf_counter() - self._t) * 1000, 3)
        ms = self.d.setdefault("ms", {})
        ms[self.key] = round(ms.get(self.key, 0.0) + dt, 3)
        return False


# ----------------------------------------------------------------- 判定轨迹
def sample(text, trace, sid=None, ms=None, extra=None):
    """记录**一条样本**的完整判定轨迹（主事件）。

    trace 采用 pipeline.run / predict.predict_one 的原生返回结构，本函数只做**投影**，
    不新增任何判定逻辑。字段含义：
      guard_action / guard_residual   输入哨兵（L2）的处置与残留类型
      l1_*                            确定性规则引擎（L1）的结论与 tier
      l3_*                            本地模型建议（**仅建议，永不落 COMPLIANT**）
      l4a_*                           外部大模型（可选件）
      final_*                         最终结论与给出结论的层
      review_reason                   进复核的原因（无则自动出口）
    """
    if not ENABLED:
        return
    # pipeline.run 返回的是「结果 + trace」；各层细节在 trace 里（兼容直接传 trace 的调用）
    outer = trace or {}
    tr = outer.get("trace") if isinstance(outer.get("trace"), dict) else outer
    l1 = tr.get("L1") or {}
    l3 = tr.get("L3") or {}
    l4a = tr.get("L4a") or {}
    decision = outer.get("decision", tr.get("decision"))
    needs_human = outer.get("needs_human", tr.get("needs_human"))
    if needs_human:
        outcome = "REVIEW"
    elif decision == "COMPLIANT":
        outcome = "AUTO_COMPLIANT"
    elif decision:
        outcome = "AUTO_VIOLATION"
    else:
        outcome = "REVIEW"
    fields = {
        "sid": sid,
        "api": frame_api(text),
        "text_len": len(text) if isinstance(text, str) else None,
        "input_sha1": input_digest(text),
        "text": scrub_text(text),
        "outcome": outcome,
        "l2_guard": tr.get("L2_guard") or outer.get("L2_guard"),
        "l1_combo": l1.get("combo"),
        "l1_tier": l1.get("tier"),
        "l1_confidence": l1.get("confidence"),
        "l1_needs_review": l1.get("needs_review"),
        "l3_kind": l3.get("kind"),
        "l3_combo": l3.get("suggest"),
        "l3_confidence": l3.get("confidence"),
        "l4a": (l4a.get("verdict") if isinstance(l4a, dict) else l4a),
        "decision": decision,
        "data_type": outer.get("data_type", tr.get("data_type")),
        "needs_human": needs_human,
        "final_layer": outer.get("final_layer", tr.get("final_layer")),
        "review_reason": outer.get("review_reason", tr.get("review_reason")),
        "ms": ms or tr.get("ms"),
    }
    if extra:
        fields.update(extra)
    log("sample", **fields)


def backend(kind, ok, note=None, gate=None):
    if not ENABLED:
        return
    log("backend", kind=kind, available=bool(ok), note=note, gate=gate)


def model_sample(text, out, sid=None, ms=None):
    """记录 `predict.predict_one` 的单条轨迹（与 `sample()` 同一 JSONL，`src="predict"`）。

    与 `sample()` 的区别：这条路径**不做四层编排**，而是"规则 + 模型 + 冲突/阈值复核"，
    因此单独投影，字段名保持自解释，便于 `dbg_summary.py` 一并聚合。
    """
    if not ENABLED:
        return
    o = out or {}
    if o.get("needs_review"):
        outcome = "REVIEW"
    elif o.get("violation") == "COMPLIANT":
        outcome = "AUTO_COMPLIANT"
    elif o.get("violation"):
        outcome = "AUTO_VIOLATION"
    else:
        outcome = "REVIEW"
    log("sample", src="predict", sid=sid,
        api=frame_api(text),
        text_len=len(text) if isinstance(text, str) else None,
        input_sha1=input_digest(text),
        text=scrub_text(text),
        outcome=outcome,
        l2_guard=o.get("guard"),
        backend=o.get("backend"),
        rules_hint=o.get("rules_hint"),
        l3_kind=o.get("backend"),
        l3_combo=o.get("combo"),
        l3_confidence=o.get("confidence"),
        model_prob=o.get("model_prob"),
        calibrated=o.get("calibrated"),
        decision=o.get("violation") if o.get("violation") != "COMPLIANT" else "COMPLIANT",
        data_type=o.get("data_type"),
        needs_human=o.get("needs_review"),
        final_layer=o.get("source"),
        review_reason=o.get("review_reason"),
        ms=ms)
