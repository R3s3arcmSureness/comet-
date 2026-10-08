# -*- coding: utf-8 -*-
"""pipeline.py — 四层漏斗编排（L4a 外部大模型为**可选件**）

★ 核心设计不变式（这是 99.9% 的数学保证，也是"可以不用外部大模型"的依据）
------------------------------------------------------------------
  INV-1  「COMPLIANT」只能由 L1 规则引擎在**完整确定性匹配**(tier=="full")且
         未触发任何 fail-closed 时给出。L2/L3/L4a/L4b **一律不得**把样本降级为 COMPLIANT。
  INV-2  L4a 的输出空间被**结构性限制**为 {违规类别, 不确定}，不存在 COMPLIANT 通道。
  INV-3  任何层的异常/超时/低置信 → fail-closed 转人工，绝不"猜一个合规"。

推论（漏判率与 L4a 无关）
  漏判 = 「自动输出 COMPLIANT，但真值违规」。
  由 INV-1，auto-COMPLIANT 集合 ⊆ {x | L1 判 full-tier COMPLIANT}。
  L4a 只接收 L1 升级上来的样本（L1 未给 COMPLIANT），故 L4a 的加入/移除
  **既不扩大也不缩小 auto-COMPLIANT 集合** ⇒ 漏判率不变。
  L4a 唯一的经济作用是：把一部分"人工复核"变成"机器复核"，降低人工工时。

用法：
  echo '<text>' | python pipeline.py            # 单条
  python pipeline.py --in data/test_ood.jsonl --out r.jsonl --limit 500
  环境变量：
    PC_LLM=0|1            是否启用 L4a 外部大模型（默认 0 = 不用）
    PC_REVIEW_THRESHOLD   L3 复核阈值（默认 0.85）
"""
import os, sys, json, argparse, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from rules_engine import classify as rules_classify
from deobfuscate import input_guard, deobfuscate_text
from labels import DATA_TYPES

try:                                    # 调试日志（默认关闭；关闭时零开销、零行为变化）
    import debuglog
except Exception:                       # pragma: no cover - 缺模块也必须能跑
    debuglog = None

# L4a 允许输出的违规类别（**不含 COMPLIANT** —— 结构性禁止降级）
VIOLATION_LABELS = ["NO_CONSENT", "NOT_DISCLOSED", "PLAINTEXT_TRANSMIT",
                    "NO_MASK", "OVER_COLLECT", "WARNING"]
# L4a 判定"无个人数据"时输出的**哨兵**，它仍然不是 COMPLIANT，而是"建议人工判无个人数据"
NO_PII_SENTINEL = "NO_PII_CANDIDATE"

USE_LLM = os.environ.get("PC_LLM", "0") == "1"


# ---------------------------------------------------------------- L4a
class L4aExternalLLM:
    """外部大模型难例兜底层（可选）。

    两条硬约束（缺一不可，否则会**直接破坏** 99.9%）：
      1. 输出枚举**不含 COMPLIANT**（INV-2）——它只能给"违规类别"或"不确定"。
         即便模型高置信认为样本无个人数据，也只能返回 NO_PII_CANDIDATE 建议，
         是否降级为 COMPLIANT **必须**由人工确认（因为"无 PII"是全系统唯一能
         产生漏判的结论，绝不可交给概率模型）。
      2. 外送前强制脱敏（正则抹掉电话/身份证/银行卡/邮箱/经纬度/密钥/URL token），
         只送「函数签名 + 栈帧元数据 + 脱敏后的参数骨架」。
    """
    def __init__(self, model=None, timeout=8.0, sanitize=True):
        self.model = model or os.environ.get("PC_LLM_MODEL", "deepseek-v4-pro")
        self.timeout = timeout
        self.sanitize = sanitize
        self.available = self._probe()

    def _probe(self):
        # 真实部署时在此做一次最小连通性检查（缺 key / 网络不通 → 返回 False）
        return bool(os.environ.get("PC_LLM_API_KEY"))

    # ---- 脱敏 ----
    _PAT = [
        (r"1[3-9]\d{9}", "<PHONE>"),
        (r"\b\d{17}[\dXx]\b", "<IDCARD>"),
        (r"\b\d{16,19}\b", "<BANKCARD>"),
        (r"[\w.+-]+@[\w-]+\.[\w.]+", "<EMAIL>"),
        (r"\b\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b", "<GEO>"),
        (r"(?i)\b(sk|ak|pk|ghp|xox[baprs])[-_][A-Za-z0-9_\-]{16,}", "<KEY>"),
        (r"(?i)\b(token|access_token|sessionid|authorization)\s*[=:]\s*[^\s,}\"]+", r"\1=<REDACTED>"),
        (r"https?://[^\s\"']+", "<URL>"),
    ]

    def sanitize_text(self, text):
        import re
        out = text
        for pat, rep in self._PAT:
            out = re.sub(pat, rep, out)
        return out

    def adjudicate(self, text):
        """返回 dict{verdict, data_type, violation, confidence, note}。

        verdict ∈ {"violation", "uncertain"}  ——  **不存在 "compliant"**。
        """
        if not self.available:
            return {"verdict": "uncertain", "note": "llm_unavailable"}
        payload = self.sanitize_text(text) if self.sanitize else text
        try:
            raw = self._call(payload)
        except Exception as e:
            return {"verdict": "uncertain", "note": f"llm_error:{type(e).__name__}"}
        # 契约校验：模型返回的任何越界值一律降为不确定（不信任模型自述）
        v = (raw or {}).get("verdict")
        if v not in ("violation", "uncertain"):
            return {"verdict": "uncertain", "note": f"llm_schema_violation:{v!r}"}
        if v == "violation" and raw.get("violation") not in VIOLATION_LABELS:
            return {"verdict": "uncertain", "note": "llm_bad_label"}
        return raw

    def _call(self, payload):
        """接入点：默认不实现真实 HTTP（避免误触发外呼）。

        生产接入示例（DeepSeek 兼容 OpenAI 协议，结构化输出）：
            import urllib.request
            req = urllib.request.Request(
                "https://api.deepseek.com/chat/completions",
                data=json.dumps({...}).encode(), headers={...})
            ...
        且**必须**带 response_format={"type":"json_object"} 与白名单枚举校验。
        """
        raise NotImplementedError(
            "L4a 真实外呼未启用（PC_LLM=0 时不会走到这里）。"
            "接入时请实现本方法，并保持 verdict ∈ {violation, uncertain}。")


# ---------------------------------------------------------------- L3
class L3LocalModel:
    """本地小模型（分层结构化 l3-struct / mmBERT / TF-IDF 降级）。仅作**辅助诊断**，不得输出 COMPLIANT。

    【第六轮修复】原先此处**硬编码 `TfidfBackend()`**，等于绕过了 `predict.get_backend()`
    的 fail-closed 部署闸门链（先验 `deploy_gate.json`，未达标即拒用），使生产编排实际
    一直在用最弱后端（char n-gram TF-IDF，macro-F1 0.84），而报告里声称的是 l3-struct（0.99）。
    现改为统一走 `get_backend()`：优先级 mmBERT → l3-struct → tfidf 降级 → none，
    与 `predict.py` 单条/批量路径**同一后端**，避免"评测说 A、编排跑 B"。
    """
    def __init__(self):
        self.backend = None
        self.kind = "none"
        self.note = None
        try:
            from predict import get_backend
            self.backend = get_backend()
            self.kind = getattr(self.backend, "kind", "unknown")
            if self.kind == "none":
                self.note = "no_backend"
        except Exception as e:                       # 缺 sklearn/torch → 规则引擎单独工作
            self.kind = "none"
            self.note = f"{type(e).__name__}: {e}"

    def suggest(self, text):
        if self.backend is None:
            return {"combo": "UNKNOWN||UNKNOWN", "confidence": 0.0}
        try:
            return self.backend.predict(text)
        except Exception:
            return {"combo": "UNKNOWN||UNKNOWN", "confidence": 0.0}


_l3 = None
_l4a = None


def get_l3():
    global _l3
    if _l3 is None:
        _l3 = L3LocalModel()
    return _l3


def get_l4a():
    global _l4a
    if _l4a is None and USE_LLM:
        _l4a = L4aExternalLLM()
    return _l4a


# ---------------------------------------------------------------- 编排
def run(text, use_llm=None, sid=None):
    """四层漏斗主入口（对外唯一入口）。

    本函数只做两件事：**计时** + **落调试日志**，随后把控制权原样交给 `_run_impl`。
    调试日志默认关闭（`PC_DEBUG_LOG` 未设）时，本包装层除了两次 `time.perf_counter`
    之外不做任何事 —— 判定结果与方法体逐位一致。
    """
    dbg = {"ms": {}} if (debuglog is not None and debuglog.ENABLED) else None
    t0 = time.perf_counter()
    try:
        out = _run_impl(text, use_llm=use_llm, _dbg=dbg)
    except Exception as e:                     # fail-closed 兜底：异常绝不外泄成"无结论"
        if debuglog is not None:
            debuglog.error("pipeline.run", e, text=text, sid=sid)
        out = _human(None, None, "internal_error:" + type(e).__name__,
                     {"exception": type(e).__name__})
    if dbg is not None:
        dbg["ms"]["total"] = round((time.perf_counter() - t0) * 1000, 3)
        debuglog.sample(text, out, sid=sid, ms=dbg["ms"])
    return out


def _run_impl(text, use_llm=None, _dbg=None):
    """四层漏斗的实际实现（见模块 docstring 的 INV-1/2/3）。

    返回 dict：
      decision      : "COMPLIANT" | 违规类别 | None(未定)
      data_type     : 数据类型或 None
      needs_human   : 是否进人工复核队列
      final_layer   : 给出最终结论的层（rules / human / llm_suggest）
      trace         : 各层轨迹（可审计）
    """
    llm_on = USE_LLM if use_llm is None else use_llm
    tr = {}

    # ---- L2 输入哨兵（fail-closed）----
    with debuglog.stage(_dbg, "guard") if debuglog is not None else _nullctx():
        guard = input_guard(text)
    tr["L2_guard"] = guard["action"]
    if guard["action"] == "review":
        return _human(None, None, "L2_input_residual:" + ",".join(guard["residual"]), tr)
    if guard["action"] == "preprocess":
        text, _ = deobfuscate_text(text)

    # ---- L1 确定性规则引擎（唯一可产出 COMPLIANT 的层）----
    with debuglog.stage(_dbg, "l1") if debuglog is not None else _nullctx():
        r = rules_classify(text)
    tr["L1"] = {"combo": r["combo"], "confidence": r["confidence"],
                "tier": r.get("tier"), "needs_review": r["needs_review"]}
    if (not r["needs_review"]) and r["violation"] == "COMPLIANT":
        # INV-1：只有 L1 完整匹配才能到此
        return {"decision": "COMPLIANT", "data_type": r["data_type"], "needs_human": False,
                "final_layer": "rules", "review_reason": None, "trace": tr}
    if (not r["needs_review"]) and r["violation"] in VIOLATION_LABELS:
        # 确定性命中违规：直接判违规（同为自动出口，但不涉 COMPLIANT，无漏判风险）
        return {"decision": r["violation"], "data_type": r["data_type"], "needs_human": False,
                "final_layer": "rules", "review_reason": None, "trace": tr}

    # ---- 需要兜底：L1 未给出确定结论 ----
    reason = r.get("review_reason") or "rules_low_confidence"

    # ---- L3 本地模型（仅建议，绝不落 COMPLIANT）----
    l3 = get_l3()
    with debuglog.stage(_dbg, "l3") if debuglog is not None else _nullctx():
        sug = l3.suggest(text)
    tr["L3"] = {"suggest": sug.get("combo"), "confidence": sug.get("confidence"),
                "kind": l3.kind}

    # ---- L4a 外部大模型（可选；输出空间无 COMPLIANT）----
    if llm_on:
        l4a = get_l4a()
        if l4a is not None:
            with debuglog.stage(_dbg, "l4a") if debuglog is not None else _nullctx():
                v = l4a.adjudicate(text)
            tr["L4a"] = v
            if v.get("verdict") == "violation" and v.get("confidence", 1.0) >= 0.9:
                return {"decision": v["violation"], "data_type": v.get("data_type"),
                        "needs_human": False, "final_layer": "llm",
                        "review_reason": reason, "trace": tr}
            # 注意：verdict=="uncertain" 或模型建议"无 PII"，**一律仍进人工**（INV-1/INV-2）
        else:
            tr["L4a"] = {"verdict": "uncertain", "note": "llm_disabled"}

    # ---- L4b 人工复核（fail-closed 终点）----
    return _human(None, r.get("data_type"), reason, tr)


class _nullctx(object):
    """`debuglog` 不可用时的空上下文（保证 `with` 语法在两种情况下都成立）。"""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _human(dt, dt_hint, reason, tr):
    return {"decision": None, "data_type": dt or dt_hint, "needs_human": True,
            "final_layer": "human", "review_reason": reason, "trace": tr}


# ---------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp")
    ap.add_argument("--out", dest="outp")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--llm", type=int, default=None, choices=[0, 1],
                    help="覆盖 PC_LLM：1=启用 L4a 外部大模型")
    a = ap.parse_args()

    use_llm = None if a.llm is None else bool(a.llm)

    if a.inp:
        rows = [json.loads(l) for l in open(a.inp, encoding="utf-8") if l.strip()]
        if a.limit:
            rows = rows[:a.limit]
        fout = open(a.outp, "w", encoding="utf-8") if a.outp else None
        n_h = 0
        t0 = time.time()
        if debuglog is not None:
            debuglog.start("pipeline.py", {"input": a.inp, "n": len(rows),
                                           "llm": bool(use_llm)})
        for i, r in enumerate(rows):
            rec = run(r["text"], use_llm=use_llm, sid=r.get("id"))
            rec["id"] = r.get("id")
            n_h += rec["needs_human"]
            if fout:
                fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if fout:
            fout.close()
        dt = time.time() - t0
        if debuglog is not None:
            debuglog.finish("pipeline.py", {"n": len(rows), "human": n_h,
                                            "human_rate": round(n_h / max(1, len(rows)), 6)},
                            path=a.outp, elapsed_ms=round(dt * 1000, 1))
        print(f"n={len(rows)} human={n_h} ({n_h/len(rows):.2%}) "
              f"{dt:.1f}s -> {a.outp}", file=sys.stderr)
    else:
        if debuglog is not None:
            debuglog.start("pipeline.py", {"mode": "stdin"})
        print(json.dumps(run(sys.stdin.read()), ensure_ascii=False, indent=2))
        if debuglog is not None:
            debuglog.finish("pipeline.py", {"n": 1})


if __name__ == "__main__":
    main()
