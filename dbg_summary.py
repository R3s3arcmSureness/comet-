# -*- coding: utf-8 -*-
"""dbg_summary.py — 把回传的 `debug.jsonl` 汇总成可读报告（`debuglog.py` 的分析端）

用途
----
你在别的服务器上跑完真实数据后，把 `logs/debug.jsonl` 回传，**不需要**再做任何预处理；
本脚本一次性给出：环境快照 / 后端选择 / 复核原因分布 / 按 API 的复核与漏判风险排序 /
模型置信分布 / 分阶段耗时 / 异常清单 / **优化建议**。并附 `--pii-scan` 自查，
让你在回传前确认日志里没有明文个人信息。

用法
----
    python dbg_summary.py logs/debug.jsonl                 # 打印 Markdown 报告
    python dbg_summary.py logs/debug.jsonl --out r.md      # 落盘
    python dbg_summary.py logs/debug.jsonl --top 40        # 控制 Top-N
    python dbg_summary.py logs/debug.jsonl --pii-scan      # 只做 PII 泄露自查

退出码：0 = 正常；2 = 文件不可读；3 = PII 自查发现疑似明文（供 CI/脚本判断）。
"""
import argparse
import collections
import json
import math
import os
import re
import sys

SAMPLE_EV = "sample"


# ----------------------------------------------------------------- 读取
def load(path, limit=None):
    evs = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evs.append(json.loads(line))
            except Exception:
                evs.append({"_bad": line[:200]})
            if limit and len(evs) >= limit:
                break
    return evs


# ----------------------------------------------------------------- 统计
def pctile(xs, p):
    if not xs:
        return 0.0
    s = sorted(xs)
    k = min(len(s) - 1, max(0, int(math.ceil(p / 100.0 * len(s))) - 1))
    return s[k]


def dist(evs, key, keep_none=False):
    c = collections.Counter()
    for e in evs:
        v = e.get(key)
        if v is None and not keep_none:
            continue
        if isinstance(v, (list, dict)):
            v = json.dumps(v, ensure_ascii=False)
        c[str(v)] += 1
    return c


def norm_reason(r):
    """把带参数的复核原因归一到稳定类别（便于跨次对比）。"""
    if not r:
        return "(自动出口)"
    r = re.split(r"[:;,]", str(r))[0].strip()
    return r or "(空)"


def outcome_of(e):
    return e.get("outcome") or ("REVIEW" if e.get("needs_human") else "?")


# ----------------------------------------------------------------- PII 自查
# 判据与 `debuglog` **共用同一事实来源**（单一来源，避免自相矛盾告警）：
#   · 强 PII 形态表  ← `debuglog.PII_PATTERNS`
#   · 编码/密钥串判据 ← `debuglog.looks_like_blob`
try:
    from debuglog import PII_PATTERNS as _PII_PATTERNS, looks_like_blob as _looks_like_blob
except Exception:                                        # pragma: no cover
    def _looks_like_blob(s):
        return len(s) >= 24 and any(c.isdigit() for c in s)
    _PII_PATTERNS = [("手机号", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "<PHONE>")]

_PII_RULES = [(name, pat) for name, pat, _rep in _PII_PATTERNS]
_PII_RULES.append(("编码/密钥串", re.compile(r"[A-Za-z0-9+/=]{24,}")))


def pii_scan(evs):
    """在 `text` 字段里找**未被打码**的疑似明文 PII。返回 [(规则名, 证据片段, sid)]。"""
    hits = []
    for e in evs:
        t = e.get("text")
        if not isinstance(t, str):
            continue
        for name, pat in _PII_RULES:
            for m in pat.finditer(t):
                tok = m.group(0)
                if name == "编码/密钥串" and not _looks_like_blob(tok):
                    continue          # 长标识符（类名/栈帧）不算泄露
                s = max(0, m.start() - 12)
                hits.append((name, t[s:m.end() + 12], e.get("sid")))
    return hits


# ----------------------------------------------------------------- 报告
def build_report(evs, top=25, path=None):
    samples = [e for e in evs if e.get("ev") == SAMPLE_EV]
    starts = [e for e in evs if e.get("ev") == "run_start"]
    ends = [e for e in evs if e.get("ev") == "run_end"]
    backs = [e for e in evs if e.get("ev") == "backend"]
    errors = [e for e in evs if e.get("ev") == "error"]
    bad = [e for e in evs if "_bad" in e]

    L = []
    A = L.append
    A("# 调试日志汇总报告")
    A("")
    A("- 日志文件：`%s`" % (path or "(stdin)"))
    A("- 事件总数：**%d**（其中样本 **%d** 条、异常 **%d** 条）" % (len(evs), len(samples), len(errors)))
    if bad:
        A("- ⚠️ 无法解析的行：%d（首行样例：`%s`）" % (len(bad), bad[0]["_bad"][:80]))
    A("")

    # ---- 运行环境 ----
    if starts:
        st = starts[-1]
        A("## 1. 运行环境（末次运行）")
        A("")
        A("| 项 | 值 |")
        A("|---|---|")
        for k in ("tool", "log_level", "log_path", "input", "n", "backend"):
            if st.get(k) is not None:
                A("| %s | `%s` |" % (k, st[k]))
        env = st.get("env") or {}
        for k in sorted(env):
            A("| `%s` | `%s` |" % (k, env[k]))
        A("")
    if backs:
        A("## 2. L3 后端选择（闸门）")
        A("")
        A("| 后端 | 可用 | 备注 | 闸门 |")
        A("|---|---|---|---|")
        seen = set()
        for b in backs:
            k = b.get("kind")
            if k in seen:
                continue
            seen.add(k)
            g = b.get("gate")
            gtxt = "-"
            if isinstance(g, dict):
                gtxt = "pass=%s test=%s ood=%s" % (g.get("pass"), g.get("test_f1"), g.get("ood_f1"))
            A("| `%s` | %s | %s | %s |" % (k, b.get("available"), (b.get("note") or "")[:60], gtxt))
        A("")

    # ---- 结论分布 ----
    A("## 3. 结论分布")
    A("")
    oc = collections.Counter(outcome_of(e) for e in samples)
    n = max(1, len(samples))
    A("| 出口 | 条数 | 占比 |")
    A("|---|---:|---:|")
    for k, v in oc.most_common():
        A("| %s | %d | %.2f%% |" % (k, v, v / n * 100))
    A("")
    if oc.get("AUTO_COMPLIANT", 0) == 0 and samples:
        A("> ⚠️ **本轮没有任何样本走自动合规出口**：说明上游输入普遍不满足契约"
          "（缺信号字段 / 缺 `consent_scope` / 仍有混淆）。见 §4 复核原因。")
        A("")

    # ---- 复核原因 ----
    A("## 4. 复核原因（Top %d）" % top)
    A("")
    rc = collections.Counter(norm_reason(e.get("review_reason")) for e in samples
                             if e.get("needs_human"))
    A("| 原因 | 条数 | 占复核 |")
    A("|---|---:|---:|")
    tot_rev = max(1, sum(rc.values()))
    for k, v in rc.most_common(top):
        A("| `%s` | %d | %.2f%% |" % (k, v, v / tot_rev * 100))
    A("")

    # ---- 按 API ----
    A("## 5. 按 API 分布（Top %d）" % top)
    A("")
    by_api = collections.defaultdict(lambda: collections.Counter())
    for e in samples:
        by_api[e.get("api") or "(无)"][outcome_of(e)] += 1
    A("| API | 合计 | 自动合规 | 自动违规 | 复核 | 复核占比 |")
    A("|---|---:|---:|---:|---:|---:|")
    for api, c in sorted(by_api.items(), key=lambda kv: -sum(kv[1].values()))[:top]:
        t = sum(c.values())
        A("| `%s` | %d | %d | %d | %d | %.1f%% |"
          % (api, t, c.get("AUTO_COMPLIANT", 0), c.get("AUTO_VIOLATION", 0),
             c.get("REVIEW", 0), c.get("REVIEW", 0) / max(1, t) * 100))
    A("")

    # ---- L1 tier ----
    A("## 6. 规则引擎（L1）命中层级")
    A("")
    for k, v in dist(samples, "l1_tier").most_common():
        A("- `%s`：%d" % (k, v))
    A("")
    none_t = sum(1 for e in samples if e.get("l1_tier") == "none")
    if none_t and none_t / max(1, len(samples)) > 0.2:
        A("> ⚠️ **`l1_tier=none` 占 %.1f%%**：这些样本的 API 完全未在三/四端目录中命中 —— "
          "是**目录扩充**的第一优先级线索（见 §8）。" % (none_t / len(samples) * 100))
        A("")

    # ---- 模型 ----
    A("## 7. 模型层（L3）建议分布")
    A("")
    A("| 后端 | 条数 |")
    A("|---|---:|")
    for k, v in dist(samples, "l3_kind").most_common():
        A("| `%s` | %d |" % (k, v))
    A("")
    confs = [e["l3_confidence"] for e in samples
             if isinstance(e.get("l3_confidence"), (int, float))]
    if confs:
        buckets = collections.Counter()
        for c in confs:
            b = ("<0.30" if c < .3 else "0.30-0.50" if c < .5 else "0.50-0.70" if c < .7
                 else "0.70-0.85" if c < .85 else "0.85-0.95" if c < .95 else "≥0.95")
            buckets[b] += 1
        A("**L3 置信分布**（n=%d，均值 %.3f，p50 %.3f）" % (len(confs), sum(confs) / len(confs),
                                                        pctile(confs, 50)))
        A("")
        A("| 置信区间 | 条数 |")
        A("|---|---:|")
        for b in ("<0.30", "0.30-0.50", "0.50-0.70", "0.70-0.85", "0.85-0.95", "≥0.95"):
            if buckets.get(b):
                A("| %s | %d |" % (b, buckets[b]))
        A("")
        hi = sum(1 for c in confs if c >= 0.85)
        A("> 高置信（≥0.85）占 %.1f%%。**注意**：本系统里 L3 只是“建议”，"
          "规则层不确认就一律转人工；高置信不等于正确（真实数据上出现过"
          "“全 0.998 自信判错”）。" % (hi / len(confs) * 100))
        A("")

    # ---- 耗时 ----
    A("## 8. 分阶段耗时（ms）")
    A("")
    stage_keys = collections.Counter()
    for e in samples:
        ms = e.get("ms")
        if isinstance(ms, dict):
            for k in ms:
                stage_keys[k] += 1
    if stage_keys:
        A("| 阶段 | n | 均值 | p50 | p95 | max |")
        A("|---|---:|---:|---:|---:|---:|")
        for k in [x for x, _ in stage_keys.most_common()]:
            xs = [e["ms"][k] for e in samples
                  if isinstance(e.get("ms"), dict) and isinstance(e["ms"].get(k), (int, float))]
            if not xs:
                continue
            A("| `%s` | %d | %.3f | %.3f | %.3f | %.3f |"
              % (k, len(xs), sum(xs) / len(xs), pctile(xs, 50), pctile(xs, 95), max(xs)))
        A("")

    # ---- 异常 ----
    A("## 9. 异常")
    A("")
    if not errors:
        A("- 无 ✅")
    else:
        ec = collections.Counter((e.get("stage"), e.get("err_type")) for e in errors)
        A("| 阶段 | 异常类型 | 次数 | 示例 |")
        A("|---|---|---:|---|")
        for (s, t), c in ec.most_common(top):
            ex = next((e.get("err") for e in errors
                       if e.get("stage") == s and e.get("err_type") == t), "")
            A("| `%s` | `%s` | %d | %s |" % (s, t, c, str(ex)[:80]))
    A("")

    # ---- 优化建议（自动推导）----
    A("## 10. 自动优化建议")
    A("")
    tips = []
    top_rev = rc.most_common(1)
    if top_rev and top_rev[0][0] != "(自动出口)":
        tips.append("**第一大复核原因**是 `%s`（%d 条）：%s"
                    % (top_rev[0][0], top_rev[0][1], _reason_hint(top_rev[0][0])))
    unk = [e for e in samples if e.get("l1_tier") in ("none", None)]
    if unk:
        c = collections.Counter(e.get("api") for e in unk if e.get("api"))
        top_api = "、".join("`%s`(%d)" % (a, n) for a, n in c.most_common(8))
        tips.append("**未命中目录的 API 数** %d 条，Top：%s —— 这些是四端 SDK 目录的补录候选。"
                    % (len(unk), top_api))
    if confs:
        hi = sum(1 for c in confs if c >= 0.85)
        if hi / len(confs) > 0.5:
            tips.append("模型高置信占比 %.0f%% 但仍有大量转人工 ⇒ 瓶颈在**规则层可见信息不足**"
                        "（信号字段缺失），不是模型。" % (hi / len(confs) * 100))
    if oc.get("AUTO_COMPLIANT", 0) == 0 and samples:
        tips.append("自动合规为 0 ⇒ 请上游按契约补齐 `consent_scope` 与信号字段后再跑一轮，"
                    "否则系统只能全量转人工（安全但无自动化收益）。")
    if errors:
        tips.append("存在 %d 条异常，优先修掉（见 §9）。" % len(errors))
    if not tips:
        tips.append("未发现明显异常；可提高 `--top` 或补充第二轮样本。")
    for i, t in enumerate(tips, 1):
        A("%d. %s" % (i, t))
    A("")
    return "\n".join(L)


_REASON_HINT = {
    "contract_missing_consent_scope": "上游未按契约 v1.2 传 `consent_scope`（非 PII 调用也应传空数组）。",
    "obfuscated_identifier_unresolved": "输入仍有混淆标识符未还原 ⇒ 需上游完成反混淆。",
    "unknown_sensitive_api_hint": "栈帧含敏感语义词但目录未收录该 API ⇒ 补目录。",
    "L2_input_residual": "输入含残留编码/加密串（L2 哨兵拦截）⇒ 上游需完成真解混淆。",
    "ambiguous_partial_identifier": "标识符有歧义，无法唯一确定数据类型 ⇒ 补栈帧上下文。",
    "indirect_tier": "只解析到 payload 层、缺 consent/transport/mask 信号 ⇒ 补信号字段。",
    "rules_low_confidence": "规则置信不足 ⇒ 通常因信号字段缺失。",
    "compliance_metadata_unobservable": "合规元数据不可观测（上报/加密通道）⇒ 需上游补通道标记。",
}


def _reason_hint(r):
    for k, v in _REASON_HINT.items():
        if r.startswith(k):
            return v
    return "请对照 `docs/hook_schema_contract.md` 检查该原因的触发条件。"


# ----------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log", help="debug.jsonl 路径")
    ap.add_argument("--out", help="把 Markdown 报告写到该文件")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--limit", type=int, default=None, help="只读前 N 行事件（调试用）")
    ap.add_argument("--pii-scan", action="store_true", help="只做明文 PII 自查")
    a = ap.parse_args()

    if not os.path.exists(a.log):
        print(f"错误：找不到 {a.log}", file=sys.stderr)
        return 2

    evs = load(a.log, a.limit)

    if a.pii_scan:
        hits = pii_scan(evs)
        if not hits:
            print("PII 自查：未发现疑似明文（日志可安全外传）✅")
            return 0
        print(f"PII 自查：发现 {len(hits)} 处疑似明文 ⚠️")
        for name, frag, sid in hits[:40]:
            print(f"  [{name}] sid={sid} …{frag}…")
        print("\n建议：改用 PC_DEBUG_LOG_LEVEL=safe 重跑，或人工确认后再外传。", file=sys.stderr)
        return 3

    rep = build_report(evs, top=a.top, path=a.log)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(rep)
        print(f"报告已写入 {a.out}")
    else:
        print(rep)
    hits = pii_scan(evs)
    if hits:
        print(f"\n⚠️ 提示：日志中有 {len(hits)} 处疑似明文 PII，外传前请先 `--pii-scan` 确认。",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
