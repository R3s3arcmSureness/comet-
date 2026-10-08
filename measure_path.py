# -*- coding: utf-8 -*-
"""measure_path.py — 漏判率溯源测量（决定性实验）

目的：回答"去掉 L4a 外部大模型，99.9% 还算不算数"。
方法：把 L1 规则引擎的每条样本判成三个互斥出口，分别统计：

    A. auto-judged  : needs_review=False  → 系统直接给出结论
    B. escalated    : needs_review=True   → 进 L4a/L4b（fail-closed）
    C. （不存在）   : 无第三出口

真值口径：
    truth != COMPLIANT  = 应当判"违规/警告"
    truth == COMPLIANT  = 应当判"合规"

漏判（miss / leak）定义：**自动**给出 COMPLIANT，但真值是违规。
    → 只有 A 出口里、判 COMPLIANT 的那部分才可能产生漏判。
    → B 出口无论有没有 L4a，都不会自动落 COMPLIANT ⇒ 漏判率与 L4a 无关。

用法：python measure_path.py [--n 20000]
"""
import os, sys, json, argparse, time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from rules_engine import classify as rules_classify   # noqa: E402

# 【P0-D】严重度序：数字越小越严重（取自 labels.VIOLATION_PRIORITY）
# 红队指出：原口径只统计"自动判 COMPLIANT"，于是 L1 把 NO_CONSENT 降级成 WARNING
# 后照样自动放行、且不进入任何漏判统计 —— **评测口径本身有盲区**。
# 现补一条独立指标「严重度降级率」：真值为违规 V、系统自动输出更轻的 V' ⇒ 计入降级。
from labels import VIOLATION_PRIORITY                  # noqa: E402
_SEV = {v: i for i, v in enumerate(VIOLATION_PRIORITY)}
_SEV["COMPLIANT"] = len(VIOLATION_PRIORITY)            # 最轻


def severity(v):
    return _SEV.get(v, len(VIOLATION_PRIORITY))


def measure(path, limit=None, use_guard=True):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    if limit:
        rows = rows[:limit]

    t0 = time.time()
    n = len(rows)
    c = Counter()
    # 真值为违规的样本，结局分布
    viol_outcome = Counter()
    leak_examples = []
    downgrade_examples = []

    for r in rows:
        truth = r.get("violation")
        is_viol = (truth != "COMPLIANT")
        rec = rules_classify(r["text"])
        auto = not rec["needs_review"]
        pred = rec["violation"]
        c["auto" if auto else "esc"] += 1
        if is_viol:
            c["truth_viol"] += 1
            if auto and pred == "COMPLIANT":
                viol_outcome["漏判(自动判合规)"] += 1
                if len(leak_examples) < 5:
                    leak_examples.append((r.get("id"), truth, r["text"][:160]))
            elif auto and pred not in (None, "COMPLIANT"):
                viol_outcome["正确拦截"] += 1
                # 【P0-D】严重度降级：真值更严重、自动输出更轻 ⇒ 计入降级（原口径看不见）
                if severity(pred) > severity(truth):
                    viol_outcome["严重度降级"] += 1
                    if len(downgrade_examples) < 5:
                        downgrade_examples.append((r.get("id"), truth, pred, r["text"][:140]))
            elif not auto:
                viol_outcome["转复核(fail-closed)"] += 1
            else:
                # auto=True 且 pred is None：本不应发生（不可判必须 needs_review=True），
                # 单独计数以便一旦出现立刻暴露（这是 fail-closed 被绕过的信号）
                viol_outcome["其他(自动但无结论)"] += 1
                c["auto_indeterminate"] += 1
        else:
            c["truth_ok"] += 1
            if auto and pred == "COMPLIANT":
                c["ok_auto_compliant"] += 1
            elif auto:
                c["ok_false_alarm"] += 1          # 真值合规却被自动判成非合规
            else:
                c["ok_escalated"] += 1

    dt = time.time() - t0
    out = {
        "dataset": os.path.basename(path),
        "n": n, "seconds": round(dt, 1),
        "auto_rate": round(c["auto"] / n, 6),
        "review_rate": round(c["esc"] / n, 6),
        "n_truth_violation": c["truth_viol"],
        "n_truth_compliant": c["truth_ok"],
        # ★ 核心指标：漏判率（自动判合规 / 全部真违规）
        "miss_rate_on_violation": round(
            viol_outcome["漏判(自动判合规)"] / max(c["truth_viol"], 1), 8),
        # 误报率（自动判违规 / 全部真合规）
        "false_alarm_rate_on_compliant": round(
            c["ok_false_alarm"] / max(c["truth_ok"], 1), 8),
        # ★【P0-D】严重度降级率（真值违规 → 自动输出更轻类别）
        "downgrade_rate_on_violation": round(
            viol_outcome["严重度降级"] / max(c["truth_viol"], 1), 8),
        "n_auto_indeterminate": c["auto_indeterminate"],
        "violation_outcome": dict(viol_outcome),
        "leak_examples": leak_examples,
        "downgrade_examples": downgrade_examples,
    }
    return out, c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=None)
    a = ap.parse_args()
    for ds in ("data/test.jsonl", "data/test_ood.jsonl"):
        p = os.path.join(HERE, ds)
        if not os.path.exists(p):
            continue
        res, c = measure(p, a.n)
        print("=" * 68)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        print(f"[原始计数] {dict(c)}")


if __name__ == "__main__":
    main()
