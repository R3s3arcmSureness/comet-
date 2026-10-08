# -*- coding: utf-8 -*-
"""train_dtype_guard_pure.py — 零依赖的 dtype 交叉校验哨兵（替代 sklearn 版）

## 为什么要重写
原 `models/dtype_guard.pkl` 用 sklearn(TfidfVectorizer + LinearSVC) 训练，
反序列化**必须有 sklearn**。而 `rules_engine._ensure_guard_tried` 原实现是
`except Exception: _GUARD = None` —— 缺依赖时**静默降级为"无意见"**，
号称的"第 5 道闸门"在无人知晓的情况下消失（红队实测本机两个 Python 都无 sklearn）。

这类"安全网静默失效"与本项目已修的 deploy_gate 三条 fail-open 是同一种错误。
彻底解法 = **让安全网不依赖外部包**：本脚本用纯 Python 实现
「字符 3-gram + 哈希桶 + 多项式朴素贝叶斯」，只用标准库（json/re/array/zlib），
产出可直接 pickle 反序列化的普通 dict + array，**不需要 sklearn / numpy**。

## 与规则引擎的独立性
特征只用字符 n-gram 的**统计**共现，不使用任何 API 目录 / 关键词表 / 策略函数，
因此它是与 L1 规则引擎**完全独立的信号路径**——这正是"交叉校验哨兵"的意义。

用法：
  python train_dtype_guard_pure.py                 # 训练并写 models/dtype_guard_pure.pkl
  python train_dtype_guard_pure.py --eval-only     # 只评测已有模型
"""
import os, sys, json, re, array, zlib, math, argparse, time, pickle
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from labels import DATA_TYPES                       # noqa: E402

NONE_CLS = "NONE"
CLASSES = list(DATA_TYPES)                          # 14 类（含 NONE）
CLS2IDX = {c: i for i, c in enumerate(CLASSES)}
B = 1 << 16                                         # 哈希桶数（65536）
NGRAM = 3
MAXCHARS = 600
MODEL_PATH = os.path.join(HERE, "models", "dtype_guard_pure.pkl")

_TOK = re.compile(r"[a-z0-9_$]{1,}")


def grams(text):
    """字符 3-gram（在 token 边界内加 ^ $ 标记，缓解跨 token 噪声）。"""
    s = text.lower()[:MAXCHARS]
    out = []
    for tok in _TOK.findall(s):
        t = "^" + tok + "$"
        for i in range(len(t) - NGRAM + 1):
            out.append(t[i:i + NGRAM])
    return out


def bucket(g):
    return zlib.crc32(g.encode("utf-8", "ignore")) % B


def load_rows(path, limit=None):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            dt = r.get("data_type")
            if dt not in CLS2IDX:
                continue
            rows.append((r["text"], CLS2IDX[dt]))
            if limit and len(rows) >= limit:
                break
    return rows


def build(rows, alpha=0.2):
    """训练多项式 NB。返回 (logp_flat, prior_logp)。
    logp_flat 用 array('f') 存，pickle 后体积约为 float list 的 1/3。"""
    t0 = time.time()
    counts = [[0.0] * B for _ in range(len(CLASSES))]   # 平滑前计数（float，防 int 溢出）
    cls_n = [0] * len(CLASSES)
    for text, ci in rows:
        gs = Counter(grams(text))
        cls_n[ci] += 1
        row = counts[ci]
        for g, c in gs.items():
            row[bucket(g)] += c
    # 拉普拉斯平滑 + log
    flat = array.array("f", bytes(4 * B * len(CLASSES)))
    prior = array.array("f", bytes(4 * len(CLASSES)))
    total_n = sum(cls_n) or 1
    for ci in range(len(CLASSES)):
        row = counts[ci]
        tot = sum(row) + alpha * B
        ltot = math.log(tot)
        base = ci * B
        for b in range(B):
            flat[base + b] = math.log(row[b] + alpha) - ltot
        prior[ci] = math.log((cls_n[ci] + 1.0) / (total_n + len(CLASSES)))
    print(f"  [build] {len(rows)} 样本 / {len(CLASSES)} 类 / B={B}，耗时 {time.time()-t0:.1f}s")
    return flat, prior


def predict(model, text):
    flat, prior = model["logp"], model["prior"]
    gs = Counter(bucket(g) for g in grams(text))
    best_c, best_s = 0, None
    n = len(CLASSES)
    for ci in range(n):
        base = ci * B
        s = prior[ci]
        row = flat
        for b, c in gs.items():
            s += row[base + b] * c
        if best_s is None or s > best_s:
            best_s, best_c = s, ci
    return CLASSES[best_c], best_s


def evaluate(model, path, limit=None):
    rows = load_rows(path, limit)
    ok = Counter()
    n = 0
    t0 = time.time()
    for text, ci in rows:
        pred, _ = predict(model, text)
        n += 1
        ok["acc"] += (CLS2IDX[pred] == ci)
        # 只关心"是否敏感"（真正用于兜底的判断）与"具体类型"两档
        ok["sens_acc"] += ((pred != NONE_CLS) == (CLASSES[ci] != NONE_CLS))
    return {"n": n, "acc_15c": round(ok["acc"] / max(n, 1), 6),
            "sens_binary_acc": round(ok["sens_acc"] / max(n, 1), 6),
            "sec": round(time.time() - t0, 1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-limit", type=int, default=60000)
    ap.add_argument("--eval-limit", type=int, default=8000)
    ap.add_argument("--eval-only", action="store_true")
    a = ap.parse_args()

    if a.eval_only:
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
    else:
        print("[1/3] 载入训练集")
        rows = load_rows(os.path.join(HERE, "data", "train.jsonl"), a.train_limit)
        print(f"  {len(rows)} 条")
        print("[2/3] 训练（纯 Python 字符 3-gram + 哈希桶 NB）")
        logp, prior = build(rows)
        model = {"classes": CLASSES, "B": B, "ngram": NGRAM, "logp": logp, "prior": prior}
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        tmp = MODEL_PATH + ".tmp"
        with open(tmp, "wb") as f:
            pickle.dump(model, f, protocol=4)
        os.replace(tmp, MODEL_PATH)
        print(f"  模型 -> {MODEL_PATH}  ({os.path.getsize(MODEL_PATH)/1e6:.1f} MB)")

    print("[3/3] 评测")
    res = {}
    for tag, p in (("test", "data/test.jsonl"), ("test_ood", "data/test_ood.jsonl")):
        r = evaluate(model, os.path.join(HERE, p), a.eval_limit)
        res[tag] = r
        print(f"  {tag:9s} n={r['n']:6d}  15类acc={r['acc_15c']:.4f}  "
              f"敏感/非敏感二分类acc={r['sens_binary_acc']:.4f}  ({r['sec']}s)")

    out = os.path.join(HERE, "reports", "dtype_guard_pure_eval.json")
    json.dump({"model": "pure-python char3gram hashed MNB", "classes": len(CLASSES),
               "B": B, "results": res}, open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    print(f"  评测 -> {out}")


if __name__ == "__main__":
    main()
