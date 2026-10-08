# -*- coding: utf-8 -*-
"""predict.py v2 — 生产推理入口（生产级修订版）

对照审计报告 D1/D4 的修订：
1. 【D1 修复】真正接入微调的 mmBERT 模型（models/ft_transformer），TF-IDF 仅作降级备选
2. 混合管线：规则引擎主判（确定性）→ 模型兜底（低置信/缺字段时）→ 冲突入复核
3. 概率校准：加载训练产出的 temperature.json（dev 上 NLL 最优温度）
4. 复核队列：模型置信 < 阈值 / 规则与模型冲突 / 规则 needs_review → needs_review=True
5. 输入约定见 docs/hook_schema_contract.md（与逆向 Hook 层的契约）

用法：
  单条：echo '<text>' | python predict.py
  批量：python predict.py --in data/test.jsonl --out results.jsonl [--limit N]
"""
import os, sys, json, time, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from rules_engine import classify as rules_classify
from labels import COMBO_CLASSES, COMBO2IDX
from deobfuscate import input_guard, deobfuscate_text

try:                                    # 调试日志（默认关闭；关闭时零开销、零行为变化）
    import debuglog
except Exception:                       # pragma: no cover - 缺模块也必须能跑
    debuglog = None

# 微调模型目录。训练完成前默认目录可能残缺（仅有 checkpoint），
# 此时会自动降级 TF-IDF；部署时用 PC_MODEL_DIR 指向实际产物目录。
FT_DIR = os.environ.get("PC_MODEL_DIR") or os.path.join(HERE, "models", "ft_transformer")
TFIDF_PATH = os.path.join(HERE, "models", "clf.pkl")
TFIDF_VEC_PATH = os.path.join(HERE, "models", "vec.pkl")
# 【第五轮】模型侧复核阈值同样由校准文件驱动（缺省与历史值一致）：
#   已校准后端（温度标定后）→ model_threshold_calibrated（缺省 0.85）
#   未校准后端（TF-IDF 伪概率偏乐观）→ 更严格阈值（缺省 0.95）
# 注意：这与 rules_engine 的 λ 是**两个不同的旋钮** ——
#   λ 管规则引擎的确定性结论；本阈值管"规则低置信 → 模型兜底"这条分支。
#   二者都写进同一份校准产物（models/calibration.json），便于统一审计。
from calib_runtime import calib_value as _calib_value    # noqa: E402


def model_threshold(calibrated=True):
    if calibrated:
        return _calib_value("model_threshold_calibrated",
                            float(os.environ.get("PC_REVIEW_THRESHOLD", "0.85")))
    return _calib_value("model_threshold_uncalibrated",
                        float(os.environ.get("PC_UNCALIB_THRESHOLD", "0.95")))
# 未校准后端（TF-IDF 伪概率偏乐观）→ 施加更严格阈值，避免\"假高置信\"漏过复核
# UNCALIB_THRESHOLD 常量已废弃 —— 见上方 model_threshold(calibrated=False)（默认 0.95）。
MAXLEN = int(os.environ.get("PC_MAXLEN", "320"))   # 与训练一致（样本 p99=307）


# ---------------- 模型层 ----------------
class TransformerBackend:
    def __init__(self, model_dir=FT_DIR):
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        # 【部署闸门 · fail-closed】多 Agent 复审 P0：
        # 原实现把闸门放在加载权重「之后」且用 `if os.path.exists(gpath)` 包住整块 —— 于是
        #   ① deploy_gate.json 缺失 → 跳过校验，未达标模型被**无条件采用**；
        #   ② JSON 损坏 → gate=None → `if gate and ...` 短路，同样放过；
        #   ③ 缺 pass 键 → `gate.get("pass", True)` 默认 True，同样放过。
        # 而"有权重、无闸门"的目录是**真实可达**的（训练脚本先 save_model 后写 gate，两步间被杀）。
        # 故改为：**先验闸门、再加载权重**；缺失/不可解析/pass 非 True 一律拒绝采用。
        # PC_FORCE_MODEL=1 为显式调试开关（唯一可绕过闸门的方式）。
        gpath = os.path.join(model_dir, "deploy_gate.json")
        force = os.environ.get("PC_FORCE_MODEL") == "1"
        gate = None
        if os.path.exists(gpath):
            try:
                gate = json.load(open(gpath, encoding="utf-8"))
            except Exception as e:
                if not force:
                    raise RuntimeError(f"deploy_gate.json 无法解析（{e}）→ 拒绝采用")
        self.deploy_gate = gate
        if not force:
            if gate is None:
                raise RuntimeError(
                    f"deploy_gate.json 缺失或不可解析（{gpath}）→ 拒绝采用（fail-closed）；"
                    f"PC_FORCE_MODEL=1 可强制")
            if gate.get("pass") is not True:
                raise RuntimeError(
                    f"deploy_gate: pass={gate.get('pass')!r} test_acc={gate.get('test_acc')} "
                    f"ood_acc={gate.get('test_ood_acc')} baseline={gate.get('baseline')}"
                    f"/{gate.get('baseline_ood')} → 拒绝采用（PC_FORCE_MODEL=1 可强制）")
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(model_dir)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_dir)
        self.model.eval()
        self.label2id = self.model.config.label2id
        self.id2label = {i: c for c, i in self.label2id.items()}
        tpath = os.path.join(model_dir, "temperature.json")
        self.temperature = json.load(open(tpath, encoding="utf-8"))["temperature"] \
            if os.path.exists(tpath) else 1.0
        self.available = True

    def predict(self, text):
        import torch
        with torch.no_grad():
            enc = self.tok(text, truncation=True, max_length=MAXLEN, return_tensors="pt")
            logits = self.model(**enc).logits[0] / self.temperature
            probs = torch.softmax(logits, dim=-1)
        conf, idx = float(probs.max()), int(probs.argmax())
        top2 = torch.topk(probs, k=2)
        margin = float(top2.values[0] - top2.values[1])
        return {"combo": self.id2label[idx], "confidence": round(conf, 4),
                "margin": round(margin, 4),
                "probs": {self.id2label[int(i)]: round(float(p), 4)
                          for i, p in zip(top2.indices, top2.values)}}


class StructBackend:
    """分层结构化 L3 后端（data_type 头 × violation 头）。CPU 约 1 分钟可训。

    两个头：
        data_type ← 栈帧 API token / payload 键名（LogisticRegression；实测 F1≈1.0）
        violation ← 契约信号字段（**梯度提升**；树模型表达 policy 的布尔合取）
    相对 TF-IDF(char ngram) 的实测 macro-F1（合成，reports/l3_struct_metrics.json）：
        combo 0.8414 → ~0.99（+15）   ood 0.7889 → ~0.99（+20）
    为什么这么便宜又有效：violation 是信号字段的确定性布尔函数、data_type 由 API token
    决定，两头各自可学，**CPU 上无需 transformer**。

    与 TransformerBackend 相同的**部署闸门纪律**：先验 deploy_gate.json，缺失/不可解析/
    pass 非 True 一律拒绝采用（fail-closed）；PC_FORCE_MODEL=1 为唯一显式绕过开关。
    """
    def __init__(self, d=None):
        import pickle
        d = d or os.path.join(HERE, "models", "l3_struct")
        gpath = os.path.join(d, "deploy_gate.json")
        force = os.environ.get("PC_FORCE_MODEL") == "1"
        gate = None
        if os.path.exists(gpath):
            try:
                gate = json.load(open(gpath, encoding="utf-8"))
            except Exception as e:
                if not force:
                    raise RuntimeError(f"l3_struct deploy_gate.json 无法解析（{e}）→ 拒绝采用")
        if not force:
            if gate is None:
                raise RuntimeError(f"l3_struct deploy_gate.json 缺失（{gpath}）→ 拒绝采用（fail-closed）")
            if gate.get("pass") is not True:
                raise RuntimeError(
                    f"l3_struct 闸门未过：pass={gate.get('pass')!r} "
                    f"test_f1={gate.get('test_f1')} ood_f1={gate.get('ood_f1')} → 拒绝采用")
        self.deploy_gate = gate
        with open(os.path.join(d, "model.pkl"), "rb") as f:
            M = pickle.load(f)
        self._M = M
        self.available = True
        self.calibrated = True          # LogisticRegression → 真概率（非 softmax 伪概率）

    def predict(self, text):
        import numpy as np
        from l3_features import dt_feats, split_text, build_combo
        M = self._M
        Xd = M["vd"].transform([dt_feats(text)])
        Xv = M["enc"].transform([split_text(text)[2]])
        pd = M["md"].predict_proba(Xd)[0]
        pv = M["mv"].predict_proba(Xv)[0]
        idt, ivt = int(np.argmax(pd)), int(np.argmax(pv))
        dt, vv = M["md"].classes_[idt], M["mv"].classes_[ivt]
        combo = build_combo(str(dt), str(vv))
        conf = float(pd[idt] * pv[ivt])          # 联合置信（两头独立 ⇒ 乘积）
        s_d = np.sort(pd)[::-1]
        s_v = np.sort(pv)[::-1]
        margin = float((s_d[0] - s_d[1]) * s_v[0] + (s_v[0] - s_v[1]) * s_d[0])
        return {"combo": combo, "confidence": round(conf, 4),
                "margin": round(margin, 4), "calibrated": True}


class TfidfBackend:
    """TF-IDF(char_wb 2-4gram) + LinearSVC 降级后端。

    两个易错点（曾在此处出过真实 bug）：
      ① 必须先经 vec.pkl 向量化，不能把原始文本直接喂给 clf；
      ② LinearSVC 没有 predict_proba，用 decision_function + softmax 得到**伪概率**。
         该伪概率未经校准、偏乐观，故 calibrated=False，由 predict_one 施加更严格阈值。
    """
    def __init__(self, path=TFIDF_PATH, vec_path=TFIDF_VEC_PATH):
        import pickle
        with open(path, "rb") as f:
            self.clf = pickle.load(f)
        with open(vec_path, "rb") as f:
            self.vec = pickle.load(f)
        self.available = True
        self.calibrated = False

    def predict(self, text):
        import numpy as np
        X = self.vec.transform([text])
        if hasattr(self.clf, "predict_proba"):
            p = np.asarray(self.clf.predict_proba(X)[0], dtype=float)
        else:
            d = np.asarray(self.clf.decision_function(X)[0], dtype=float).ravel()
            e = np.exp(d - d.max())
            p = e / e.sum()                      # 伪概率（softmax over decision）
        order = np.argsort(p)[::-1]
        i = int(order[0])
        margin = float(p[order[0]] - p[order[1]]) if len(order) > 1 else 1.0
        return {"combo": str(self.clf.classes_[i]), "confidence": round(float(p[i]), 4),
                "margin": round(margin, 4), "calibrated": False}


_backend = None


def get_backend():
    """后端优先级（逐级 fail-closed 降级）：

        mmBERT-finetuned  → 需 models/ft_transformer/deploy_gate.json 通过（当前缺 → 跳过）
        l3-struct         → 需 models/l3_struct/deploy_gate.json 通过（**当前生产默认**）
        tfidf-fallback    → 旧基线（macro-F1 0.84/0.79），仅在前两者不可用时兜底
        none              → 规则引擎单独工作（缺 sklearn/torch 时的裸解释器场景）
    """
    global _backend
    if _backend is not None:
        return _backend
    for ctor, kind in ((TransformerBackend, "mmBERT-finetuned"),
                       (StructBackend, "l3-struct")):
        try:
            _backend = ctor()
            _backend.kind = kind
            if debuglog is not None:
                debuglog.backend(kind, True,
                                 gate=getattr(_backend, "deploy_gate", None))
            return _backend
        except Exception as e:
            print(f"[predict] {kind} unavailable ({e})", file=sys.stderr)
            if debuglog is not None:
                debuglog.backend(kind, False, note=str(e)[:200])
    try:
        _backend = TfidfBackend()
        _backend.kind = "tfidf-fallback"
        if debuglog is not None:
            debuglog.backend("tfidf-fallback", True, note="degraded:gate_unavailable")
    except Exception as e2:
        print(f"[predict] no model backend at all: {e2}", file=sys.stderr)
        if debuglog is not None:
            debuglog.backend("none", False, note=str(e2)[:200])

        class _None:
            kind = "none"
            available = False
            def predict(self, text):
                return {"combo": "UNKNOWN||UNKNOWN", "confidence": 0.0, "margin": 0.0}
        _backend = _None()
    return _backend


# ---------------- 混合判定 ----------------
def predict_one(text, use_guard=True, sid=None):
    """对外唯一入口：计时 + 调试日志，随后原样交给 `_predict_one_impl`。

    调试日志默认关闭；关闭时本包装层除两次 `time.perf_counter` 外不做任何事，
    返回值与方法体逐位一致。
    """
    on = debuglog is not None and debuglog.ENABLED
    t0 = time.perf_counter()
    try:
        out = _predict_one_impl(text, use_guard=use_guard)
    except Exception as e:
        if debuglog is not None:
            debuglog.error("predict.predict_one", e, text=text, sid=sid)
        raise
    if on:
        debuglog.model_sample(text, out, sid=sid,
                              ms={"total": round((time.perf_counter() - t0) * 1000, 3)})
    return out


def _predict_one_impl(text, use_guard=True):
    """返回 {data_type, violation, combo, confidence, source, needs_review, review_reason, backend}

    管线顺序（四层漏斗的 L0→L1→L3）：
      L0 输入哨兵 input_guard：判断上游是否已完成脱壳/解混淆/解密
         - pass        → 干净明文，直接进 L1
         - preprocess  → 低危残留（零宽/同形字），确定性还原后重判
         - review      → 高危残留（sf:/b64:/高熵串），fail-closed 直接入复核，绝不猜测
      L1 规则引擎（确定性主判）
      L3 模型兜底（规则低置信时）
    """
    guard = input_guard(text) if use_guard else {"action": "pass", "residual": []}
    if guard["action"] == "review":
        return {"data_type": None, "violation": None, "combo": "UNKNOWN||UNKNOWN",
                "confidence": 0.0, "source": "input_guard",
                "needs_review": True,
                "review_reason": "upstream_residual:" + ",".join(guard["residual"]),
                "backend": "none", "guard": guard["action"]}
    if guard["action"] == "preprocess":
        text, _ = deobfuscate_text(text)      # 确定性还原（100% 可逆，零风险）

    rules = rules_classify(text)
    be = get_backend()
    model_out = be.predict(text)

    # 规则高置信 → 直接采用
    if rules["confidence"] >= 0.9 and not rules["needs_review"]:
        return {"data_type": rules["data_type"], "violation": rules["violation"],
                "combo": rules["combo"], "confidence": rules["confidence"],
                "source": "rules", "needs_review": False, "review_reason": None,
                "backend": be.kind, "model_prob": model_out.get("confidence"),
                "guard": guard["action"]}

    # 规则低置信（缺字段/解析失败）→ 模型结果为主，规则做一致性参考
    combo = model_out["combo"]
    dt, v = (combo.split("||") + [None, None])[:2] if "||" in combo else (None, None)
    conflict = (rules.get("combo") not in (None, "UNKNOWN||UNKNOWN")
                and rules["combo"] != combo and model_out["confidence"] >= 0.5)
    calibrated = model_out.get("calibrated", True)
    thr = model_threshold(calibrated)      # 【第五轮】改由校准产物驱动，缺省行为不变
    low_conf = model_out["confidence"] < thr or model_out.get("margin", 0) < 0.1
    reasons = []
    if low_conf:
        # 未校准后端阈值更严（0.95），已校准后端用 0.85（均可由校准产物覆盖）
        reasons.append(f"model_conf<{thr}_or_margin<0.1(uncalibrated)" if not calibrated
                       else f"model_conf<{thr}_or_margin<0.1")
    if conflict:
        reasons.append(f"rules_model_conflict(rules={rules['combo']})")
    if rules.get("needs_review") and rules.get("review_reason"):
        reasons.append(rules["review_reason"])
    return {"data_type": dt, "violation": v, "combo": combo,
            "confidence": model_out["confidence"], "source": f"model({be.kind})",
            "needs_review": bool(reasons), "review_reason": ";".join(reasons) or None,
            "backend": be.kind, "rules_hint": rules.get("combo"),
            "guard": guard["action"], "calibrated": calibrated}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", help="输入 JSONL（需含 text 字段）；缺省读 stdin")
    ap.add_argument("--out", dest="outp", help="输出 JSONL；缺省打印 stdout")
    ap.add_argument("--limit", type=int, default=None)
    a = ap.parse_args()

    def _emit(rec, f):
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    if a.inp:
        rows = [json.loads(l) for l in open(a.inp, encoding="utf-8") if l.strip()]
        if a.limit:
            rows = rows[:a.limit]
        fout = open(a.outp, "w", encoding="utf-8") if a.outp else None
        n_rev = 0
        t0 = time.perf_counter()
        if debuglog is not None:
            debuglog.start("predict.py", {"input": a.inp, "n": len(rows),
                                          "backend": getattr(get_backend(), "kind", None)})
        for i, r in enumerate(rows):
            rec = predict_one(r["text"], sid=r.get("id"))
            rec["id"] = r.get("id")
            n_rev += rec["needs_review"]
            if fout:
                _emit(rec, fout)
            else:
                print(json.dumps(rec, ensure_ascii=False))
        if fout:
            fout.close()
            dt = time.perf_counter() - t0
            if debuglog is not None:
                debuglog.finish("predict.py",
                                {"n": len(rows), "needs_review": n_rev,
                                 "review_rate": round(n_rev / max(1, len(rows)), 6)},
                                path=a.outp, elapsed_ms=round(dt * 1000, 1))
            print(f"done: {len(rows)} records, needs_review={n_rev} "
                  f"({n_rev/len(rows):.2%}) -> {a.outp}", file=sys.stderr)
    else:
        if debuglog is not None:
            debuglog.start("predict.py", {"mode": "stdin"})
        print(json.dumps(predict_one(sys.stdin.read()), ensure_ascii=False, indent=2))
        if debuglog is not None:
            debuglog.finish("predict.py", {"n": 1})


if __name__ == "__main__":
    main()
