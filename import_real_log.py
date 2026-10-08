# -*- coding: utf-8 -*-
"""import_real_log.py — 把「核桃编程小程序 Hook 采集·全量解混淆日志」转成契约输入

日志格式（结构化文本，非 JSONL）：
    #00100 [11:32:54.326] [H6] getDeviceInfo  <<敏感>>
      -- 参数内容 --------------------------------------------------
      api: getDeviceInfo
      params: {"waidPkg":""}
      ...
      -- Java 调用栈 --------------------------------------------------
      共 1 帧
      [00] (微信框架) com.tencent.mm...Jni.nativeInvokeHandler(SourceFile:-2)<= 小程序 native 桥（JNI）
    ------------------------------------------------------------------------------------------

转成契约 §1 的三段文本：
    [platform=miniprogram]
    stack: <frame> <- <frame> ...
    params: {<真实 params ∪ extra ∪ 元字段>}

注意：真实日志**没有契约 §2 的信号字段**（consent_state/crypto/pii_mask/…），
本导入器**如实照搬**，不做任何补全——补全等于伪造合规信号。

输出：realdata/real.jsonl（含 id/text/api/category/sensitive/session 字段）
"""
import json
import os
import re
import sys
import collections

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOG = os.path.join(os.path.dirname(HERE), "realdata",
                           "核桃编程_hook采集_全量解混淆.log")
SEP = "-" * 90
REC_RE = re.compile(r"^#(\d+)\s+\[([\d:.]+)\]\s+\[(H\d|META)\]\s+(.*?)(\s+<<敏感>>)?\s*$")
FRAME_RE = re.compile(r"^\s*\[(\d+)\]\s*(.*)$")
SESSION_RE = re.compile(r"^#\s*(S\d+)\s*·\s*(.+?)\s*$")


def parse_log(path):
    recs = []
    cur = None
    section = None
    session = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\r\n")
            s = line.strip()
            m = SESSION_RE.match(s)
            if m:
                session = m.group(1)
                continue
            m = REC_RE.match(line)
            if m:
                if cur:
                    recs.append(cur)
                cur = {"seq": m.group(1), "time": m.group(2), "category": m.group(3),
                       "name": m.group(4), "sensitive_mark": bool(m.group(5)),
                       "session": session, "kv": {}, "stack": [],
                       "thread": None, "n_frames": None}
                section = None
                continue
            if cur is None:
                continue
            if line.startswith(SEP):
                if cur:
                    recs.append(cur)
                    cur = None
                continue
            if "-- 参数内容" in line:
                section = "params"
                continue
            if "-- Java 调用栈" in line:
                section = "stack"
                continue
            if "-- 线程" in line:
                cur["thread"] = s.lstrip("- ").replace("-- ", "")
                section = None
                continue
            if section == "params" and ":" in line:
                k, _, v = line.strip().partition(":")
                cur["kv"][k.strip()] = v.strip()
            elif section == "stack":
                if s.startswith("共 ") and "帧" in s:
                    cur["n_frames"] = s
                elif s and s != "（无）":
                    fm = FRAME_RE.match(line)
                    if fm:
                        cur["stack"].append(fm.group(2).strip())
    if cur:
        recs.append(cur)
    return recs


def to_contract_text(rec):
    """转成契约 §1 的三段文本。params 如实合并（真实 params + extra + 元字段）。"""
    params = {}
    p = rec["kv"].get("params")
    if p:
        try:
            o = json.loads(p)
            if isinstance(o, dict):
                params.update(o)
        except Exception:
            params["_params_raw"] = p
    e = rec["kv"].get("extra")
    if e:
        try:
            o = json.loads(e)
            if isinstance(o, dict):
                params["_extra"] = o
        except Exception:
            pass
    params["_api"] = rec["kv"].get("api", rec["name"])
    params["_category"] = rec["category"]
    if rec["sensitive_mark"] or rec["kv"].get("sensitive") == "True":
        params["_sensitive"] = True
    stack = " <- ".join(rec["stack"]) if rec["stack"] else "（无）"
    return f"[platform=miniprogram]\nstack: {stack}\nparams: {json.dumps(params, ensure_ascii=False)}"


def main():
    log = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(HERE), "realdata", "real.jsonl")
    recs = parse_log(log)
    with open(out, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps({"id": r["seq"], "session": r["session"], "category": r["category"],
                                "api": r["kv"].get("api", r["name"]),
                                "sensitive": bool(r["sensitive_mark"] or r["kv"].get("sensitive") == "True"),
                                "n_stack": len(r["stack"]),
                                "text": to_contract_text(r)}, ensure_ascii=False) + "\n")
    cat = collections.Counter(r["category"] for r in recs)
    api = collections.Counter(r["kv"].get("api", r["name"]) for r in recs)
    print(f"[import] records={len(recs)} → {out}")
    print(f"[import] 分类: {dict(sorted(cat.items()))}")
    print(f"[import] 有栈记录={sum(1 for r in recs if r['stack'])}/"
          f"{len(recs)}  敏感标记={sum(1 for r in recs if r['sensitive_mark'])}")
    print(f"[import] api top10: {api.most_common(10)}")


if __name__ == "__main__":
    main()
