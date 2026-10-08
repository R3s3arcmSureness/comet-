# -*- coding: utf-8 -*-
"""smoke_test.py — 部署后一条命令自检（**不依赖训练数据与 GPU**）

检查内容
--------
C1 运行环境        Python 版本、关键依赖（numpy/sklearn）、工作目录
C2 模型与部署闸门   l3-struct 产物存在、`deploy_gate.json` 通过、后端选择结果
C3 目录与四端覆盖   安卓 / iOS / 小程序 / 鸿蒙 四端目录均有条目，且平台可识别
C4 判定不变式      INV-1：`COMPLIANT` 只能由 L1 完整（tier=full）匹配给出
C5 契约判别器      `consent_scope` 缺失 → 转人工；显式 `[]` → 可自动合规
C6 fail-closed     未知 API + 无信号字段 → 转人工（绝不猜"合规"）
C7 调试日志链路     开关关闭时零副作用；开启后事件可写、可解析、**已脱敏**
C8 脱敏规则单测     明文 PII 必打码；而**长类名/栈帧/鸿蒙模块名/毫秒时间戳不得误伤**
C8 汇总脚本         `dbg_summary.py` 能读回日志并出报告

用法
----
    python smoke_test.py            # 全部检查
    python smoke_test.py --verbose  # 打印每条样本的判定

退出码：0 = 全部通过；1 = 有检查失败。
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

OK, FAIL, WARN = [], [], []


def ck(cond, name, detail=""):
    (OK if cond else FAIL).append(name)
    print(("  [OK] " if cond else "  [!!] ") + name + (("  " + str(detail)) if detail else ""))
    return bool(cond)


def warn(name, detail=""):
    WARN.append(name)
    print("  [~ ] " + name + (("  " + str(detail)) if detail else ""))


# --------------------------------------------------------------- 样例
SAMPLES = [
    # (说明, 文本, 期望不变式标签)
    ("安卓·完整合规", "[platform=android]\nstack: com.app.Ui.onClick <- "
     "android.telephony.TelephonyManager.getDeviceId\n"
     'params: {"consent_state": "granted", "consent_scope": ["DEVICE_ID"],'
     ' "crypto": "tls1.3", "pii_mask": true, "biz_purpose": "device_binding"}', "INV1"),
    ("iOS·缺 consent_scope", "[platform=ios]\nstack: NSString <- "
     "[[UIDevice currentDevice] identifierForVendor]\n"
     'params: {"api": "identifierForVendor"}', "CONTRACT"),
    ("小程序·显式空声明", '[platform=miniprogram]\nstack: wx.getSystemInfoSync\n'
     'params: {"api": "getSystemInfoSync", "consent_scope": []}', "EMPTY_SCOPE"),
    ("鸿蒙·未知 API", "[platform=harmony]\nstack: entry/src/main/ets/Index.ets:42\n"
     'params: {"api": "my.unknown.api.doThing"}', "FAILCLOSED"),
    ("安卓·残留混淆", "[platform=android]\nstack: a.b.c\n"
     'params: {"api": "getImei", "v": "b64:YWJjZGVmZ2hpamtsbW5vcA=="}', "RESIDUAL"),
]

FORBIDDEN_IN_LOG = ["13800138000", "110101199003078515"]


# --------------------------------------------------------------- 检查
def c1_env(args):
    print("\nC1 运行环境")
    v = sys.version_info
    ck(v >= (3, 8), "Python ≥ 3.8", f"{v.major}.{v.minor}.{v.micro}")
    for mod in ("numpy", "sklearn"):
        try:
            __import__(mod)
            ck(True, f"依赖可用：{mod}")
        except Exception as e:
            ck(False, f"依赖可用：{mod}", f"{type(e).__name__}: {e}")
    print(f"  工作目录：{HERE}")


def c2_models():
    print("\nC2 模型与部署闸门")
    import predict
    d = os.path.join(HERE, "models", "l3_struct")
    ck(os.path.exists(os.path.join(d, "model.pkl")), "l3-struct 模型产物存在")
    gp = os.path.join(d, "deploy_gate.json")
    gate = None
    if os.path.exists(gp):
        try:
            gate = json.load(open(gp, encoding="utf-8"))
        except Exception as e:
            ck(False, "deploy_gate.json 可解析", e)
    ck(gate is not None, "deploy_gate.json 存在且可解析")
    if gate:
        ck(gate.get("pass") is True, "部署闸门 pass=True",
           f"test={gate.get('test_f1')} ood={gate.get('ood_f1')}")
    be = predict.get_backend()
    ck(getattr(be, "kind", None) in ("l3-struct", "mmBERT-finetuned"),
       "后端选择：l3-struct 或 mmBERT（非降级）", getattr(be, "kind", None))
    out = be.predict(SAMPLES[1][1])
    ck(isinstance(out, dict) and "combo" in out, "后端可给出预测",
       f"combo={out.get('combo')} conf={out.get('confidence')}")
    return be


def c3_catalog():
    print("\nC3 四端目录覆盖")
    import apis
    idx = getattr(apis, "API_INDEX", None)
    if idx is None:                                  # 兼容不同实现命名
        for nm in ("API_INDEX", "_API_INDEX", "PLATFORM_INDEX"):
            idx = getattr(apis, nm, None)
            if idx is not None:
                break
    if not isinstance(idx, dict):
        ck(False, "找到 API_INDEX")
        return
    for p in ("android", "ios", "miniprogram", "harmony"):
        n = len(idx.get(p, {}) or {})
        ck(n > 0, f"{p} 目录有条目", f"{n} 条")
    # 平台识别：四端各一条，能被引擎识别出平台（不因平台未知而全局搜索）
    from rules_engine import classify
    for p in ("android", "ios", "miniprogram", "harmony"):
        r = classify(f"[platform={p}]\nstack: （无）\nparams: {{}}")
        ck(isinstance(r, dict) and "combo" in r, f"{p} 平台可判定（不抛异常）",
           f"tier={r.get('tier')}")
    ck(getattr(apis, "EXPANDED_ENABLED", None) in (True, False),
       "扩充目录开关可读（默认关闭）", getattr(apis, "EXPANDED_ENABLED", "?"))


def c4_invariants(verbose=False):
    print("\nC4/C5/C6 判定不变式")
    import pipeline
    results = []
    for desc, text, tag in SAMPLES:
        out = pipeline.run(text, use_llm=False)
        tr = out.get("trace", {})
        tier = (tr.get("L1") or {}).get("tier")
        results.append((desc, tag, out, tier))
        if verbose:
            print(f"    · {desc}: decision={out.get('decision')} "
                  f"needs_human={out.get('needs_human')} tier={tier} "
                  f"reason={out.get('review_reason')}")
        # 全局不变式：凡自动输出 COMPLIANT，必须 tier == "full"
        if out.get("decision") == "COMPLIANT" and not out.get("needs_human"):
            ck(tier == "full", f"INV-1：{desc} 的 COMPLIANT 来自 full-tier", tier)
        # 全局不变式：L3 建议永不直接落 COMPLIANT（这里用 trace 结构守护）
        ck("L3" not in out or out.get("final_layer") != "L3",
           f"INV-2：{desc} 未由 L3 直接定论")

    by = {t: o for _, t, o, _ in results}
    o = by.get("CONTRACT")
    ck(o and o["needs_human"] and o.get("decision") is None,
       "C5：缺 consent_scope → 不自动放行（转人工）",
       o.get("review_reason") if o else None)
    ck(any("contract_missing_consent_scope" in str(r[2].get("review_reason"))
           for r in results),
       "C5：契约判别器确实生效（出现 contract_missing_consent_scope）")
    o = by.get("EMPTY_SCOPE")
    ck(o is not None and (o["needs_human"] or o["decision"] == "COMPLIANT"),
       "C5：显式空声明 → 有确定结论（自动合规或按值级印证转人工）",
       f"decision={o.get('decision')} reason={o.get('review_reason')}")
    o = by.get("FAILCLOSED")
    ck(o and o["needs_human"], "C6：未知 API 且无信号字段 → 转人工",
       o.get("review_reason") if o else None)
    o = by.get("INV1")
    ck(o is not None, "样例可跑通（未抛异常）")
    return results


def c7_debuglog():
    print("\nC7 调试日志链路")
    # 7.1 关闭时零副作用
    tmp = tempfile.mkdtemp(prefix="pc_dbg_off_")
    p = os.path.join(tmp, "debug.jsonl")
    code = ("import os,sys;sys.path.insert(0,%r);import pipeline;"
            "pipeline.run('[platform=ios]\\nstack: x\\nparams: {}')" % HERE)
    env = dict(os.environ)
    env.pop("PC_DEBUG_LOG", None)
    env["PC_DEBUG_LOG_PATH"] = p
    subprocess.run([sys.executable, "-c", code], env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ck(not os.path.exists(p), "未设 PC_DEBUG_LOG 时不建日志文件（零副作用）")

    # 7.2 开启后可写、可解析、已脱敏
    tmp2 = tempfile.mkdtemp(prefix="pc_dbg_on_")
    p2 = os.path.join(tmp2, "debug.jsonl")
    sample = ("[platform=android]\\nstack: com.a.B.getImei\\n"
              'params: {"api":"getImei","phone":"13800138000",'
              '"idcard":"110101199003078515","consent_scope":["DEVICE_ID"]}')
    code2 = ("import os,sys;sys.path.insert(0,%r);import pipeline;"
             "pipeline.run(%r, sid='SMOKE-1');"
             "pipeline.run('[platform=ios]\\nstack: x\\nparams: {}', sid='SMOKE-2')"
             % (HERE, sample))
    env2 = dict(os.environ)
    env2.update({"PC_DEBUG_LOG": "1", "PC_DEBUG_LOG_LEVEL": "safe",
                 "PC_DEBUG_LOG_PATH": p2})
    r = subprocess.run([sys.executable, "-c", code2], env=env2,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if not ck(os.path.exists(p2), "PC_DEBUG_LOG=1 时写出日志文件",
              (r.stderr or b"")[-200:].decode("utf-8", "replace")):
        return None
    evs = [json.loads(l) for l in open(p2, encoding="utf-8") if l.strip()]
    ck(len(evs) > 0, "日志事件可逐行解析为 JSON", f"{len(evs)} 条")
    ck(any(e.get("ev") == "sample" for e in evs), "含 sample 主事件")
    ck(any(e.get("ev") == "backend" for e in evs), "含 backend 后端选择事件")
    raw = open(p2, encoding="utf-8").read()
    leaked = [x for x in FORBIDDEN_IN_LOG if x in raw]
    ck(not leaked, "safe 级已脱敏（明文手机号/身份证未落盘）", leaked or "无泄露")
    ck("com.a.B.getImei" in raw, "safe 级保留 API/栈帧（优化必需的信息未丢）")
    # 汇总脚本
    sm = os.path.join(HERE, "dbg_summary.py")
    if os.path.exists(sm):
        rr = subprocess.run([sys.executable, sm, p2], capture_output=True, text=True)
        ck(rr.returncode == 0 and "结论分布" in rr.stdout,
           "dbg_summary.py 可读回日志并出报告", f"rc={rr.returncode}")
        rr2 = subprocess.run([sys.executable, sm, p2, "--pii-scan"],
                             capture_output=True, text=True)
        ck(rr2.returncode == 0, "dbg_summary.py --pii-scan 通过（无明文 PII）",
           rr2.stdout.strip()[:60])
    else:
        warn("未找到 dbg_summary.py（汇总分析端缺失）")
    return p2


def c8_scrub_rules():
    """脱敏规则的**双向**回归：该码的必码，不该码的**绝不能**码。

    这些用例来自真实踩坑（每一个都曾在真实日志上误伤过诊断信息）：
      · `\\b1[3-9]\\d{9}\\b` 会把 13 位毫秒时间戳前 10 位当手机号（实测 160 处误报，
        且会把 `timeStamp` 字段改成 `<PHONE>396` —— 既误报又**破坏数据**）；
      · `[\\w.+-]+@[\\w-]+\\.[\\w.]+` 会吃掉鸿蒙模块名的前导 `-`（`-@ohos.payment`）；
      · "长串即密钥"会把栈帧类名（`RIVERViewControllerBridgeLegacy`）与
        JVM 描述符（`Lcom/tencent/mm/X;`）当密钥抹掉 —— 而它们正是补目录的关键信息。
    """
    print("\nC8 脱敏规则单测（正向必码 / 反向不得误伤）")
    import debuglog as D
    must_mask = [
        ("13800138000", "<PHONE>"),
        ("110101199003078515", "<IDCARD>"),
        ("6222021234567890123", "<BANKCARD>"),
        ("alice@example.com", "<EMAIL>"),
        ("https://a.example/x?token=1", "<URL>"),
        ("eyJhbGciOiJIUzI1NiJ9", "<blob"),          # JWT 头（20 字符）
        ("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "<blob"),
        ("YWJjZGVmZ2hpamtsbW5vcA==", "<blob"),
    ]
    must_keep = [
        "1790220775396",                             # 13 位毫秒时间戳
        "-@ohos.payment",                            # 鸿蒙模块名
        "@ohos.identifier.oaid",
        "RIVERViewControllerBridgeLegacy",            # 长类名
        "getLastKnownLocationInternal",
        "subscriberCellularProviderWithCompletion",
        "Lcom/tencent/mm/plugin/Test;",              # JVM 描述符
        "com.kuaishou.security.DeviceUtils.getImei",  # 包路径
    ]
    for s, expect in must_mask:
        got = D.scrub_str(s)
        ck(expect in got, f"必码：{s[:34]}", got[:48])
    for s in must_keep:
        got = D.scrub_str(s)
        ck(s in got, f"不得误伤：{s[:38]}", got[:48])
    ck(D.scrub_value("DEVICE_ID") == "DEVICE_ID", "枚举值原样保留（consent_scope 需要）")
    ck(D.looks_like_blob("RIVERViewControllerBridgeLegacy") is False,
       "判据：长类名 ⊄ 编码串")
    ck(D.looks_like_blob("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6") is True,
       "判据：32 位混合串 ⊂ 编码串")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true", help="打印每条样本的判定")
    a = ap.parse_args()

    print("=" * 70)
    print("privacy_compliance 部署自检")
    print("=" * 70)
    c1_env(a)
    c2_models()
    c3_catalog()
    c4_invariants(a.verbose)
    c7_debuglog()
    c8_scrub_rules()

    print("\n" + "=" * 70)
    print(f"结果：通过 {len(OK)} 项，失败 {len(FAIL)} 项，提示 {len(WARN)} 项")
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  - " + f)
    print("=" * 70)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
