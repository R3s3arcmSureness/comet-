# -*- coding: utf-8 -*-
"""check_robust.py — 异常输入鲁棒性压测（生产级必备）

目标：
  ① 任何输入都不得抛异常（崩溃 = 生产事故）
  ② 任何输入都不得在"未复核"状态下给出 COMPLIANT（fail-closed 红线）
     例外：确实识别为"无敏感 API + 无混淆痕迹"的真·无个人数据，允许判 NONE||COMPLIANT
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rules_engine import classify
from deobfuscate import input_guard
from predict import predict_one

CASES = [
    ("空字符串", ""),
    ("纯空白", "   \n\t  "),
    ("纯乱码", "\\\\x00\\\\x01\\\\xff\\\\xfe abcd"),
    ("无 platform", 'stack: LocationManager.getLastKnownLocation\nparams: {"crypto":"none"}'),
    ("params 非 JSON", '[platform=android]\nstack: TelephonyManager.getImei\nparams: {broken json'),
    ("无 params 段", '[platform=android]\nstack: TelephonyManager.getImei(T.java:1)'),
    ("无 stack 段", '[platform=android]\nparams: {"consent_state":"granted"}'),
    ("只有 platform", '[platform=ios]'),
    ("超长文本(5万字符)", '[platform=android]\nstack: ' + "A" * 50000 + '\nparams: {"crypto":"none"}'),
    ("深度嵌套 JSON", '[platform=android]\nstack: TelephonyManager.getImei\nparams: '
                      + "{\"a\":" * 50 + "1" + "}" * 50),
    ("特殊字符注入", '[platform=android]\nstack: <script>alert(1)</script>\nparams: {"k":"\'\"; DROP TABLE--"}'),
    ("Unicode  emoji/中文", '[platform=harmony]\nstack: 相机.拍照()\nparams: {"备注":"用户同意✅"}'),
    ("Null 字节", '[platform=android]\nstack: TelephonyManager.getImei\x00\nparams: {}'),
    ("数字型 params", '[platform=android]\nstack: TelephonyManager.getImei\nparams: 12345'),
    ("数组型 params", '[platform=android]\nstack: TelephonyManager.getImei\nparams: [1,2,3]'),
    ("platform 未知值", '[platform=windows]\nstack: TelephonyManager.getImei\nparams: {"crypto":"none"}'),
    ("空 JSON params", '[platform=android]\nstack: Camera.open\nparams: {}'),
]

print("=" * 78)
print("D. 异常输入鲁棒性压测")
print("=" * 78)
print(f"{'场景':22s} {'崩溃':6s} {'结果':22s} {'复核':6s} {'红线':6s}")
print("-" * 78)

crashes, violations_of_redline = 0, 0
for name, text in CASES:
    crashed = False
    try:
        o = classify(text)
        g = input_guard(text)
        p = predict_one(text)
    except Exception as e:
        crashed = True
        crashes += 1
        print(f"{name:22s} {'崩溃!!':6s} {type(e).__name__}: {str(e)[:40]}")
        continue

    # 红线：不得在未复核时给出 COMPLIANT，除非是"真·无个人数据"(NONE)
    is_compliant = (o.get("violation") == "COMPLIANT")
    auto = not o.get("needs_review", True)
    is_true_none = (o.get("data_type") == "NONE")
    redline_ok = not (is_compliant and auto and not is_true_none)
    if not redline_ok:
        violations_of_redline += 1

    combo = str(o.get("combo"))[:22]
    print(f"{name:22s} {'OK':6s} {combo:22s} "
          f"{str(o.get('needs_review')):6s} {'OK' if redline_ok else '违反!!':6s}")

print("-" * 78)
print(f"崩溃数: {crashes}/{len(CASES)}   |   红线违反数: {violations_of_redline}/{len(CASES)}")
print("=" * 78)
