# -*- coding: utf-8 -*-
"""labels.py v2 — 标签体系（生产级修订版）

修订说明（对照多Agent审计报告 B3）：
- 类别空间从"声明92类/实际75类"改为**单一事实来源**：NONE||COMPLIANT + 13种PII类型×7种违规 = 92类
- 所有 92 类均可生成（v2 生成器保证），labels/generator/policy/rules/training 使用同一枚举
- WARNING / PLAINTEXT_TRANSMIT 覆盖全部 PII 类型
"""

# ---------------- 数据类型（14） ----------------
DATA_TYPES = [
    "PHONE", "ID_CARD", "BANK_CARD", "DEVICE_ID", "EMAIL", "NAME",
    "EXACT_IMAGE", "HEALTH", "LOCATION", "SMS", "CONTACTS",
    "BIOMETRIC", "CAMERA_MIC", "NONE",
]

DATA_TYPE_DESC = {
    "PHONE": "手机号",
    "ID_CARD": "身份证号",
    "BANK_CARD": "银行卡号",
    "DEVICE_ID": "设备标识（IMEI/OAID/MAC/ANDROID_ID）",
    "EMAIL": "电子邮箱",
    "NAME": "真实姓名",
    "EXACT_IMAGE": "精确人脸/照片图像",
    "HEALTH": "健康/医疗记录",
    "LOCATION": "精确地理位置",
    "SMS": "短信内容/验证码",
    "CONTACTS": "通讯录",
    "BIOMETRIC": "生物特征（人脸/指纹）",
    "CAMERA_MIC": "摄像头/麦克风能力调用",
    "NONE": "非个人敏感数据",
}

# ---------------- 违规类型（7） ----------------
VIOLATIONS = [
    "COMPLIANT", "WARNING", "NO_CONSENT", "NOT_DISCLOSED",
    "OVER_COLLECT", "PLAINTEXT_TRANSMIT", "NO_MASK",
]

VIOLATION_DESC = {
    "COMPLIANT": "合规",
    "WARNING": "警告（弱必要性/三方共享缺单独同意/长留存等软风险）",
    "NO_CONSENT": "未取得同意（拒绝/未请求/撤回/范围外/过期/无同意记录）",
    "NOT_DISCLOSED": "未告知（未公开政策/收集后改政策未再告知）",
    "OVER_COLLECT": "过度收集（超业务必要性/全量采集/搭车采集）",
    "PLAINTEXT_TRANSMIT": "明文传输（未加密/弱加密/HTTP）",
    "NO_MASK": "未脱敏（raw 或 高敏类型仅部分脱敏）",
}

# 违规判定优先级（多个违规并存时取最高优先级为标签）
VIOLATION_PRIORITY = [
    "NO_CONSENT",          # 1 同意是前提
    "NOT_DISCLOSED",       # 2 告知是同意生效的前提
    "PLAINTEXT_TRANSMIT",  # 3 传输安全
    "NO_MASK",             # 4 存储展示最小化
    "OVER_COLLECT",        # 5 必要性
    "WARNING",
    "COMPLIANT",
]

# GB/T 35273 个人敏感信息（部分脱敏不充分的类型）
SENSITIVE_HIGH = {"ID_CARD", "HEALTH", "BIOMETRIC", "BANK_CARD", "LOCATION", "EXACT_IMAGE"}

# ---------------- 组合类别空间（92，单一事实来源） ----------------
COMBO_CLASSES = ["NONE||COMPLIANT"]
for _dt in DATA_TYPES:
    if _dt == "NONE":
        continue
    for _v in VIOLATIONS:
        COMBO_CLASSES.append(f"{_dt}||{_v}")

COMBO2IDX = {c: i for i, c in enumerate(COMBO_CLASSES)}
IDX2COMBO = {i: c for i, c in enumerate(COMBO_CLASSES)}


def build_combo(data_type: str, violation: str) -> str:
    assert data_type in DATA_TYPES and violation in VIOLATIONS, (data_type, violation)
    return f"{data_type}||{violation}"


def split_combo(combo: str):
    dt, v = combo.split("||")
    return dt, v
