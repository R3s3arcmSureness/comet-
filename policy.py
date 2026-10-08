# -*- coding: utf-8 -*-
"""policy.py — 隐私合规判定策略（生成器 / 规则引擎 共享的唯一事实来源）

★ 本文件即生产策略基线，对应 docs/hook_schema_contract.md 中每个字段的语义与缺省行为。
★ 修订（对照审计 D3）：
  - 补 PIPL「单独同意」：向第三方提供个人信息需 separate_consent
  - 修 NO_MASK 误报：非敏感类型 partial 脱敏视为充分；仅高敏类型（GB/T 35273）要求完全脱敏
  - OVER_COLLECT 建立业务必要性映射（GOOD_PURPOSE，见 apis.py）
  - 缺失字段采用「就高判定」（fail-closed）但有替代证据路径，避免单字段捷径

判定优先级：NO_CONSENT > NOT_DISCLOSED > PLAINTEXT_TRANSMIT > NO_MASK > OVER_COLLECT > WARNING > COMPLIANT
"""

import re

from apis import GOOD_PURPOSE, BAD_CRYPTO
from labels import SENSITIVE_HIGH

# 无效同意状态
CONSENT_NONE_VALUES = {"denied", "not_requested", "revoked"}

# 业务必要性白名单（数据类型 -> 允许的业务目的）
_PURPOSE_OK = {dt: set(v) for dt, v in GOOD_PURPOSE.items()}

# 长留存警告阈值（天）
RETENTION_WARN_DAYS = 365


# ============================================================================
# P0-C 信号字段类型契约与正规化（2026-10-07 红队修复）
# ----------------------------------------------------------------------------
# 红队实测击穿：`policy_disclosed="false"`（字符串）被 `is False` 判为假 →
# NOT_DISCLOSED 被吞 → 判 COMPLIANT。单字段漏判 11.28%、三字段同时 25.53%。
# 根因：判定链用 `is False` / `isinstance(int)` 等**强类型判断**，但上游 JSON 序列化
# 可能把布尔写成字符串、数字写成字符串（JSON 本身合法）。没有任何一层做类型校验。
# 现新增正规化层：**能无歧义转换才转**；不能 → 记入 malformed_keys，由调用方 fail-closed。
# 绝不把"类型不对"静默当成"缺失"或"默认值"——那会吞掉真实违规。
# ============================================================================
_BOOL_KEYS = {"consent_version_expired", "policy_disclosed",
              "policy_updated_after_consent", "extra_fields_collected", "separate_consent"}
_INT_KEYS = {"retention_days"}
_LIST_KEYS = {"consent_scope"}
_STR_KEYS = {"consent_state", "consent_log", "crypto", "transport", "pii_mask",
             "biz_purpose", "collect_scope", "data_destination"}

_BOOL_TRUE = {"true", "1", "yes", "y", "t"}
_BOOL_FALSE = {"false", "0", "no", "n", "f"}

# 合规元数据三要素（同意 / 传输 / 脱敏）。三者全缺 ⇒ 合规模态**不可观测**
_CONSENT_KEYS = {"consent_state", "consent_log", "consent_scope"}
_TRANSPORT_KEYS = {"crypto", "transport"}
_MASK_KEYS = {"pii_mask"}


def normalize_signals(sig: dict):
    """按类型契约正规化信号字段。返回 (norm_sig, malformed_keys)。

    - 布尔字段：bool 直通；"true"/"false"/"1"/"0" 等字符串无歧义转换；
      0/1 整数转换；其余 → malformed。
    - 整数字段：int 直通；纯数字字符串转换；bool（Python 里是 int 子类）→ malformed；
      其余 → malformed。
    - 列表字段 consent_scope：字符串列表直通；逗号串转换；其余 → malformed。
    - 字符串枚举字段：str 直通；数字转 str；其余 → malformed。
    """
    out, bad = {}, []
    for k, v in sig.items():
        if k in _BOOL_KEYS:
            if isinstance(v, bool):
                out[k] = v
            elif isinstance(v, str) and v.strip().lower() in (_BOOL_TRUE | _BOOL_FALSE):
                out[k] = v.strip().lower() in _BOOL_TRUE
            elif isinstance(v, int) and v in (0, 1):
                out[k] = bool(v)
            else:
                bad.append(k)
        elif k in _INT_KEYS:
            if isinstance(v, bool):
                bad.append(k)
            elif isinstance(v, int):
                out[k] = v
            elif isinstance(v, str) and re.fullmatch(r"-?\d+", v.strip()):
                out[k] = int(v.strip())
            else:
                bad.append(k)
        elif k in _LIST_KEYS:
            if isinstance(v, list) and all(isinstance(x, str) for x in v):
                out[k] = v
            elif isinstance(v, str):
                out[k] = [x.strip() for x in v.split(",") if x.strip()]
            else:
                bad.append(k)
        else:
            # 未在契约中的额外键：不参与判定，直接忽略（不产生 malformed）
            if k not in _STR_KEYS:
                continue
            if isinstance(v, str):
                out[k] = v
            elif isinstance(v, (int, float)) and not isinstance(v, bool):
                out[k] = str(v)
            else:
                bad.append(k)
    return out, bad


def metadata_unobservable(sig: dict) -> bool:
    """合规模态是否**完全不可观测**：同意 / 传输 / 脱敏 三要素全缺。

    用于 P0-E「部分识别」：此时既不能断言违规（NO_CONSENT 是猜的），
    也不能断言合规（那是漏判）。学术对应 AISTATS 2024 的 partial identification
    ——无观测变量时给**区间**不给点。
    """
    if any(k in sig for k in _CONSENT_KEYS):
        return False
    if any(k in sig for k in _TRANSPORT_KEYS):
        return False
    if any(k in sig for k in _MASK_KEYS):
        return False
    return True


def _consent_ok(dt, sig):
    """同意有效性：多路径判定。
    返回 True / False / None(None=证据不足，按未同意处理)"""
    cs = sig.get("consent_state")
    if cs is not None:
        if cs in CONSENT_NONE_VALUES:
            return False
        if cs == "granted":
            scope = sig.get("consent_scope") or []
            if dt not in scope:
                return False                       # 同意了但范围不含本类型
            if sig.get("consent_version_expired", False):
                return False                       # 同意版本过期
            return True
        return None                                # 未知状态值 -> 证据不足
    # consent_state 缺失：查替代证据 consent_log（格式 "granted:TYPE,TYPE" / "absent" / "revoked@..."）
    log = sig.get("consent_log")
    if log and log.startswith("granted:"):
        types = [t.strip() for t in log.split(":", 1)[1].split(",") if t.strip()]
        return dt in types
    if log and log.startswith("revoked"):
        return False
    return None                                    # 完全无同意记录 -> 未同意


def decide_ex(data_type: str, sig: dict):
    """核心策略入口（带诊断）。返回 (verdict, malformed_keys, bounds)。

    verdict      : 违规类别 | None（None = **不可判**，调用方必须 fail-closed 转人工）
    malformed_keys: 类型不合契约的字段名列表（非空 ⇒ 证据不可用，verdict 为 None）
    bounds       : None | {"optimistic","pessimistic"}（部分识别区间，仅不可判时给出）

    P0-C：类型不合契约 → 不算"缺失"、也不算"默认值"，而是**证据不可用** → fail-closed。
    P0-E：合规元数据完全不可观测 → 不猜违规也不猜合规，输出区间 + 交人工。
    """
    norm, bad = normalize_signals(sig)
    if bad:
        return None, bad, None

    if data_type == "NONE":
        return "COMPLIANT", [], None

    # P0-E 部分识别：合规元数据完全不可观测
    #   乐观界 = 合规（假设一切都合规）；悲观界 = NO_CONSENT（无任何同意证据）
    #   真实结论在区间内，系统不猜 → 交人工。绝不落 COMPLIANT（漏判），
    #   也绝不默认 NO_CONSENT（红队实测：会把 736 条真值合规 100% 误报为未同意）。
    if metadata_unobservable(norm):
        return None, [], {"optimistic": "COMPLIANT", "pessimistic": "NO_CONSENT",
                          "reason": "compliance_metadata_unobservable"}

    return decide_with(data_type, norm), [], None


def decide(data_type: str, sig: dict) -> str:
    """兼容入口（保持原签名为 str）。供 generate_data 等既有调用方使用。

    注意：**调用方若需要 fail-closed，应改用 `decide_ex`** —— 本函数在"不可判"时
    回退为保守的 NO_CONSENT，以免破坏既有标签生成流程。
    """
    v, _bad, bounds = decide_ex(data_type, sig)
    if v is not None:
        return v
    if bounds:
        return bounds["pessimistic"]
    return "NO_CONSENT"


def decide_with(data_type: str, sig: dict) -> str:
    """核心判定链（输入必须已通过 normalize_signals）。"""
    if data_type == "NONE":
        return "COMPLIANT"                          # 非个人数据不涉隐私

    # 1. 同意
    if _consent_ok(data_type, sig) is not True:
        return "NO_CONSENT"

    # 2. 告知（同意有效后仍需确认告知有效）
    if sig.get("policy_disclosed") is False or sig.get("policy_updated_after_consent") is True:
        return "NOT_DISCLOSED"

    # 3. 传输安全（crypto 与 transport 任一命中即明文）
    if sig.get("crypto") in BAD_CRYPTO or sig.get("transport") == "http":
        return "PLAINTEXT_TRANSMIT"

    # 4. 脱敏（高敏类型 partial 不足；非敏感类型 partial 可接受）
    mask = sig.get("pii_mask")
    if mask == "raw" or (mask == "partial" and data_type in SENSITIVE_HIGH):
        return "NO_MASK"

    # 5. 必要性（业务目的白名单 / 全量采集 / 搭车采集）
    bp = sig.get("biz_purpose")
    if bp is not None and bp not in _PURPOSE_OK.get(data_type, set()):
        return "OVER_COLLECT"
    if sig.get("collect_scope") == "all" or sig.get("extra_fields_collected", False):
        return "OVER_COLLECT"

    # 6. 软风险（警告）
    if sig.get("data_destination") == "third_party" and sig.get("separate_consent") is False:
        return "WARNING"                            # 对外提供缺单独同意
    rd = sig.get("retention_days")
    if isinstance(rd, int) and rd > RETENTION_WARN_DAYS:
        return "WARNING"

    return "COMPLIANT"
