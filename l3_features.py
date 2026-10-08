# -*- coding: utf-8 -*-
"""l3_features.py — L3 分层结构化模型的特征抽取（训练/推理共用，单一事实来源）

契约：输入是 predict.py / train_l3_struct.py 共用的三段文本
      `[platform=X]\\nstack: ...\\nparams: {JSON}`（见 docs/hook_schema_contract.md §1）。

两个特征视图（对应分层模型的两个头）：
    dt_feats(text) → data_type 头：栈帧 API token + payload 键名 + platform
    v_feats(text)  → violation 头：契约信号字段的 键=值（含 <MISSING>）

不依赖 sklearn / numpy（仅 json + re），故可被推理路径安全导入。
"""
import json
import re

# 契约 §2 信号字段（决定 violation 的那一组；新增/改名须同步 policy.py + 契约）
SIG_FIELDS = (
    "consent_state", "consent_scope", "consent_version_expired", "consent_log",
    "policy_disclosed", "policy_updated_after_consent", "crypto", "transport",
    "pii_mask", "biz_purpose", "collect_scope", "extra_fields_collected",
    "retention_days", "data_destination", "separate_consent",
)
_SIG = frozenset(SIG_FIELDS)

_PLAT_RE = re.compile(r"\[platform=([a-z]+)\]")
_API_RE = re.compile(r"at\s+([A-Za-z_][\w.$]*(?:\.[A-Za-z_]\w*))\s*\(")


def split_text(text):
    """→ (platform, stack_part, params_obj)。params 解析失败时返回空 dict（不抛异常）。"""
    m = _PLAT_RE.search(text)
    plat = m.group(1) if m else "?"
    stack = text.split("params:")[0]
    mi = text.find("params:")
    obj = {}
    if mi >= 0:
        try:
            obj = json.loads(text[mi + 7:].strip())
        except Exception:
            obj = {}
    if not isinstance(obj, dict):
        obj = {}
    return plat, stack, obj


def dt_feats(text):
    """data_type 视图：API token / 类名 / payload 键名 / platform。"""
    plat, stack, obj = split_text(text)
    f = {f"plat={plat}": 1}
    for m in _API_RE.findall(stack):
        f[f"api={m}"] = 1
        f[f"cls={m.split('.')[0]}"] = 1
    for k in obj:
        if k not in _SIG:
            f[f"key={k}"] = 1
    return f


def v_feats(text):
    """violation 视图：契约信号字段的 键=值；字段缺失显式记为 <MISSING>（fail-closed 语义）。"""
    _, _, obj = split_text(text)
    f = {}
    for k in SIG_FIELDS:
        if k in obj:
            v = obj[k]
            if isinstance(v, list):
                v = "|".join(sorted(map(str, v)))
            f[f"{k}={v}"] = 1
        else:
            f[f"{k}=<MISSING>"] = 1
    return f


def build_combo(data_type, violation):
    """把两个头拼成 92 类之一；非法组合（如 NONE||NO_MASK）退化为该类型 COMPLIANT。"""
    from labels import COMBO2IDX
    c = f"{data_type}||{violation}"
    if c in COMBO2IDX:
        return c
    fallback = f"{data_type}||COMPLIANT"
    return fallback if fallback in COMBO2IDX else "NONE||COMPLIANT"


# ---------------------------------------------------------------------------
# violation 头的**紧凑编码**（供树模型；实测把 violation macro-F1 从 0.965 → 0.990）
#
# 为什么需要它：`policy.decide` 是信号字段的**布尔合取/析取**（if consent_state==denied
# and scope∌T → NO_CONSENT…）。线性模型在 1-hot 上只能表达**加性**效应，故卡在 0.965；
# 树模型能表达合取。但树模型吃不下 1169 维稀疏 1-hot，故这里编码为**低维稠密**：
#   · consent_scope → 13 个 PII 类型的 0/1（缺失=2），显式表达"范围是否覆盖某类型"
#   · 其余字段 → 类别码（高频保留，低频折叠为 <OTHER>，基数 ≤ CARD_MAX）
# ---------------------------------------------------------------------------
class SigEncoder:
    CARD_MAX = 200
    OTHER_FIELDS = tuple(k for k in SIG_FIELDS if k != "consent_scope")

    def __init__(self):
        self.maps = {}
        self._pii = None

    @staticmethod
    def _scalar(v):
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, list):
            return "|".join(sorted(map(str, v)))
        if v is None:
            return "<NULL>"
        return str(v)

    def _pii_types(self):
        if self._pii is None:
            from labels import DATA_TYPES
            self._pii = [t for t in DATA_TYPES if t != "NONE"]
        return self._pii

    def fit(self, params_objs):
        import collections
        cnt = {k: collections.Counter() for k in self.OTHER_FIELDS}
        for obj in params_objs:
            for k in self.OTHER_FIELDS:
                cnt[k][self._scalar(obj.get(k, "<MISSING>"))] += 1
        for k in self.OTHER_FIELDS:
            self.maps[k] = {v: i for i, v in enumerate(v for v, _ in cnt[k].most_common(self.CARD_MAX))}
        self._pii_types()
        return self

    def transform(self, params_objs):
        import numpy as np
        pii = self._pii_types()
        nf = len(pii) + len(self.OTHER_FIELDS)
        X = np.zeros((len(params_objs), nf), dtype=np.float32)
        for j, obj in enumerate(params_objs):
            cs = obj.get("consent_scope", "__MISSING__")
            if cs == "__MISSING__":
                X[j, :len(pii)] = 2.0
            else:
                s = set(map(str, cs)) if isinstance(cs, list) else {str(cs)}
                for i, t in enumerate(pii):
                    X[j, i] = 1.0 if t in s else 0.0
            for i, k in enumerate(self.OTHER_FIELDS):
                X[j, len(pii) + i] = self.maps[k].get(self._scalar(obj.get(k, "<MISSING>")), -1)
        tail = X[:, len(pii):]
        tail[tail < 0] = np.nan
        return X

    @property
    def categorical_indices(self):
        return list(range(len(self._pii_types()), len(self._pii_types()) + len(self.OTHER_FIELDS)))
