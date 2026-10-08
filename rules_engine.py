# -*- coding: utf-8 -*-
"""rules_engine.py v2 — 确定性规则引擎（生产级修订版）

修订（对照审计报告 D2/D3/D4）：
- 策略唯一来源 = policy.py（与生成器、法务评审对象一致）
- 四端真实 SDK API 目录 = apis.py，按平台匹配方法 token（精确 token，非子串）
- ContentResolver.query 的 SMS/CONTACTS 歧义用 URI 参数消歧
- 缺字段降级：解析不出必要字段时不硬判，输出低置信标记入复核队列
- 输出 {combo, data_type, violation, confidence, source, needs_review, review_reason}
"""
import re
import os
import json
import html as _pyhtml
import base64
import itertools
import unicodedata
import urllib.parse
from collections import Counter
from functools import lru_cache
from policy import decide, decide_ex
from apis import API_INDEX, PLATFORM_APIS
from labels import build_combo, DATA_TYPES

# SMS/CONTACTS 消歧标记（android ContentResolver.query 的 URI 参数）
_URI_SMS = "content://sms"
_URI_CONTACTS = "contactscontract"

# 数据类型关键词（参数回退：payload 键名）
# 【P0 · 2026-10-07 红队修复】原表缺 lat/lng/lon/addr/mac/ssid 等**真实业务键名**，
# 导致 `params: {"uid":123,"lat":31.23,"lng":121.47}` 这类"未收录 SDK + 真实参数"
# 完全不触发任何闸门 → 自动判 NONE||COMPLIANT（红队 D3 实测漏判 85.10%）。
# 注意：键名匹配用 `"key"\s*:` 精确形态，故 `latency_ms` 不会误命中 `lat`。
_PAYLOAD_KEY2DT = {
    "phone": "PHONE", "mobile": "PHONE",
    "idcard": "ID_CARD", "idno": "ID_CARD", "identitycard": "ID_CARD",
    "bankcard": "BANK_CARD", "cardno": "BANK_CARD",
    "imei": "DEVICE_ID", "oaid": "DEVICE_ID", "androidid": "DEVICE_ID",
    "idfa": "DEVICE_ID", "idfv": "DEVICE_ID", "mac": "DEVICE_ID", "serial": "DEVICE_ID",
    "email": "EMAIL", "mail": "EMAIL",
    "name": "NAME", "realname": "NAME", "username": "NAME",
    "image": "EXACT_IMAGE", "photo": "EXACT_IMAGE", "faceimg": "EXACT_IMAGE",
    "avatar": "EXACT_IMAGE", "picture": "EXACT_IMAGE",
    "health": "HEALTH", "medical": "HEALTH", "steps": "HEALTH", "heartrate": "HEALTH",
    "coord": "LOCATION", "lat": "LOCATION", "lng": "LOCATION", "lon": "LOCATION",
    "latitude": "LOCATION", "longitude": "LOCATION", "gps": "LOCATION",
    "addr": "LOCATION", "address": "LOCATION", "geohash": "LOCATION",
    "sms": "SMS", "msg": "SMS", "verifycode": "SMS", "captcha": "SMS",
    "contacts": "CONTACTS", "contactlist": "CONTACTS", "phonebook": "CONTACTS",
    "biometric": "BIOMETRIC", "fingerprint": "BIOMETRIC",
    "cammic": "CAMERA_MIC", "audio": "CAMERA_MIC",
}

SIGNAL_KEYS = ["consent_state", "consent_scope", "consent_version_expired", "consent_log",
               "policy_disclosed", "policy_updated_after_consent", "crypto", "transport",
               "pii_mask", "biz_purpose", "collect_scope", "extra_fields_collected",
               "retention_days", "data_destination", "separate_consent"]

# 数据类型风险排序（Tier5 consent_scope 命中多类型时取最高风险者 = fail-closed）
_DT_RISK_ORDER = ["ID_CARD", "BIOMETRIC", "HEALTH", "BANK_CARD", "LOCATION", "EXACT_IMAGE",
                  "SMS", "CONTACTS", "CAMERA_MIC", "PHONE", "EMAIL", "NAME", "DEVICE_ID"]

# Tier4 键名扫描顺序：越"专有"越靠前，通用键（name/msg/audio）垫底，
# 避免一个含 name 的业务对象把 CONTACTS/ID_CARD 这类更强的证据挤掉。
_TIER4_ORDER = [
    "contacts", "contactlist", "phonebook",
    "idcard", "idno", "identitycard", "bankcard", "cardno",
    "biometric", "fingerprint", "cammic",
    "health", "medical", "heartrate", "steps",
    "verifycode", "captcha", "sms",
    "faceimg", "image", "photo", "avatar", "picture",
    "latitude", "longitude", "coord", "geohash", "lat", "lng", "lon", "gps",
    "addr", "address",
    "imei", "oaid", "androidid", "idfa", "idfv", "mac", "serial",
    "email", "mail",
    "phone", "mobile",
    "realname", "username", "name",
    "msg", "audio",
]


def _detect_platform(text):
    if "[platform=" in text:
        m = re.search(r"\[platform=(\w+)\]", text)
        if m:
            return m.group(1)
    return None


def _detect_stack_platform(text):
    """无 platform 标记时按栈帧特征推断（真实逆向日志无标记的场景）"""
    if re.search(r"-\[[A-Z]\w+ [\w:]+\]", text):
        return "ios"
    if re.search(r"wx\.\w+", text):
        return "miniprogram"
    if re.search(r"@?ohos\.", text, re.I) or re.search(r"\.ets:", text):
        return "harmony"
    if re.search(r"(android|\.java:)", text, re.I):
        return "android"
    return None


# ---------------- 分级识别（应对"部分标识符不可完全解混淆"） ----------------
# 真实场景：上游尽量还原语义名，但部分标识符无法完全解混淆。
# 栈帧形态可能是：① Class.method 全可读 ② 类名可读/方法名混淆(LocationManager.a)
#   ③ 类名混淆/方法名可读(a.getLastKnownLocation) ④ 全混淆(a.a.b)
# 策略：三级识别 + 混淆感知 + fail-closed（识别不了 → 复核，绝不落 NONE→COMPLIANT）。

# 通用/歧义类名（不足以单独定位数据类型）
_GENERIC_CLASS = {"wx", "sim", "sms", "contact", "payment", "oaid", "cloud",
                  "cloudfunction", "ocrplugin", "cameracontext", "user"}

# 敏感语义提示词（用于"API 目录未收录"时的 fail-closed 兜底）
# 场景：规则库不可能穷举所有敏感 API（新增 SDK、老 API、变体名）。若栈帧已出现
# 明确的敏感语义词，却因目录未收录而匹配失败，绝不能判 NONE||COMPLIANT——
# 这会把"采集摄像头/位置/通讯录"漏判为合规。此处改为入人工复核。
# 注意：仅作用于"API 未命中"的分支，已命中的样本不受影响。
_SENSITIVE_HINT_RE = re.compile(
    r"(camera|microphone|mic\b|recordaudio|capturesession|audiomanager|"
    r"location|gps\b|geolocation|geocoder|geocode|coord|latitude|longitude|latlng|"
    r"maps\.googleapis|googleapis\.com/maps|/maps/api|amap\.com|restapi\.amap|"
    r"mapkit|mkmapview|baidumap|gaode|"
    r"contacts|contactlist|phonestate|telephony|telephonymanager|imei|meid|oaid|android_id|"
    r"macaddress|bluetooth|wifimanager|ssid|bssid|advertisingid|idfa|idfv|"
    r"idcard|identitycard|bankcard|creditcard|"
    r"biometric|fingerprint|faceid|facerecogni|iris|"
    r"health|medical|stepcount|werundata|"
    r"smsmanager|mms|calllog|"
    r"calendar|photoalbum|gallery|screenshot|clipboard|media projection)",
    re.I)


# 严格模式：无法区分"真 NONE"与"信号字段违约改名"时，宁可转人工（默认关闭）
_STRICT_NONE = os.environ.get("PC_STRICT_NONE", "0") == "1"
# 间接层提速：允许 payload/consent 层在**非 COMPLIANT** 时自动定论（默认关闭，守契约）
_INDIRECT_AUTOPASS = os.environ.get("PC_INDIRECT_AUTOPASS", "0") == "1"
# 契约 v1.2 判别器：要求 params 必带 consent_scope（非 PII 调用传空数组）
# 【真实日志实证】默认关闭会在真实数据上造成可测漏判：核桃编程 6364 条日志中，
# 默认(=0) 有 600 条敏感调用被自动判 NONE||COMPLIANT（占敏感 25.9%）；开启(=1) 后 0 漏判
# （代价：无 consent_scope 的输入一律转人工）。故默认改为**开启**（安全优先，fail-closed）。
# 见 reports/真实日志评估_最终结论.md。显式设 PC_SCOPE_CONTRACT=0 可退回旧行为。
_SCOPE_CONTRACT = os.environ.get("PC_SCOPE_CONTRACT", "1") == "1"

# ---------------------------------------------------------------------------
# 【第五轮 · 校准阈值 λ】自动放行阈值不再是硬编码 0.9，而是从校准文件读取。
#
# 为什么必须改这里（而不是只改 predict.py）：
#   λ̂ 是"自动出结论的门槛"。若只在 predict.py 生效，任何**直接调用规则引擎**
#   的上游（本项目的 measure_path / redteam / stress / pipeline…）都会绕过 λ̂，
#   于是"已校准"就成了纸面属性。
#
# 保持逐位不变的保证：`calib_runtime.auto_lambda()` 在没有校准文件时**恒为 0.9**，
#   与原 `confidence < 0.9` 完全等价；且 `effective_lambda()` 对间接层强制 ≥0.86、
#   对未获保证的校准集强制 ≥0.9（只能收紧、不能放松）。
#
# 单调性（CRC 的前提）：λ 增大 ⇒ 自动集合收缩 ⇒ 漏判单调不增。见 reports/校准与基础风险_第五轮.md
# ---------------------------------------------------------------------------
from calib_runtime import auto_lambda as _auto_lambda, lambda_info as _lambda_info  # noqa: E402
# 【第五轮 · 纵深防御】声明抽样审计 + 撤销回路（与"内容级"规则**正交**的第二道防线）：
#   规则靠"我们猜得到攻击形态"，抽样靠"服务端密钥决定的不可预测抽样"，
#   撤销靠"一次被骗、永久不信任该声明形态"。三者都**不是**保证来源，
#   保证仍来自 calibrate.py 的 CRC；它们只降低"未知形态"的期望漏判。
from scope_audit import (is_revoked as _sa_revoked, revoke as _sa_revoke,       # noqa: E402
                         selected_for_audit as _sa_selected, status as _sa_status,
                         fingerprint as _sa_fingerprint)


def review_threshold(tier=None):
    """该 tier 的自动放行阈值：confidence < 阈值 ⇒ 转复核。"""
    return _auto_lambda(tier)


def calibration_report():
    """调试/审计：打印各 tier 实际生效的阈值与来源。"""
    out = {}
    for t in ("full", "none_verified", "class", "method", "payload", "consent"):
        eff, src, raised = _lambda_info(t)
        out[t] = {"lambda": eff, "source": src, "raised_by_floor": raised}
    return out


def scope_audit_status():
    """空声明"安全网"健康状态（供 check_runtime 硬闸门使用）。

    语义与 `guard_status()` 一致：**安全网失效必须响亮，绝不静默降级**。
    `contract_on=True` 且 `available=False` ⇒ 部署"只敢开契约、不敢配审计"，
    即空声明的漏判上界退化为 1.0（= 与未开契约同）——必须记 `!!`。
    """
    st = dict(_sa_status())
    st["contract_on"] = bool(_SCOPE_CONTRACT)
    st["degraded"] = bool(_SCOPE_CONTRACT and not st.get("available"))
    return st


def _json_has_keys_no_signal(text):
    """params 是合法 JSON 对象、含 >=1 个键，却一个契约信号字段都没有 → True。"""
    import json
    body = _PARAMS_OF(text).strip()
    if not body:
        return False
    try:
        p, _ = json.JSONDecoder().raw_decode(body)
    except Exception:
        return False
    if not isinstance(p, dict) or len(p) < 1:
        return False
    return not any(k in p for k in SIGNAL_KEYS)


# 【P0-B · 2026-10-07 红队修复】统一的 params 头识别
# 原实现到处硬编码 `text.split("params:")`，对以下**等价写法**全部失明：
#   `params :`（冒号前多空格）、`Params:`/`PARAMS:`（大写）、`params:  `（冒号后空格）
# 失明后果（已实测）：与"未收录 SDK"叠加时输出 `NONE||COMPLIANT` 且 **needs_review=False**
#   → 真漏判。样例：
#     [platform=android]\nstack: com.cloud.bridge.Sync.pull(X.kt:1)\nparams : {"consent_state":"denied",...}
#     → 修复前 NONE||COMPLIANT（不进复核）；修复后 UNKNOWN||UNKNOWN（进复核）
# 故改为**大小写不敏感 + 容忍冒号两侧空白**的单一事实来源。
_PARAMS_HEAD_RE = re.compile(r"params\s*:\s*", re.I)


def _split_params(text):
    """返回 (stack_part, params_body)。无 params 头时 body 为空串。"""
    m = _PARAMS_HEAD_RE.search(text)
    if not m:
        return text, ""
    return text[:m.start()], text[m.end():]


def _STACK_OF(text):
    """取 params 段之前的栈帧部分。"""
    return _split_params(text)[0]


def _PARAMS_OF(text):
    """取 params 段之后的参数体（无则返回空串）。"""
    return _split_params(text)[1]


def _sensitive_hint_in_stack(stack_line, params_tail=""):
    """在栈帧的「类名.方法名」段匹配敏感词，忽略包路径前缀。

    原因：`cn.com.sdk.location.core.ClientBridge.invoke` 这类噪声栈里 `location`
    出现在**包名**中，若整行匹配会把非敏感调用误送复核。取每段标识符的最后两段
    （类名.方法名）再匹配，可显著降低误伤，同时保留对 `Camera.open` /
    `LocationManager.getLastKnownLocation` 这类真敏感 API 的捕获。

    【第三轮复审修复·params 段盲区】原实现只扫栈帧段。但"API 目录未收录"时，
    `params` 段同样是敏感语义的富集区——例如未知 SDK 把定位查询放进参数：
        params: {"url":"https://maps.googleapis.com/maps/api/geocode/json?latlng=31.23,121.47"}
    此时栈帧 `com.z.y.Z.a` 无语义、params 却明摆着是地理定位，原实现会漏判为
    `NONE||COMPLIANT`。故对 params 段做**整段**匹配（无需取尾段，因为参数里没有
    包名噪声）。实测在 3 万条干净数据上不产生任何额外复核触发。
    """
    for m in re.finditer(r"[A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)*", stack_line):
        parts = m.group(0).split(".")
        tail = ".".join(parts[-2:]) if len(parts) >= 2 else m.group(0)
        if _SENSITIVE_HINT_RE.search(tail):
            return True
    if params_tail and _SENSITIVE_HINT_RE.search(params_tail):
        return True
    return False


# ---------------- dtype 交叉校验哨兵（独立信号路径的 fail-closed 复核）----------------
# 由来：第三轮多 Agent 复审确认，规则引擎的残余漏判暴露面只剩一种 ——
#   API 目录未收录 + 标识符不含敏感语义 + 无混淆痕迹 → 会判 NONE||COMPLIANT。
# 决定性实验（本机 CPU，秒级）：
#   · policy.decide(dtype, signals) -> violation  : acc 1.000000  ⇒ 违规是确定性函数，不该"学"
#   · TF-IDF(char_wb 2-4gram) text -> dtype(14类) : acc 1.000000  ⇒ 数据类型用普通线性模型即满分
#   · mmBERT-small (8000×2ep, 3.8h) 92类: 0.4514（dtype 0.9999 / violation 0.4514）
#     ⇒ 40h 微调在 dtype 上并未超过 3 秒的 TF-IDF
# 故把"模型"用在它真正可学的子任务（数据类型）上，并作为规则 token 表的**独立交叉校验**。
# 实测（test 20000 / OOD 10000）：哨兵在 NONE 子集上的升级率 0.0000% → 零额外复核成本。
# 若 `models/dtype_guard.pkl` 不存在或缺 sklearn，本哨兵静默失效，绝不影响主判路径。
# 用 PC_DTYPE_GUARD=0 可显式关闭。
_GUARD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "models", "dtype_guard.pkl")
# 零依赖版哨兵（纯 Python 字符 3-gram + 哈希桶 NB，由 train_dtype_guard_pure.py 产出）。
# 存在的意义：原 sklearn 版在缺 sklearn 时会整体失效；有了它，安全网不再依赖外部包。
_PURE_GUARD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "models", "dtype_guard_pure.pkl")
_GUARD_ENABLED = os.environ.get("PC_DTYPE_GUARD", "1") != "0"
_GUARD = None
_GUARD_KIND = None
_GUARD_TRIED = False
# 【P0-A · 2026-10-07 红队修复】哨兵状态显式化
# 原实现的致命问题：`except Exception: _GUARD = None` —— 缺 sklearn、模型损坏、
# 版本不符统统静默降级为"无意见"，于是号称的"第 5 道闸门"在**无人知晓**的情况下消失。
# 红队实测：本机两个 Python 都没有 sklearn ⇒ _GUARD 恒为 None ⇒ 实际只有 4 道闸门。
# 这与 deploy_gate 的三条 fail-open 路径是同一类错误：**安全网失效必须响亮**。
# 现记录原因并对外暴露 `guard_status()`，由 check_runtime / 部署闸门强制检查。
_GUARD_STATUS = {"available": None, "reason": "not_tried", "kind": None, "path": _GUARD_PATH}


def guard_status():
    """返回 dtype 哨兵的健康状态。

    {"enabled","available","kind","reason","path","path_pure"}
      kind   ∈ {"sklearn","pure",None}
      reason ∈ {"ok","disabled","model_missing","dependency_missing","load_error:<Exc>","not_tried"}
    """
    _ensure_guard_tried()
    return {"enabled": _GUARD_ENABLED, "path": _GUARD_PATH,
            "path_pure": _PURE_GUARD_PATH, **_GUARD_STATUS}


def _ensure_guard_tried():
    """两級回退加载哨兵，并记录失败原因（绝不静默）。

    优先 sklearn 版（若其依赖可用），否则用**零依赖**的纯 Python 版。
    """
    global _GUARD, _GUARD_KIND, _GUARD_TRIED
    if _GUARD_TRIED:
        return
    _GUARD_TRIED = True
    if not _GUARD_ENABLED:
        _GUARD_STATUS.update(available=False, reason="disabled", kind=None)
        return

    import pickle
    dep_err = None
    # ---- 一级：sklearn 版 ----
    if os.path.exists(_GUARD_PATH):
        try:
            with open(_GUARD_PATH, "rb") as f:
                obj = pickle.load(f)
            if isinstance(obj, dict) and {"vec", "clf", "classes"} <= set(obj):
                _GUARD, _GUARD_KIND = obj, "sklearn"
                _GUARD_STATUS.update(available=True, reason="ok", kind="sklearn")
                return
            dep_err = "load_error:bad_schema(sklearn)"
        except ImportError as e:
            dep_err = f"dependency_missing:{e}"
        except Exception as e:                       # noqa: BLE001
            dep_err = f"load_error:{type(e).__name__}(sklearn)"

    # ---- 二级：零依赖纯 Python 版 ----
    if os.path.exists(_PURE_GUARD_PATH):
        try:
            with open(_PURE_GUARD_PATH, "rb") as f:
                obj = pickle.load(f)
            if isinstance(obj, dict) and {"classes", "B", "logp", "prior"} <= set(obj):
                _GUARD, _GUARD_KIND = obj, "pure"
                _GUARD_STATUS.update(available=True, reason="ok", kind="pure")
                return
            _GUARD_STATUS.update(available=False, kind=None,
                                 reason="load_error:bad_schema(pure)")
            return
        except Exception as e:                       # noqa: BLE001
            _GUARD_STATUS.update(available=False, kind=None,
                                 reason=f"load_error:{type(e).__name__}(pure)")
            return

    _GUARD_STATUS.update(available=False, kind=None, reason=dep_err or "model_missing")


def _guard_says_sensitive(text):
    """返回哨兵高置信认定的**敏感数据类型**名；无意见/不可用则返回 None。"""
    _ensure_guard_tried()
    if _GUARD is None:
        return None
    try:
        if _GUARD_KIND == "sklearn":
            X = _GUARD["vec"].transform([text])
            cls = _GUARD["classes"][int(_GUARD["clf"].predict(X)[0])]
            return None if cls == "NONE" else cls
        # 纯 Python NB：字符 3-gram → 哈希桶 → 逐类打分
        from train_dtype_guard_pure import grams, bucket   # 复用同一套特征定义
        from collections import Counter as _C
        B_ = _GUARD["B"]
        prior = _GUARD["prior"]
        flat = _GUARD["logp"]
        classes = _GUARD["classes"]
        gs = _C(bucket(g) for g in grams(text))
        best_c, best_s = 0, None
        for ci in range(len(classes)):
            base = ci * B_
            s = prior[ci]
            for b, cnt in gs.items():
                s += flat[base + b] * cnt
            if best_s is None or s > best_s:
                best_s, best_c = s, ci
        cls = classes[best_c]
        return None if cls == "NONE" else cls
    except Exception:
        return None


def _build_class_index():
    """类/模块名 token -> data_type 集合（用于方法名被混淆、类名可读的场景）"""
    idx = {}
    for plat, m in PLATFORM_APIS.items():
        d = {}
        for dt, apis in m.items():
            for a in apis:
                if " " in a:                       # ios 风格 "CLLocationManager startUpdatingLocation"
                    cls = a.split(" ", 1)[0]
                elif "." in a:                     # android/harmony/miniprogram 风格
                    head = a.rsplit(".", 1)[0]
                    cls = head.split(".")[-1]
                else:
                    cls = a
                cl = cls.lower()
                if len(cl) >= 5 and cl not in _GENERIC_CLASS:
                    d.setdefault(cl, set()).add(dt)
        idx[plat] = d
    return idx


def _method_of(a):
    """从 API token 提取方法名部分（用于类名被混淆、方法名可读的场景）"""
    if " " in a:                       # ios 风格 "CLLocationManager startUpdatingLocation"
        parts = a.split(" ", 1)
        return parts[1] if len(parts) > 1 else a
    if "." in a:
        return a.rsplit(".", 1)[-1]
    return a


def _build_method_index():
    """方法名 token -> data_type 集合。
    门槛：长度≥8 且（长度≥10 或 含≥2 个大写驼峰词）——排除 query/get/start 等通用词误报。
    通用方法名（query/start/open/read…）一律不入索引。"""
    idx = {}
    for plat, m in PLATFORM_APIS.items():
        d = {}
        for dt, apis in m.items():
            for a in apis:
                mth = _method_of(a)
                ml = mth.lower()
                n_caps = sum(1 for c in mth if c.isupper())
                if len(mth) >= 8 and (len(mth) >= 10 or n_caps >= 2):
                    d.setdefault(ml, set()).add(dt)
        idx[plat] = d
    return idx


_CLASS_TOKEN_INDEX = _build_class_index()
_METHOD_TOKEN_INDEX = _build_method_index()

# 混淆标识符特征：类名与方法名均为极短符号（ProGuard/R8 典型 a.a( / a.b(）
_OBF_JAVA_RE = re.compile(r"(?<![a-z0-9])([a-z][a-z0-9]?)\.([a-z][a-z0-9]?)(?=\s*\()")
# iOS 混淆：-[a b] / -[a bc]
_OBF_IOS_RE = re.compile(r"-\[\s*[a-z]{1,2}\s+[a-z][a-z0-9]?\s*\]")


def detect_obfuscation(text):
    """栈帧中是否存在"无法解混淆的短标识符"痕迹（用于 NONE 的 fail-closed 判定）。
    只对 stack 部分检测，且要求两个极短段相邻成调用形态，防误报。"""
    stack = _STACK_OF(text)
    if _OBF_JAVA_RE.search(stack) or _OBF_IOS_RE.search(stack):
        return True
    return False


# 【第五轮 · A4 子串伪歧义】被"最长命中获胜"规则抑制掉的 hit（审计用）。
# 抑制本身安全（见 _resolve_data_type Tier1 注释），且**在干净语料上就是非零的**：
# 实测 test+OOD 共 30000 条 → NAME×555、EXACT_IMAGE×285，但**零条 verdict 变化**
#   （因为同一条记录另有 payload 键名证据，`_disambiguate` 的 pref 规则已先一步消歧，
#    根本没走到"多 dt 冲突"分支）。该计数是**基线可观测值**：
#   · A4 修复的价值只在"键名失明"（未收录 SDK + 无信号键）时兑现 —— 那时它把
#     "伪歧义→白转人工"变成"用可信的长 token 直接定类型"。
#   · 若该计数**显著偏离基线**（例如 NAME 数暴涨），说明有人用"长 token 掩埋短 token"，
#     值得告警。故保留为可观测计数器，而不是静默丢弃。
_SUPPRESSED_HITS = Counter()


def suppressed_substring_hits():
    """返回被抑制的 hit 计数（供审计/回归断言）。"""
    return dict(_SUPPRESSED_HITS)


def _disambiguate(dts, text, tier):
    """多义消歧。返回 **(data_type_or_None, ambiguous_flag)**。

    【第五轮修复 · 红队 D4 —— 一个真实的漏判通道】
    原实现：`pref` 非空取 `sorted(pref)[0]`，否则 `sorted(s)[0]` —— 都是**按字母序猜**。
    这不只是"不优雅"：不同数据类型的违规结论不同，猜错类型会直接产出**错误的自动结论**
    （把 `NAME||NO_CONSENT` 洗成 `CONTACTS||COMPLIANT` = 真漏判）。
    更隐蔽的是：本项目的合成数据恰好让字母序"猜对"，所以回归测试**看不见**这个缺陷 ——
    这正是"合成数据自证"的典型陷阱。

    现改为三条 fail-safe 规则（**绝不使用字母序**）：
      1. 只有一条 payload 证据 → 采用（有证据，非猜测）。
      2. 多条 payload 证据**冲突** → 按 `_DT_RISK_ORDER` 取**风险最高**者（确定性、
         且取向保守），并置 ambiguous=True ⇒ 上层把 tier 标为 `full_ambiguous`，
         于是 INV-1' 会自动阻断"证据冲突下自动判 COMPLIANT"这条漏判通道
         （同时保留非 COMPLIANT 结论的自动能力，不白增人工）。
      3. 无 payload 证据 → None（交复核，不猜）。
    """
    s = set(dts)
    if not s:
        return None, False
    if len(s) == 1:
        return next(iter(s)), False
    low = text.lower()
    pref = [d for d in s if any(
        re.search(r'"' + k + r'"\s*:', low)
        for k, d2 in _PAYLOAD_KEY2DT.items() if d2 == d)]
    if len(pref) == 1:
        return pref[0], False
    if len(pref) > 1:
        order = {d: i for i, d in enumerate(_DT_RISK_ORDER)}
        return min(pref, key=lambda d: order.get(d, len(order))), True
    return None, True                      # 无证据：转复核，绝不猜


def _class_token_hits(stack, platform):
    plats = [platform] if platform else list(_CLASS_TOKEN_INDEX.keys())
    hits = []
    for plat in plats:
        for cl, dts in _CLASS_TOKEN_INDEX.get(plat, {}).items():
            if re.search(r"(?<![a-z0-9])" + re.escape(cl) + r"(?![a-z0-9])", stack):
                hits.extend(dts)
    return hits


def _method_token_hits(stack, platform):
    plats = [platform] if platform else list(_METHOD_TOKEN_INDEX.keys())
    hits = []
    for plat in plats:
        for ml, dts in _METHOD_TOKEN_INDEX.get(plat, {}).items():
            if re.search(r"(?<![a-z0-9])" + re.escape(ml) + r"(?![a-z0-9])", stack):
                hits.extend(dts)
    return hits


def _resolve_data_type(text, platform=None):
    """分级识别。返回 (data_type_or_None, tier)。tier ∈ full/class/payload/none"""
    stack = _STACK_OF(text).lower()
    plats = [platform] if platform else list(API_INDEX.keys())

    # Tier 1：完整 API token 匹配（最可靠）
    # 【第五轮 · A4 子串伪歧义 —— 一次"证据去噪"，非"证据删减"】
    # token 匹配刻意用**子串**（让 `ImageCapture.takePicture` 能命中
    # `CameraXImageCapture.takePicture` 这类前缀变体），代价是：
    #   若 token S 是 token L 的**真子串**且两者都收录，则文本含 L 时**必然**也匹配 S，
    #   同一处 API 于是产生两个 dt ⇒ **伪歧义** ⇒ 白转人工（甚至按风险序取到错误 dt）。
    # 全库实测**仅 2 对**碰撞：accountmanager.getaccounts(NAME) ⊂ …getaccountsbytype(EMAIL)
    #   （异 dt ⇒ 真伪歧义）；imagecapture.takepicture ⊂ camerax…（同 dt ⇒ 无影响）。
    # 规则：命中集里若某变体是**另一命中变体**的真子串，则丢弃 —— 它的出现完全被更长的
    #   那次命中解释，**信息量为 0**，保留它只会制造噪声。
    # 安全性论据：真正会"丢证据"的唯一情形是**两个 API 各自成帧同时出现**；
    #   实测 test+OOD 共 30000 条中该情形出现 **0** 次（见 rt_scratch 分析），
    #   且被丢弃的 hit 记入 `_SUPPRESSED_HITS` 可审计。
    _matched = []                                   # [(variant, dts)]
    hits = []
    for plat in plats:
        for token, dts in API_INDEX.get(plat, {}).items():
            variants = (token, token.replace(".", " "))
            vit = next((v for v in variants if v in stack), None)
            if vit is None:
                continue
            if token == "contentresolver.query":
                if _URI_CONTACTS in stack:
                    hits.append("CONTACTS")
                elif _URI_SMS in stack:
                    hits.append("SMS")
                continue
            _matched.append((vit, dts))
    _vs = [m[0] for m in _matched]
    for _v, _dts in _matched:
        if any(_v != _w and _v in _w for _w in _vs):
            for _d in _dts:
                _SUPPRESSED_HITS[_d] += 1
            continue
        hits.extend(_dts)
    if hits:
        dt, amb = _disambiguate(hits, text, "full")
        if dt is None:
            # 【第五轮修复】原为 (None, "none")：tier="none" 会让上层 dt-为-None 分支
            # 继续走完其余闸门、最终可能落到 none_verified ⇒ 自动判 NONE||COMPLIANT。
            # 这等于"Tier1 明明命中了 API，却因消歧失败被洗成非 PII" = 真漏判通道
            # （红队实测：未收录 SDK 或 payload 值伪装时可达）。
            return (None, "full_ambiguous")
        return (dt, "full_ambiguous" if amb else "full")

    # Tier 2：仅类名 token 匹配（方法名被混淆时仍可定位数据类型）
    hits2 = _class_token_hits(stack, platform)
    if hits2:
        dt, _amb = _disambiguate(hits2, text, "class")
        return (dt, "class") if dt else (None, "class_ambiguous")

    # Tier 3：仅方法名 token 匹配（类名被混淆、方法名可读的场景）
    hits3 = _method_token_hits(stack, platform)
    if hits3:
        dt, _amb = _disambiguate(hits3, text, "class")
        return (dt, "method") if dt else (None, "method_ambiguous")

    # Tier 4：payload 键名回退（按特异性排序：越具体越靠前，避免"通用键"抢占）
    low = text.lower()
    for k in _TIER4_ORDER:
        if re.search(r'"' + re.escape(k) + r'"\s*:', low):
            return (_PAYLOAD_KEY2DT[k], "payload")

    # Tier 5：同意范围回退（consent_scope 是**结构化语义信号**，与 API 名完全独立）
    # 由来（2026-10-07 压力测试定位到的真实漏判）：
    #   栈帧 API 名未收录 + payload 键名不可读时，引擎直接落 NONE||COMPLIANT；
    #   但 params 里 `"consent_scope": ["BANK_CARD","NAME","PHONE"]` 明摆着写了被采集的类型。
    #   实测（未见 SDK 压力测试 S2）：漏判率从 0 恶化到 26.86%（671/3000 条）。
    # 语义：同意范围 = 本次调用**声明要采集**的数据类型。空数组/缺失不触发。
    # 注意：本层是**间接推断**，其 COMPLIANT 结论一律降级复核（见 classify 的 INV-1'）。
    m5 = re.search(r'"consent_scope"\s*:\s*\[([^\]]*)\]', text, re.I)
    if m5:
        names = set(re.findall(r'"([A-Za-z_]+)"', m5.group(1)))
        cand = [d for d in _DT_RISK_ORDER if d in names]     # 取风险最高者（fail-closed）
        if cand:
            return (cand[0], "consent")

    return (None, "none")


def detect_data_type(text, platform=None):
    """向后兼容：返回数据类型字符串（无法识别返回 None）。"""
    dt, _ = _resolve_data_type(text, platform)
    return dt


def parse_signals(text):
    """从 params 段解析信号字段。返回 (sig, parsed_ok, missing_keys)

    【P0-B · 2026-10-07 红队修复】
    原实现 `re.search(r"params:\\s*(\\{.*\\})\\s*$", text, re.S)` 有两个致命前提：
      ① 依赖字面量 `params:` 与整串末尾锚定 —— JSON 后有尾随内容（换行/注释/后续文本）即失配；
      ② 且**无论如何都返回 parsed_ok=True**，使"解析失败"与"字段缺失"不可区分，
         调用方无法 fail-closed（红队报告 A3 的根因之一）。
    现改为：
      · 用 `_PARAMS_OF` 取参数体（大小写不敏感、容忍空格）；
      · 用 `json.JSONDecoder().raw_decode` 解析，**允许尾随内容**；
      · 解析不出 dict 时退回逐字段正则；若两者都拿不到 → **parsed_ok=False**（fail-closed）。
    """
    import json
    body = _PARAMS_OF(text).strip()
    if not body:
        return {}, False, list(SIGNAL_KEYS)
    p = None
    try:
        p, _ = json.JSONDecoder().raw_decode(body)     # 允许 JSON 之后有尾随内容
    except Exception:
        p = None
    if not isinstance(p, dict):
        # 退回正则逐字段抓取（JSON 截断等异常）；抓不到任何字段即判解析失败
        p = {}
        for k in SIGNAL_KEYS:
            km = re.search(r'"' + k + r'"\s*:\s*(\[[^\]]*\]|"?[^,}]*"?)', body)
            if km:
                v = km.group(1).strip().strip('"')
                p[k] = v
        if not p:
            return {}, False, list(SIGNAL_KEYS)
    sig = {k: p[k] for k in SIGNAL_KEYS if k in p}
    missing = [k for k in SIGNAL_KEYS if k not in sig]
    return sig, True, missing


# ── 值级 PII 形态检测（第五轮 · 堵住"空声明换自动合规"的可达漏判）─────────────
# 与 `_PAYLOAD_KEY2DT`（看**键名**）互补：上游把 PII 放进中性键名（`event`/`uid`/`f1`）
# 甚至 base64 编码时，键名层完全失明，但**值的形态**依然在。
# 红队实测（可达、100% 成功）：栈帧用未收录 SDK + `consent_scope: []`（自称不涉及个人信息）
#   params: {"consent_scope": [], "event": "13800138000", "ts": 1712345678}
# → 修复前：自动判 `NONE||COMPLIANT`、needs_review=False = **真漏判**。
# 本检测只在"上游**显式声明空**"时启用（干净数据里显式空声明出现 0 次 ⇒ 零回归，已实测）。
# 【第五轮 · 独立复核 V2 修复】形态字典按"归一化需求"**分两类**：
#   数字类（手机/身份证/银行卡）：先折叠所有**数字等价写法**再匹配；
#   结构类（邮箱/坐标/长编码串）：保留 `.` `,` 等结构字符，只做字符级等价替换。
# 原实现把两者混在一个 `^…$` 字典里、只做一种归一化 ⇒ 红队 22 种真实等价写法全逃逸
# （`138_0013_8000` / `١٣٨…`(阿拉伯-印度数字) / `1.3800138e10` / `013800138000` …），
# 且当时**仅**靠可关闭的 dtype 哨兵兜住 —— 违反"主规则必须独立成立"的分层原则。
_MOBILE_CORE = r"1[3-9]\d{9}"                       # 11 位手机号主体
_MOBILE_PFX = r"(?:0086|00|86|0)?"                  # 国际区号 / 中继前缀（可选）
_MOBILE_LEAD = r"0*"                                # 补齐零（`0138…`、`00138…`）
_DIGIT_SHAPES = {
    # 先试手机（最具体），再身份证，最后银行卡（最宽）—— 顺序即优先级。
    "mobile":   re.compile(r"^" + _MOBILE_PFX + _MOBILE_LEAD + _MOBILE_CORE + r"$"),
    "idcard":   re.compile(r"^(?:\d{17}[\dXx]|\d{15})$"),           # 身份证
    "bankcard": re.compile(r"^\d{16,19}$"),                         # 银行卡
}
# 坐标的**单个分量**。第三轮独立复核用"度分秒"与"带度号"两种写法再次推翻：
#   `31°13'48"N,121°28'12"E`（DMS）与 `31.23°,121.47°`（带 °）
# 故分量有两种合法形态：① 十进制度数（可选 `°`）② 度分秒。半球后缀可选。
_COORD_DEC = r"-?\d{1,3}\.\d{2,}\s*(?:°\s*)?[NSEWnsew]?"
_COORD_DMS = (r"-?\d{1,3}\s*°\s*\d{1,2}(?:\.\d+)?\s*['′]\s*\d{1,2}(?:\.\d+)?\s*[\"″]?\s*"
              r"[NSEWnsew]?")
_COORD_COMP = r"(?:" + _COORD_DEC + r"|" + _COORD_DMS + r")"
# 分隔符放宽到 `, ; | /` 与空白（原实现只认逗号）。
_COORD_SEP = r"\s*[,;|/]\s*"
# 【第四轮复核】**单分量**坐标：`31°13'48"N`、`31.23°` 本身就是明确的地理记法。
# 判别器是 `°` —— 没有度号的裸小数（`3.14`、版本号、价格）**不**算坐标，
# 否则会把正常数值字段全打成 PII（这正是单分量检测此前没做的原因）。
_COORD_DEG = (r"-?\d{1,3}(?:\.\d+)?\s*°\s*"
              r"(?:\d{1,2}(?:\.\d+)?\s*['′]\s*\d{1,2}(?:\.\d+)?\s*[\"″]?\s*)?"
              r"[NSEWnsew]?")
_STRUCT_SHAPES = {
    "email":  re.compile(r"^[\w.+-]+@[\w-]+\.[\w.]{2,}$"),
    "coord":  re.compile(r"^" + _COORD_COMP + _COORD_SEP + _COORD_COMP + r"$"),
    "coord1": re.compile(r"^" + _COORD_DEG + r"$"),
    "opaque": re.compile(r"^[A-Za-z0-9+/=_-]{32,}$"),               # 长 token / 编码串
}
# opaque 的**降噪例外**：纯 hex 且长度恰为 32/40/64（MD5/SHA-1/SHA-256 形态）通常是
# 合法摘要/会话指纹，不视为 PII 证据。注意这不削弱攻击覆盖：把手机号 hex 编码得到
# 22 个 hex 字符（≠32），由下面的"解码后复检"路径捕获，不依赖 opaque 命中。
_OPAQUE_HEX_EXEMPT = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
# 同理，标准 UUID（8-4-4-4-12 的 hex）在调用链里是**极常见的非 PII 标识**
# （trace id / request id / 会话 id）。`opaque` 的 32 字符阈值会把它们全吞进来，
# 在空声明分支造成无谓的转人工。故按其**规范形态**豁免；注意这不削弱攻击覆盖：
# 手机号 hex 编码只 22 个 hex 字符（≠36），base64 只 16 字符，都落不进 UUID 形态。
_OPAQUE_UUID_EXEMPT = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_B64_STD_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_B32_RE = re.compile(r"^[A-Z2-7]+$")
_B64_URLSAFE = str.maketrans("-_", "+/")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
# URL 百分号编码（`%31%33%38…`）。第三轮复核用单层/双层 URL 编码各打一次。
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")

# 内嵌形态：值不是**整串**恰好是 PII，而是把 PII **夹在别的文本里**
# （`tel:13800138000`、`uid=110101199003074518&v=1`、`pos(31.23,121.47)`）。
# 上面两个字典全是 `^…$` 锚定，对这类一律失明 ⇒ 廉价规避。
# 故补一组**子串**正则，并用数字边界 `(?<!\d)…(?!\d)` 防误报：
# 13 位毫秒时间戳 `1712345678901` 不会命中手机号（其 11 位子串右侧仍紧邻数字）。
_EMBEDDED_SHAPES = {
    "mobile":   re.compile(r"(?<!\d)" + _MOBILE_PFX + _MOBILE_LEAD + _MOBILE_CORE + r"(?!\d)"),
    "idcard":   re.compile(r"(?<!\d)\d{17}[\dXx](?![\dXx])"),
    "bankcard": re.compile(r"(?<!\d)\d{16,19}(?!\d)"),
    "email":    re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}"),
    # 【第三轮复核】内嵌坐标同样要支持度分秒/带度号写法（`pos(31°13'48"N,…)`），
    # 否则锚定路径修了、内嵌路径仍是十进制-only ⇒ 同一规避换个外壳就回来。
    "coord":    re.compile(r"(?<![\d.])" + _COORD_COMP + _COORD_SEP + _COORD_COMP + r"(?![\d.])"),
    "coord1":   re.compile(r"(?<![\d.])" + _COORD_DEG + r"(?![\d.])"),
}
# 注意：**不**做 opaque 的内嵌扫描（长串内嵌会误报过多，且收益低）。


def _shape_search(s):
    """在 s **内部**查找 PII 形态（返回形态名或 None）。

    【第六轮对抗复核 D1 · DoS 修复】email 内嵌正则 `"[\\w.+-]+@[\\w-]+\\.[\\w.]{2,}"`
    带多个无界量词：search 从每个起点做贪心回溯 ⇒ O(n²)。
    【第七轮对抗复核 D1b】V6 的"无 @ 才跳过"预筛**只治了一半**：
    `"a"*100000 + "@"`（有 @ 但匹配失败）实测 90 秒。
    → 根治：email 改为 **@ 定位 + 定长窗口**匹配——finditer 找出每个 `@`，
    只在两侧 ±80 字符窗口内跑正则（RFC 5321 本地部分 ≤64 字符，窗口足够）；
    复杂度 O(n + @数 × 窗口²)。@ 数量 >256 ⇒ 直接判 email 命中
    （正常调用不会有 256 个 @；fail-closed 方向）。
    其余形态（手机/身份证/银行卡/坐标）量词均有界，线性开销，无需预筛。"""
    for name, pat in _EMBEDDED_SHAPES.items():
        if name == "email":
            if _email_embedded_hit(s):
                return name
            continue
        if pat.search(s):
            return name
    return None


_EMAIL_LOCAL_MAX = 64             # RFC 5321 本地部分上限（超过即非合法邮箱）
_EMAIL_DOMAIN_MAX = 512           # 域名标签扫描上限（达到仍未闭合 ⇒ fail-closed）
_EMAIL_MAX_AT = 256               # @ 数量超过此值 ⇒ 直接判命中（fail-closed）
_EMAIL_LOCAL_CH = re.compile(r'[\w.+\-"]')   # 含 `"`：RFC 5321 quoted-string local（`"a"@b.com`）
_EMAIL_DOMAIN_CH = re.compile(r"[\w\-]")


def _email_embedded_hit(s):
    """@ 定位 + **结构化**扫描的 email 内嵌检测（复杂度有界，无正则回溯）。

    【第八轮对抗复核 A 修补】V7 的"±80 定长窗口"存在**窗口切割**漏洞：
    `a@"+"é"*100+".com"` 的域名标签 100 个 é，`.com` 被截在窗口外 ⇒ 漏判。
    定长窗口的思路本身有缺陷——窗口边界天然可被超长标签攻破。
    → 改为**结构化**扫描：@ 两侧沿 `\\w` 边界走完（本地 ≤64、域名 ≤512），
    不再切割；域名达到 512 仍未闭合 ⇒ 直接 fail-closed（超长标签本就异常）。
    复杂度：每个 @ 最多扫 64+512 字符，@ 数 ≤256 ⇒ O(256·576)，有界。
    判定条件对齐原正则 `[\\w.+-]+@[\\w-]+\\.[\\w.]{2,}`：
      local ≥1 个合法字符；@ 与 `.` 之间 ≥1 个域名字符；`.` 后 ≥2 个域名字符。
    """
    n_at = 0
    idx = s.find("@")
    while idx != -1:
        n_at += 1
        if n_at > _EMAIL_MAX_AT:
            return True
        # 本地部分：向左沿 [\w.+-] 走，上限 64
        i = idx - 1
        while i >= 0 and _EMAIL_LOCAL_CH.match(s[i]):
            i -= 1
            if idx - i > _EMAIL_LOCAL_MAX:
                break
        if idx - i - 1 < 1:                    # 无本地部分
            idx = s.find("@", idx + 1)
            continue
        # 域名部分：向右沿 [\w.-] 走，上限 512；记录第一个 `.` 位置
        j = idx + 1
        dcnt = 0
        dot_pos = -1
        while j < len(s) and dcnt < _EMAIL_DOMAIN_MAX:
            ch = s[j]
            if ch == ".":
                if dot_pos < 0:
                    dot_pos = j
            elif not _EMAIL_DOMAIN_CH.match(ch):
                break
            j += 1
            dcnt += 1
        if dcnt >= _EMAIL_DOMAIN_MAX:
            return True                        # 超长域名标签未闭合 ⇒ fail-closed
        if dot_pos > idx + 1 and j - dot_pos - 1 >= 2:
            return True
        idx = s.find("@", idx + 1)
    return False


# 【独立复核 C2+V2 修复】形态匹配的**归一化管线**（三级，互补）。
#
# 历史教训（两次独立复核都打在这里）：
#   C2 报告 5 类廉价规避（`138-0013-8000` / 空格 / 全角 / 破折号 / 逗号坐标）；
#   我修完只加了一种"去分隔符"，V2 复核随即用 22 种**真实等价写法**推翻普适断言
#   （`١٣٨…` 阿拉伯-印度数字、`\u200b` 零宽、字面 `\u0031` 转义、`1.3800138e10`
#   科学计数法、`{"event":13800138000}` JSON 数字、`{"a":"138","b":"00138000"}`
#   分片拼接…），且这些当时**仅**被可关闭的 dtype 哨兵兜住。
# 根因是方法论错误：把"归一化"当成**可选项**而非**必需环节**，且只做一层。
# 现管线：
#   ① 字符级等价 `_text_variants`：去字面转义 / NFKC / 去零宽 / 折数字同形字
#   ② 数字级规范化 `_digit_canon`：去全部分隔符 / 展开科学计数法 / 归一 `.0` 尾
#   ③ 结构级规范化：直接用 ① 的变体（保留 `.` `,`，坐标不能被"去分隔符"破坏）
# 为什么可以放宽而不担心误报：本检测**仅在 `consent_scope: []` 显式空声明时**启用，
# 而干净语料里显式空声明出现 **0** 次（已实测）⇒ 放宽也不会影响正常流量；
# 即便误报，代价只是"多转人工"（fail-closed 方向），不是漏判。

# 零宽 / 软连字符：视觉不可见，`\s` 抓不到，必须显式列出（红队 `\u200b`、BOM 规避）。
_ZW_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u00ad]")

# 数字**同形字**折叠：**不要枚举数字系统** —— 第二版枚举了 14 种区块，
# 第三轮独立复核立刻用**第 15 种**（僧伽罗 `\u0DE6`）加缅甸/高棉/桑塔利/绍拉什特拉/瓦伊/
# 巴厘，以及 ASCII+异体混写（`"1" + 僧伽罗 10 位`）再次推翻。枚举法对**无穷的等价类**
# 天然打不完。
# 正解：用 Unicode 自身的 `Numeric_Type=Decimal` 属性（`unicodedata.decimal`）把所有
# 十进制数字一律折成 ASCII —— 与脚本/区块/未来新增字符**无关**，一次性封顶。
_ASCII_DIGITS = "0123456789"
_FOLD_CAP = 65536               # 折叠长度上限：超长值跳过逐字符折叠（DoS 防御，见下）
# 【V14 发现6 DoS】params 体硬帽：超大 body（20M/50M 字符实测 19s/49s）在 json.loads
# 之前直接 fail-closed，杜绝"单请求长时间线性占用 CPU"。4M 字符已远超真实 hook 参数
# 量级，且仍保留 12×200KB（2.4M）等既有压力测试的语义。
_MAX_BODY_CHARS = 4_000_000
# 【V14 发现6 DoS】整个输入硬帽：平台/数据类型识别等前置步骤也会对整个 text 做 O(n)
# 正则扫描，超大 text 须在进入任何解析前拒绝。8M 字符已远超真实调用栈+参数量级。
_MAX_TEXT_CHARS = 8_000_000

# 【第十三轮对抗复核 DoS】逐字符 Python 循环在超大非 ASCII 输入上线性放大
# （10M 字符实测 40s：每字符 isascii+isnumeric+append 三连）。改为 C 级
# `str.translate`：把"数字字符 → ASCII 数字"映射预编译成一张表，折叠从 O(n) 次
# Python 方法调用降为一次 C 级整串扫描（10M 字符 ≈ 0.6s）。
# 表仍由 `unicodedata.decimal/numeric` **属性**驱动 —— 不枚举数字系统（第三/四轮
# 教训），任何脚本 / 未来新增的 Decimal / Numeric(0..9) 数字都自动入表。
_FOLD_MAP = {}
for _cp in range(0x110000):
    _ch = chr(_cp)
    if _ch.isascii():
        continue
    if not _ch.isnumeric():
        continue
    _d = None
    try:
        _d = unicodedata.decimal(_ch)
    except (TypeError, ValueError):
        pass
    if _d is not None:
        _FOLD_MAP[_cp] = _ASCII_DIGITS[_d]
        continue
    try:
        _v = unicodedata.numeric(_ch)
    except (TypeError, ValueError):
        continue
    if _v == int(_v) and 0 <= _v <= 9:
        _FOLD_MAP[_cp] = _ASCII_DIGITS[int(_v)]


def _fold_digits(s):
    """把**任意** Unicode 数字折叠为 ASCII 数字（不枚举数字系统）。

    两级：
      ① `Numeric_Type=Decimal`（`unicodedata.decimal`）—— 各脚本十进制数字，
         第四轮复核验证覆盖了 7+5 种我从未提过的脚本；
      ② `Numeric_Type=Numeric`（`unicodedata.numeric`）且值为 **0..9 的整数** ——
         CJK 表意数字（一/三/八/〇）、苏州码（〡〢〣）、圈数字（①…⑨）。
         第四轮复核指出：只做 ① 时，`一三八〇〇一三八〇〇〇` 与 `〡〢〣〇〇〡〢〣〇〇〇`
         仍然整串漏判（它们不是 Decimal！）。
         刻意**排除** >9 的值（`十`=10、`万`=10000 是"多位数值"而非"单个数字"，
         折叠它们会产生语义歧义）与非整数（`½`=0.5）—— 避免把无关 CJK 误折叠。

    【第十三轮对抗复核 DoS】逐字符 Python 循环在超大非 ASCII 输入上线性放大
    （10M 字符实测 40s）。改为 C 级 `str.translate`（表见上方 `_FOLD_MAP`），
    折叠从 O(n) 方法调用降为一次整串扫描。行为与旧逐字符版**逐位一致**：
    非数字非 ASCII 字符原样保留（表未收录 → translate 原样输出）。
    `_text_variants` 仍自带 `len<=` 帽（③ 文本级不折超长正文）。
    """
    if s.isascii():
        return s
    return s.translate(_FOLD_MAP)


# ── CJK 数字表达式折叠（第十三轮对抗复核 发现2）────────────────────────────
# 逐字符折叠（`_fold_digits`）对 `壹佰叁拾捌亿壹拾叁万捌仟` 只折出 6 位数字
# `138138`（单位 佰/拾/亿/万/仟 是 >9 的 Numeric 值，被刻意保留），手机号
# 13800138000 因此整串漏判。数字表达式需要**位置/乘法**折叠而非逐字符替换：
#   `壹佰叁拾捌亿` → (1×100 + 3×10 + 8)×1e8；`壹拾叁万` → (1×10 + 3)×1e4；
#   `捌仟` → 8×1000 —— 三段相加 = 13800138000。
_CJK_DIGIT_MAP = {"〇": 0, "零": 0, "一": 1, "二": 2, "三": 3, "四": 4,
                  "五": 5, "六": 6, "七": 7, "八": 8, "九": 9,
                  "壹": 1, "贰": 2, "叁": 3, "肆": 4, "伍": 5,
                  "陆": 6, "柒": 7, "捌": 8, "玖": 9}
_CJK_SMALL_UNIT = {"十": 10, "拾": 10, "百": 100, "佰": 100, "千": 1000, "仟": 1000}
_CJK_BIG_UNIT = {"万": 10000, "萬": 10000, "亿": 100000000, "億": 100000000}
_CJK_NUM_CHARS = "".join(sorted(
    set(_CJK_DIGIT_MAP) | set(_CJK_SMALL_UNIT) | set(_CJK_BIG_UNIT)))
_CJK_NUM_RE = re.compile("[" + _CJK_NUM_CHARS + "]+")


def _cjk_parse_run(run):
    """把一段**纯** CJK 数字表达式解析为整数串；无单位（如 `一三八`）或失败返回 None。

    （无单位的裸数字串交给 `_fold_digits` 逐字折叠，本函数不越权。
      超长 run（>128 字符，数值远超大整数，非手机/身份证/银行卡）直接放弃，防 DoS。）
    """
    if len(run) > 128:
        return None
    total = 0       # 已按"亿/万"结算的累加值
    section = 0     # 当前"万以下"段
    num = 0         # 当前待乘的数字
    has_unit = False
    for ch in run:
        if ch in _CJK_DIGIT_MAP:
            num = _CJK_DIGIT_MAP[ch]
        elif ch in _CJK_SMALL_UNIT:
            has_unit = True
            if num == 0:
                num = 1                       # 十/百/千 前无数字 ⇒ 隐含 1
            section += num * _CJK_SMALL_UNIT[ch]
            num = 0
        elif ch in _CJK_BIG_UNIT:
            has_unit = True
            section += num
            num = 0
            section *= _CJK_BIG_UNIT[ch]
            total += section
            section = 0
        else:                                 # 不该出现（正则会拦），防御
            return None
    if not has_unit:
        return None
    total += section + num
    return str(total)


def _cjk_numeral_fold(s):
    """把字符串中的 CJK 数字表达式替换为其整数串（无单位段原样保留）。"""
    return _CJK_NUM_RE.sub(lambda m: _cjk_parse_run(m.group(0)) or m.group(0), s)


# 字面转义：JSON 二次编码（`"\\u0031\\u0033…"`）后，字符串值里剩的是**字面** `\u0031`。
_ESC_U_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
_ESC_X_RE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _decode_escapes(s):
    """把字面 `\\uXXXX` / `\\xXX` 转义还原为字符（JSON 二次转义的常见规避）。"""
    def _sub(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:                                  # noqa: BLE001
            return m.group(0)
    return _ESC_X_RE.sub(_sub, _ESC_U_RE.sub(_sub, s))


def _text_variants(s):
    """① 字符级等价变体：原样 / 去转义 / NFKC / 去零宽 / 折数字同形字（组合）。

    只做**字符等价替换**（不删 `.` `,` 等结构字符），故对结构类形态（坐标/邮箱）安全。
    上限 8 个变体，全部只在空声明分支调用。
    """
    def _nfkc(x):
        try:
            return unicodedata.normalize("NFKC", x)
        except Exception:                                  # noqa: BLE001
            return x
    out, seen = [], set()
    for seed in (s, _decode_escapes(s)):
        for w in (seed, _nfkc(seed)):
            for z in (w, _ZW_RE.sub("", w)):
                cands = [z]
                # 超长串跳过逐字符折数字（DoS 防御）；NFKC 仍会折叠全角/圈数字等兼容形
                if len(z) <= _FOLD_CAP:
                    cands.append(_fold_digits(z))
                    # 【V13 发现2】CJK 数字表达式位置/乘法折叠
                    # （壹佰叁拾捌亿壹拾叁万捌仟 → 13800138000），产物再折单字数字
                    # （处理与表意/苏州码数字混写的情况）。
                    cjk = _cjk_numeral_fold(z)
                    if cjk != z:
                        cands.append(_fold_digits(cjk))
                for cand in cands:
                    if cand and cand not in seen:
                        seen.add(cand)
                        out.append(cand)
    return out


def _expand_sci(v):
    """把科学计数法展开为整数串（`1.3800138e10` → `13800138000`），失败返回 None。"""
    m = re.fullmatch(r"\s*([+-]?\d+(?:\.\d+)?)[eE]\s*([+-]?\d+)\s*", v)
    if not m:
        return None
    try:
        val = float(m.group(1)) * (10.0 ** int(m.group(2)))
    except Exception:                                      # noqa: BLE001
        return None
    if val == int(val) and abs(val) < 1e18:
        return str(int(val))
    return None


def _digit_canon(s):
    """② 返回该值的**纯数字**等价候选集合（供手机/身份证/银行卡形态匹配）。

    覆盖：去全部分组分隔符（`\\D` 一步即含 `_ / | · – — , .` 等）、展开科学计数法、
    归一 `123.0` 尾零。前导零不在此处剥（交给手机号正则的 `0*` 处理，避免把
    "以 0 开头的银行卡"误剥成短线号）。
    """
    out = set()
    for v in _text_variants(s):
        e = _expand_sci(v)                          # `1.3800138e10` → `13800138000`
        if e:
            out.add(e)
        m = re.fullmatch(r"([+-]?\d+)\.0+", v.strip())   # `13800138000.0` → `13800138000`
        if m:
            out.add(m.group(1))
        d = re.sub(r"\D+", "", v)                   # 去**所有**非数字字符（含一切分隔符）；`\D+` 合并连续段，C 层单次
        if d:
            out.add(d)
    return out


def _shape_of(s):
    """返回命中的形态名（无则 None）。

    顺序：结构类（字符级变体）→ 数字类（数字级规范化）→ 内嵌子串。
    数字类放中间：`opaque` 会吞掉长数字串，先给结构类一次机会即可。
    """
    for v in _text_variants(s):
        for name, pat in _STRUCT_SHAPES.items():
            if not pat.match(v):
                continue
            if name == "opaque" and (_OPAQUE_HEX_EXEMPT.match(v)
                                     or _OPAQUE_UUID_EXEMPT.match(v)):
                continue
            return name
    for d in _digit_canon(s):
        for name, pat in _DIGIT_SHAPES.items():
            if pat.match(d):
                return name
    for v in _text_variants(s):
        name = _shape_search(v)
        if name:
            return name
    return None


def _uudecode_line(line):
    """单行 **uuencode** 解码（第六轮复核 A4：白名单里没有 uu ⇒ 整体逃逸）。

    【第八轮对抗复核 DoS 修补】uu 是行编码，单行长度有上限（RFC 约定 ≤61 数据字节
    ⇒ 行 ≤ ~80 字符）。超长"单行"（如 1.5MB 无换行的值）会被 `for i in range(0,
    len, 4)` 切成 375K 次迭代 ⇒ 秒级挂死。长度护栏：>4096 直接判非 uu。"""
    if not line or len(line) > 4096:
        return None
    n = (ord(line[0]) - 32) & 0x3F
    if n == 0:
        return ""
    data = bytearray()
    chunk = line[1:]
    for i in range(0, len(chunk) - 1, 4):
        g = chunk[i:i + 4]
        if len(g) < 4:
            break
        b = [((ord(c) - 32) & 0x3F) for c in g]     # '`'(96) 与 ' '(32) 都映射为 0
        data += bytes([(b[0] << 2) | (b[1] >> 4),
                       ((b[1] & 0xF) << 4) | (b[2] >> 2),
                       ((b[2] & 3) << 6) | b[3]])
    if n > len(data):
        return None
    try:
        txt = bytes(data[:n]).decode("utf-8")
    except Exception:                                  # noqa: BLE001
        return None
    return txt if txt and txt.isprintable() else None


def _decode_variants(s, include_reversal=True):
    """**单层**解码候选：base64(标准/urlsafe/无填充/夹空白) / base32 /
    hex(0x 前缀、`:`/空格/连字符 分隔) / URL 百分号 / HTML 实体 / 反转。
    多层由 `_encoded_pii_hit()` 递归。

    【第四轮独立复核】逐项堵的洞（每条都是实测泄漏）：
      · **hex 解码曾被 opaque 豁免挡死**：`hex(b64(phone))` 是 32 个 hex 字符，
        命中 `_OPAQUE_HEX_EXEMPT`（MD5 形态）⇒ hex 分支被 `not exempt` 条件**短路**。
        根因是职责混淆：豁免的本意是"MD5 不算 PII token"（属 `opaque` 判定），
        不是"不许解码"。现在**解码层不再看豁免**，豁免只留在 `_shape_of` 的
        `opaque` 分支 —— 解出乱码自然不命中，对真 MD5 零误伤。
      · **无填充 base64** `MTM4MDAxMzgwMDA`（len%4≠0）⇒ 补 `=` 后解码。
      · **夹空白 base64** `MTM4MDAx\\nMzgwMDA=` ⇒ 先去空白。
      · **base32** `GEZDGNBVGY3TQOJQGEZA==…`（容忍多余填充/小写）。
      · **0x 前缀 hex** `0x3138…`、**冒号分隔 hex**（MAC/字节串写法）。
      · **全角 ％** `％31％33…` ⇒ 先 NFKC 再解。
      · **HTML 实体** `&#49;&#51;…` / `&#x31;…`（否则正则剥离后得到的是
        "495138…" 这种**错位数字**，既不命中也不报错 —— 最隐蔽的一类）。
      · **反转** `00083100831`（最廉价的"混淆"；空声明分支多一次复检，零成本）。
    """
    out = []
    # 【V11 发现2】uuencode 用**原始** s 解：尾空格是零字节填充，`pool=[s.strip()]`
    # 会把尾空格销毁 ⇒ `n > len(data)` 解码失败；2/3 片 uu 各自独立编码、<12 字符时
    # ⑤ 密集 token 兜不住 ⇒ 漏判。只去行尾换行、保留尾空格。
    _uu_clean = re.sub(r"\bbegin\s+[^\n]*", "", s)
    _uu_clean = re.sub(r"\bend\b", "", _uu_clean)
    for _ln in re.split(r"[\n|]+", _uu_clean):
        _d = _uudecode_line(_ln.rstrip("\r\n"))
        if _d:
            out.append(_d)
    pool = [s.strip()]
    try:
        _n = unicodedata.normalize("NFKC", pool[0])
        if _n != pool[0]:
            pool.append(_n)                        # 全角 ％ → %
    except Exception:                                  # noqa: BLE001
        pass
    for t in list(pool):                               # HTML 实体（十/十六进制，含**双重**编码）
        # 【第六轮复核 A6】条件从 `"&#" in t` 放宽到 `"&" in t`：
        # `&amp;#49;` 里 `&` 后面是 `a`，旧条件根本不触发 unescape ⇒ 双重实体整体逃逸。
        # 【自查修正】**unescape 产物必须同时进入 `out`**：旧实现只把它追加进 `pool`
        # （供同层后续解码），产物列表里没有它 ⇒ 多层 BFS（`_encoded_pii_hit`）的
        # 下一轮根本拿不到 `&#49;…`，"双重实体"的第二跳永远不发生——放宽条件形同虚设。
        if "&" in t:
            try:
                h = _pyhtml.unescape(t)
                if h and h != t:
                    if h not in pool:
                        pool.append(h)
                    if h not in out:
                        out.append(h)
            except Exception:                          # noqa: BLE001
                pass
    seen = set()
    for t in pool:
        if not t:
            continue
        # 反转（放在最前，代价 1 个候选）。【第六轮】结构怀疑闸门不用反转
        # （任何 ≥8 字符串反转后仍是 ≥8 字符 ⇒ 会把"可解码"判定变成恒真）。
        rev = t[::-1]
        if include_reversal and rev != t and rev not in seen:
            seen.add(rev)
            out.append(rev)
        # ── base64：去内嵌空白、补填充、标准与 urlsafe 都试 ──
        b = re.sub(r"\s+", "", t)
        for cand in (b, b.translate(_B64_URLSAFE)):
            if len(cand) < 8 or not _B64_STD_RE.match(cand):
                continue
            for padded in (cand, cand + "=" * (-len(cand) % 4)):
                if padded in seen:
                    continue
                seen.add(padded)
                try:
                    txt = base64.b64decode(padded, validate=True).decode("utf-8")
                    if txt and txt.isprintable():
                        out.append(txt)
                except Exception:                      # noqa: BLE001
                    pass
        # ── base32：容忍多余填充与空白（先去 `=` 再补齐到 8 的倍数）──
        b32 = re.sub(r"[\s=]", "", t).upper()
        if len(b32) >= 8 and _B32_RE.match(b32):
            b32 = b32 + "=" * (-len(b32) % 8)
            try:
                txt = base64.b32decode(b32).decode("utf-8")
                if txt and txt.isprintable():
                    out.append(txt)
            except Exception:                          # noqa: BLE001
                pass
        # ── hex：容忍 0x 前缀与 `:`/空格/连字符 分隔（解码层**不看** opaque 豁免）──
        h = re.sub(r"^0[xX]", "", t)
        h = re.sub(r"[:\s\-]", "", h)
        if len(h) >= 8 and len(h) % 2 == 0 and _HEX_RE.match(h):
            try:
                txt = bytes.fromhex(h).decode("utf-8")
                if txt and txt.isprintable():
                    out.append(txt)
            except Exception:                          # noqa: BLE001
                pass
        # ── base85 / ascii85（【第六轮 A1/A2/A42/A43】解码器白名单缺口）──
        for _fn in (base64.b85decode, base64.a85decode):
            try:
                txt = _fn(t).decode("utf-8")
                if txt and txt.isprintable():
                    out.append(txt)
            except Exception:                          # noqa: BLE001
                pass
        # 【V11 发现3】ascii85 adobe=True：标准 Adobe ascii85 带 `<~ ~>` 定界符，
        # 默认 adobe=False 不剥 ⇒ 带定界符整片解不出（a85-adobe 4 片分片漏判）。
        try:
            txt = base64.a85decode(t, adobe=True).decode("utf-8")
            if txt and txt.isprintable():
                out.append(txt)
        except Exception:                              # noqa: BLE001
            pass
        # ── URL 百分号 ──
        if "%" in t and _PCT_RE.search(t):
            try:
                txt = urllib.parse.unquote(t)
                if txt != t and txt and txt.isprintable():
                    out.append(txt)
            except Exception:                          # noqa: BLE001
                pass
    return out


def _encoded_pii_hit(s, max_rounds=3):
    """**多层**编码复检：反复解码，任一层解出 PII 形态即返回形态名（否则 None）。

    【第三轮复核】双层 base64 `TVRNNE1EQXhNemd3TURBPQ==` 解一层得 `MTM4MDAxMzgwMDA=`
    （仍是 base64）——原实现在 `_shape_of` 里只复检一层便返回 None ⇒ 连软层开着也漏。
    现用 BFS 逐层解码（上限 3 层，防crafted 无限膨胀），层内去重防爆炸。

    【第四轮复核 · 自查修正】**解码产物不接受 `opaque`**：`opaque` 是"≥32 字符的
    alnum 串"这种**弱信号**，本意只用于**原始值**；解码/反转产物动辄 32+ 字符
    （例：UUID 反转后仍是 36 字符带连字符的串）⇒ 会让 UUID 这类良性长 token 被
    误报成 PII。故解码层只接受**强形态**（手机/身份证/银行卡/邮箱/坐标）。
    """
    frontier = [s.strip()]
    seen = set(frontier)
    for _ in range(max_rounds):
        nxt = []
        for t in frontier:
            for d in _decode_variants(t):
                if d in seen:
                    continue
                seen.add(d)
                nm = _shape_of(d)
                if nm and nm != "opaque":
                    return nm
                nxt.append(d)
        if not nxt:
            break
        frontier = nxt
    return None


def _iter_scalar_values(obj, _depth=0):
    """递归产出 dict/list 里的所有**标量值**（跳过 consent_scope 自身，深度上限防爆栈）。

    【第五轮 · V2 修复】原实现只产出 `str`，于是 `{"event":13800138000}`
    （JSON **数字**）在值级检测里完全不可见 —— 而手机号恰好是全数字，正是最自然的
    数字写法。现把 int/float 也 `str()` 出来参与形态匹配（bool/None 仍跳过，它们
    既非字符串也无 PII 形态）。
    """
    if _depth > 6 or isinstance(obj, (bytes, bytearray)):
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, bool) or obj is None:
        return
    elif isinstance(obj, int):
        yield str(obj)
    elif isinstance(obj, float):
        # repr 保真（避免 str(1e10)="10000000000" 与 str(1.3800138e10) 的表示差异），
        # 数字级规范化里的 `.0` 尾零与科学计数法展开会把它折回整数串。
        yield repr(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            # 【第六轮复核 A13】只跳过**顶层**的 consent_scope（契约判别字段本身）。
            # 原实现跳过**一切层级**的同名键 ⇒ `{"meta":{"consent_scope":{"x":"<b64手机>"}}}`
            # 这类**嵌套伪装**让编码值对值级检测完全隐身。非顶层的同名键是普通数据，必须扫。
            if _depth == 0 and str(k).lower() == "consent_scope":
                continue
            yield from _iter_scalar_values(v, _depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_scalar_values(v, _depth + 1)


# 数字间分组分隔符折叠（用于**文本级**扫描）：`1_380_0138_000` 这种**不是合法 JSON**
# 的裸 token 解析不出来，逐值层失明；把"数字-分隔-数字"里的分隔符删掉即可还原。
# 刻意**不含换行** —— 不能把两行 JSON 里相邻的两个数字并成一个 11 位数。
_DIGIT_SEP_RE = re.compile(
    r"(?<=[0-9])[ \t\u00a0\u3000._/|·•‧∙‣⁃,\-\u2010\u2011\u2012\u2013\u2014\u2015\u2212]+(?=[0-9])")


def _collapse_digit_seps(s):
    return _DIGIT_SEP_RE.sub("", s)


# ── 【第六轮复核 · 类 4 结构性修复】解析语义统一 ─────────────────────────────
# 缺陷：契约闸门用**正则**取"首个" consent_scope，json.loads 取"最后一个"同名键 ——
# `{"consent_scope":[],"consent_scope":["PHONE"]}` 会被正则判成空声明、
# 而 JSON 语义下上游明明声明采集 PHONE ⇒ 自动 NONE||COMPLIANT，且**从不被检出** ⇒
# 撤销回路永不触发，重复投递稳定泄漏。根因是"同一字段两套解析语义"。
# 修复：**解析后的 JSON 是唯一事实来源**，且重复键一律视为违约（fail-closed）。
class _DupKeyError(ValueError):
    """params JSON 出现重复键 ⇒ 契约违约（歧义输入不可作放行依据）。"""


def _param_no_dup_hook(pairs):
    # 【V10 发现3 · DoS】旧实现 `keys.count(k)` 对每个键 O(n) 扫描 ⇒ O(n²)。
    # 3 万个唯一键各重复一次（约 1.8MB）即挂死单核 31s。改用 Counter 一次计数 O(n)。
    _cnt = Counter(k for k, _ in pairs)
    _dups = [k for k, c in _cnt.items() if c > 1]
    if _dups:
        raise _DupKeyError("duplicate_key:" + ",".join(_dups[:60]))
    return dict(pairs)


_DENSE_TOKEN_RE = re.compile(r"^[!-~]{12,}$")     # ≥12 字符无空白可打印 ASCII


def _obj_depth(obj, _d=0):
    """JSON 结构的最大嵌套深度（超过 `_iter_scalar_values` 的 6 层防爆栈上限即为疑点）。

    【第六轮对抗复核 · 崩溃窗口修复】深度计到 8 即提前返回——闸门只判 `> 6`，
    继续递归毫无收益；不设上限时，700~950 层嵌套（JSON 能解析、低于 Python
    递归极限）会让本函数 RecursionError 直接逃出 classify。"""
    if _d > 8:
        return _d
    if isinstance(obj, dict) and obj:
        return max(_obj_depth(v, _d + 1) for v in obj.values())
    if isinstance(obj, list) and obj:
        return max(_obj_depth(v, _d + 1) for v in obj)
    return _d


def _iter_keys(obj, _depth=0):
    """递归产出**全部 str 键名**（第六轮复核 V6：键名是检测面的完全盲区——
    PII 进键名或拆在键/值两侧，值级与文本层同时失明）。
    排除 `consent_scope` 本身（它是声明字段，13 字符密集 token 会让每条
    空声明都误报）。深度上限 8 与值迭代呼应。"""
    if _depth > 8:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k != "consent_scope":
                yield k
            yield from _iter_keys(v, _depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_keys(v, _depth + 1)


def _short_decode(v):
    """解码**短**编码片段（base64 ≥4 / base32 ≥2 / hex ≥2 且偶数），不设 `_decode_variants`
    的 8 字符下限。

    【V10 发现1】`_decode_variants` 的 base64/base32/hex 分支都有 `len<8` 护栏，把短片段
    （`MTM4`→`138`、`GEZTQ`→`138`、`313338`→`138`）整体跳过 ⇒ 短编码分片重组漏判。
    空声明分支 fail-closed，短解码只增『转人工』、零漏判风险。"""
    b = re.sub(r"\s+", "", v)
    out = []
    # base64（≥4 字符，标准/urlsafe、无填充补 `=`）
    if 4 <= len(b) <= 1024:
        for cand in (b, b.translate(_B64_URLSAFE)):
            if _B64_STD_RE.match(cand):
                try:
                    txt = base64.b64decode(cand + "=" * (-len(cand) % 4),
                                           validate=True).decode("utf-8")
                except Exception:                          # noqa: BLE001
                    txt = None
                if txt and txt.isprintable() and txt not in out:
                    out.append(txt)
    # base32（≥2 字符，去空白/`=`，补到 8 的倍数）
    b32 = re.sub(r"[\s=]", "", b).upper()
    if 2 <= len(b32) <= 1024 and _B32_RE.match(b32):
        try:
            txt = base64.b32decode(b32 + "=" * (-len(b32) % 8)).decode("utf-8")
        except Exception:                                  # noqa: BLE001
            txt = None
        if txt and txt.isprintable() and txt not in out:
            out.append(txt)
    # hex（≥2 且偶数，容忍 0x 前缀与 `:`/空格/连字符 分隔）
    h = re.sub(r"^0[xX]", "", b)
    h = re.sub(r"[:\s\-]", "", h)
    if 2 <= len(h) <= 1024 and len(h) % 2 == 0 and _HEX_RE.match(h):
        try:
            txt = bytes.fromhex(h).decode("utf-8")
        except Exception:                                  # noqa: BLE001
            txt = None
        if txt and txt.isprintable() and txt not in out:
            out.append(txt)
    return out


def _scope_structurally_suspicious(obj):
    """空声明分支的**结构性怀疑闸门**（第六轮复核 · 类 1/2/3 的 fail-closed 兜底）。

    设计原则（复核员建议，取代逐个枚举编码器）：**不判断产物是否 PII** ——
    只要"值可被任一真编码解出非平凡产物"或"结构形态异常"即转人工。
    覆盖：解码器白名单外的编码（base85/ascii85/uu/未知）、跨值编码分片、
    深嵌套 × 编码、四路以上分片、超长值表等**整个家族**。
    代价仅落在空声明场景（干净语料 30000 条出现 0 次 ⇒ 实测零回归），
    方向是 fail-closed（多转人工），不是漏判。

    【第六轮对抗复核 V6 修补】
      · **键名并入检测面**（`_iter_keys`）：键名 base64/hex 编码、键/值两侧分片
        （`{"138":"00138000"}`）、键/键分片 —— 旧实现只扫值 ⇒ 全层失明。
        检测池 = 值 + 键（各截断 12，合并去重 ≤24）。
      · ①c **有序对拼接形态扫描**（r=2）：键+值、键+键拼出完整形态即嫌疑
        （`_split_key_hit` 的 r≤3 只扫值且不扫键；4 路以上由 ④ 兜住）。
      · ④ 计数升级：**去非数字后长度 ∈ [2,8]** 或 纯数字 ≤6 位均计入 ——
        `"a13"`/`"000b"` 这类边界字母包夹的 4 路分片不再靠纯数字判定漏网。
      · 长值上限 16KB：超长值不做解码/拼接（DoS 放大器）；它们必然命中
        ⑤ 密集 token（≥12 连续字符）或 ③ 深嵌套，不损失检测。
    """
    vals = [str(v) for v in _iter_scalar_values(obj)]
    # 【第八轮对抗复核 B 修补】键帽"截断=失明"：编码 PII 藏第 33 个键名即漏
    # （V6 帽 12→V7 提 32 未根治"帽+1"）。改为**超限即 fail-closed**：键数 >32
    # 直接转人工，不再截断。值数 >12 提前判定（原先在 ①c 之后才判，浪费组合）。
    if len(vals) > 12:
        return "excessive_value_count"
    _keys_all = list(_iter_keys(obj))
    if len(_keys_all) > 32:
        return "excessive_key_count"
    keys = _keys_all
    pool = list(dict.fromkeys(vals + keys))     # ≤ 12+32=44，去重后无截断
    _DECODE_CAP = 16 * 1024      # 单元素解码上限（超长由 ⑤/③ 兜住）
    _PAIR_DECODE_CAP = 4 * 1024  # 有序对拼接解码上限（分片本来就是短串）
    _SHAPE_CONCAT_CAP = 128      # 形态扫描候选上限（内嵌形态 ≤40 字符）

    # ① 任一**池元素**被任一**真编码**解出 ≥8 字符可打印产物
    #    （不看反转——反转恒真无意义；超长元素跳过——由 ⑤ 兜住）
    for v in pool:
        if len(v) > _DECODE_CAP:
            continue
        for d in _decode_variants(v, include_reversal=False):
            d = d.strip()
            if len(d) >= 8 and d.isprintable():
                return "decodable_value"
    # ①b **跨元素编码分片**：单片解不出（<8 字符 / 填充非法），拼上另一片才完整。
    #    有序对（permutations 保序）拼接后单层解码，解出 ≥8 可打印 ⇒ 分片实锤。
    if 2 <= len(pool):
        for a, b in itertools.permutations(pool, 2):
            if len(a) + len(b) > _PAIR_DECODE_CAP:
                continue
            for d in _decode_variants(a + b, include_reversal=False):
                d = d.strip()
                if len(d) >= 8 and d.isprintable():
                    return "cross_value_encoded_shard"
        # ①c **有序对拼接形态扫描**（键+值 / 键+键分片拼接出完整形态）。
        #   【第七轮 L1】归一化候选（NFKC+零宽+折数字 → \D 剥离）。
        #   【第八轮 D】去 isdigit 预筛（漏 Numeric 型表意/苏州码/圈数字）。
        #   【第九轮 DoS 回归修复】数字候选**逐元素提取一次**（`_digit_extract`），
        #     排列在**短数字串**上进行，不再对 200KB 级组合做 join+sub；
        #     原始拼接（email/坐标分片）先算总长再 join，超帽直接跳过。
        _digits = [_digit_extract(p) for p in pool]
        for ia, ib in itertools.permutations(range(len(pool)), 2):
            nd = _digits[ia] + _digits[ib]
            if len(nd) >= 11 and _shape_search(nd):
                return "split_key_shape"
            if len(pool[ia]) + len(pool[ib]) <= _SHAPE_CONCAT_CAP:
                if _shape_search(pool[ia] + pool[ib]):
                    return "split_key_shape"
        # ①d 【V10 发现1】解码后分片重组（各自解码成功后拼接）。
        #    base64 三片各带 `==` 填充：拼接后填充居中 ⇒ 整串非法、①b"拼接后解码"
        #    失败；且 4 字符合法组被 `_decode_variants` 的 `len<8` 护栏跳过。
        #    → 逐元素提取『原串 + 短/全解码产物』的纯数字候选，r≤3 全排列重组
        #      （候选去重、只留 ≤24 位数字片、总数 ≤64：pool≤44 且单片 PII ≤19 位，
        #      64 个候选已远超单片手机号所需；permutations(64,3)≈25 万次短 join）。
        _dec_digits = []
        _dec_shard_cnt = 0
        for v in pool:
            for dd in _digit_cands(v):
                if len(dd) <= 24 and dd not in _dec_digits:
                    _dec_digits.append(dd)
            _short = False
            if len(v) <= _DECODE_CAP:
                for d in _short_decode(v):
                    for dd in _digit_cands(d):
                        if len(dd) <= 24 and dd not in _dec_digits:
                            _dec_digits.append(dd)
                        if 1 <= len(dd) <= 6:
                            _short = True
                for d in _decode_variants(v, include_reversal=False):
                    for dd in _digit_cands(d):
                        if len(dd) <= 24 and dd not in _dec_digits:
                            _dec_digits.append(dd)
                        if 1 <= len(dd) <= 6:
                            _short = True
            if _short:
                _dec_shard_cnt += 1
            if len(_dec_digits) >= 64:
                break
        # 【V10 自探】4+ 片编码分片：r≤3 全排列只覆盖 2~3 片，≥3 个元素各自解出短
        #    数字片（≤6 位）直接 fail-closed——与 ④ 对原始数字片"≥3 分片"的设计同源。
        if _dec_shard_cnt >= 3:
            return "decoded_short_shards"
        if len(_dec_digits) >= 2:
            for r in (2, 3):
                for idxs in itertools.permutations(range(len(_dec_digits)), r):
                    nd = "".join(_dec_digits[i] for i in idxs)
                    if len(nd) >= 11 and _shape_search(nd):
                        return "decoded_split_key_shape"
    # ③ 嵌套深度超限（>6 层的部分 `_iter_scalar_values` 根本看不见 ⇒ 不可验证）
    if _obj_depth(obj) > 6:
        return "excessive_nesting"
    # ④ 短数字分片过多（≥3 个）——【V6 升级】两种计数：
    #    (a) 纯数字 ≤6 位（单字符/短分片）；(b) **去非数字后长度 ∈ [2,8]**
    #    （`"a13"`→2、`"000b"`→3：边界字母包夹的 4 路分片；10+ 位时间戳不计）。
    #    【第八轮 D 修补】先 `_fold_digits` 折表意/苏州码/圈数字，再按 isdigit 计数——
    #    原版 `ch.isdigit()` 对 Numeric 型数字（一/〇/〡/①）为 False，与折叠能力不一致。
    def _is_shard(v):
        if len(v) > _FOLD_CAP:
            return False                       # 超长值不是"短分片"，由其它层兜（DoS 防御）
        vf = _fold_digits(v)
        if vf.isdigit():
            return len(vf) <= 6
        nd = sum(1 for ch in vf if ch.isdigit())
        return 2 <= nd <= 8
    if sum(1 for v in pool if _is_shard(v)) >= 3:
        return "short_digit_shards"
    # ⑤ 高密度长 token（**剥掉空白与非可打印 ASCII 后** ≥12 连续可打印 ASCII）
    #    ——**未知编码的兜底**：一个自称"不涉及个人信息"的调用里出现 12+ 字符的
    #    连续 token，无法排除它就是某种编码后的 PII ⇒ 转人工（_uuid/hex 摘要也在内，
    #    但那些本就该在空声明场景接受复核——fail-closed）。
    #    【第六轮自查修正 · uuencode 残缺行】uuencode 用 ' '（值 0）编码尾部零字节，
    #    pool 级 strip 先剥掉它 ⇒ 解码因 n > len(data) 失败——信息已销毁，
    #    但去空白后仍是高熵密集 token ⇒ 仍按 ⑤ 兜住。
    #    【第七轮对抗复核 L1③/L2/L3 修补】旧版只去 `\s`：攻击者每 ≤11 字符塞一个
    #    非 ASCII 字符（`é`/零宽）即可打破 `[!-~]{12,}` 连续段——V6"超长值由 ⑤ 兜底"
    #    的声明不成立。改为剥掉**一切非 `!-~` 字符**后计数：内嵌编码 token 现形
    #    （`"abcdefghijkéMTM4MDAxMzgwMDA=…"` → 密集 16 字符命中）。
    for v in pool:
        if _DENSE_TOKEN_RE.match(re.sub(r"[^\x21-\x7e]", "", v)):
            return "dense_token"
    # ⑥ 整数进制编码兜底（V12–V19 对抗复核）：
    #   PII 整数（手机 11 位 / 身份证 15/18 / 银行卡 16-19）可被**任意进制 N** 重编码，
    #   token 长度从 4（base1000）到 63（base2）不等，且可任意拆片到键/值两侧、可 2/3 路、
    #   可单字符键。信息论不可枚举 ⇒ 只能按 token 形状 fail-closed：
    #     · 整 token：6–11 字符非纯数字（base11–94；base2–10 纯数字整 token 由 ⑤ 兜）；
    #     · 恰 11 位纯数字（base9/境外号）；
    #     · **含任一非可打印 ASCII 字符**（空白/控制/Unicode 空白/非 ASCII/**零宽**/软
    #       连字符）⇒ fail-closed（V17 发现1/2 空白字母表与单码点非 ASCII；V18 发现1
    #       ASCII 锚 + 非 ASCII 字母表；V19 发现1 纯零宽字母表——在原始串上判
    #       `v_str != t`，不再预剥零宽）；
    #     · 字母+数字混写 或 大小写混写 或 **含任意符号（含下划线）** 的短 token
    #       （2–12 字符，键或值；base36/52/62 片段，V14 发现1/2；符号字母表 base33/59/43，
    #       V15 发现1/2/3；字母/数字+下划线 base27/28/11，V16 发现1/2——直接 fail-closed，
    #       不再依赖可被短占位值稀释的 sum≥6 阈值）；
    #     · 单字符键（V14 发现3 + V15 发现6：单字符字母/数字/符号键都不可能是描述性
    #       字段名）。
    #   已知残余（信息论下限，诚实声明）：**纯单大小写字母**片段（`{"bsr":"mvlim"}`
    #   base26）——与描述性词 event/ts/ok 信息论同构，无法不误伤地区分，接受为下限
    #   （V14 发现4 / V17 发现3 论证"白名单=新字母表"使字典/熵收窄失效）。base36/62
    #   因必含数字、base52 因大小写混写、base33/43/59/27/28/11 因含符号、空白/非 ASCII/
    #   零宽因含投影外字符，均已被上述判定覆盖。
    def _isd(t):
        return any(c.isdigit() for c in t)

    def _isa(t):
        return any(c.isalpha() for c in t)

    def _mixcase(t):
        return any(c.isupper() for c in t) and any(c.islower() for c in t)

    def _hassym(t):
        # 含任意 ASCII 符号（非字母非数字，**含下划线 `_`**）。
        # 【V16 发现】下划线是独立字符类盲区：base27(小写+_)/base28(大写+_)/base11(数字+_)
        # 里 `_` 是 1/27、1/28、1/11 的正式数字位；排除 `_` 曾造成三族编码漏判。且
        # `user_id`/`event_name`（7/10 字符）本就被 `6<=len<12` 长度子句拦截，排除 `_`
        # 对它们**零保护**（V16 发现3 实测证伪）。短蛇形片段 `a_b`/`_wky` 不是描述性
        # 字段名，应 fail-closed。
        return any(not c.isalnum() for c in t)
    for v in pool:
        v_str = str(v)
        if not v_str:
            continue                       # 真空：无内容
        t = re.sub(r"[^\x21-\x7e]", "", v_str)
        if v_str != t:
            # 【V17 发现1/2 + V18 发现1 + V19 发现1】v_str 含**任意**非可打印 ASCII 字符
            # （空白/控制/Unicode 空白/非 ASCII/**零宽**/软连字符）⇒ 内容有"投影外"的
            # 部分。旧实现先 `_ZW_RE.sub` 剥零宽、再判 `raw != t`——零宽被提前剥成空、
            # `continue` 跳过 ⇒ 纯零宽字母表整类漏判（V19）。改为**直接在原始串上**判
            # `v_str != t`（含任一投影外字符即 fail-closed），零宽/空白/非 ASCII 一网打尽。
            return "integer_base_token"
        if len(t) == 11 and t.isdigit():
            return "integer_base_token"          # base9 / 境外号
        if 6 <= len(t) < 12 and not t.isdigit():
            return "integer_base_token"          # base11–94 整 token
        if 2 <= len(t) <= 12 and ((_isd(t) and _isa(t)) or _mixcase(t) or _hassym(t)):
            return "integer_base_token"          # 字母+数字 / 大小写混写 / 含符号片段
    # 键名（V14 发现3 + V15 发现6 + V17 发现2 + V18 发现1 + V19 发现1）：单字符键、或
    # 含**任意**非可打印 ASCII 字符（非 ASCII / 空白 / 零宽）的键都不可能是描述性字段名。
    for k in keys:
        k_str = str(k)
        if not k_str:
            continue
        t = re.sub(r"[^\x21-\x7e]", "", k_str)
        if k_str != t:
            return "integer_base_token"          # 含非 ASCII / 空白 / 零宽字符的键名
        if len(t) == 1 and t.isprintable():
            return "integer_base_token"
    return None


@lru_cache(maxsize=64)
def _digit_extract(v):
    """把单个元素折叠（NFKC+零宽+异体数字→ASCII）后**剥离非数字**，返回纯数字串。

    【第九轮对抗复核 DoS 回归修复】①c / `_split_key_hit` 的数字候选按此**逐元素
    提取一次**（O(总长)），排列在短数字串上进行——避免对每个 200KB 级组合重复
    join+sub（12×200KB 实测 77s 的根因）。表意/苏州码/圈数字经 `_fold_digits`
    折成 ASCII，故剥离非数字后仍完整。
    【V10 发现2】旧实现超长元素跳过折叠、直接 `re.sub(r"\\D+","",v)`：表意/苏州码/〇
    非 `\\d`（Nd 类），被 `\\D+` **剥离销毁** ⇒ 长值里藏表意数字手机号漏判。
    本函数已逐元素只调一次（非全排列内），统一折叠 O(n) 单次成本可接受，取消跳过。

    【第十三轮对抗复核 DoS】同一超大值会被 ①/②/①c/①d 多层**重复**折叠（10M 字符
    实测 6 次 × 0.65s）。本函数是纯函数 ⇒ 加 `lru_cache` 合并重复折叠；`classify()`
    入口处 `cache_clear()` 防跨样本累积（超大串仅存活于单次判定内）。"""
    try:
        base = _ZW_RE.sub("", unicodedata.normalize("NFKC", v))
    except Exception:                                      # noqa: BLE001
        base = v
    # 【V13 发现2】CJK 数字表达式先按位置/乘法折叠
    # （壹佰叁拾捌亿壹拾叁万捌仟 → 13800138000），再对剩余单字数字做字符级折叠。
    # 顺序必须在前：若先逐字折叠，单位（佰/拾/亿…）的位置信息即被销毁。
    f = _fold_digits(_cjk_numeral_fold(base))
    return re.sub(r"\D+", "", f)


def _digit_cands(v):
    """返回 v 的纯数字候选（原串 + 反转串，去重）。

    【V11 发现1】反转分片是独立等价类：`"1" + reverse("0008310083")` 拼出手机号
    `13800138000`，但只提取原串数字时 `"1"+"0008310083"="10008310083"` 不命中。
    分片重组的数字候选必须同时纳入反转串（代价每值多 1 个候选）。"""
    out = []
    d = _digit_extract(v)
    if d:
        out.append(d)
    dr = _digit_extract(v[::-1])
    if dr and dr != d:
        out.append(dr)
    return out


def _split_key_hit(values, max_n=12, max_r=3):
    """**乱序/穿插**分片规避：把值两两/三元**全排列**拼接后扫内嵌形态。

    【第四轮复核】V2 的"按出现顺序拼接"只治 `{"a":"138","b":"00138000"}` 这种
    **正序**分片；`{"a":"00138000","b":"138"}`（**乱序**）与
    `{"a":"138","pad":"x","c":"00138000"}`（**穿插无关值**）都逃逸。
    全排列（≤3 元、值数截断 12 ⇒ 最多 12·11·10 = 1320 组合）覆盖两者。
    只在空声明分支调用，误报代价是"多转人工"。

    【第七轮对抗复核 D2/L1 修补】
      · **组合长度帽 128**：所有 PII 内嵌形态 ≤40 字符；长值里藏完整 PII 的
        场景由单值内嵌扫描覆盖。旧实现 12×2KB 值的全排列 × email 正则 O(n²)
        ⇒ 实测 81.8s（外推 8KB ≈ 21min）——帽子同时是复杂度与语义的双重边界。
      · **数字折叠候选**：拼接串被单个粘连字符（`"6222021"+"2a34567890"`）打断
        数字连续段时，`\\D` 剥离候选可还原（≥11 位才值得扫）。
        两片策略因此不再天然免死。误报面：不同值的无害数字拼接出 11 位串
        ⇒ 空声明分支多转人工（fail-closed 方向，与既有设计一致）。
    """
    _CONCAT_CAP = 128
    vs = []
    for v in list(values)[:max_n]:
        t = _fold_digits(_ZW_RE.sub("", _decode_escapes(str(v))))
        if t:
            vs.append(t)
    # 【第九轮对抗复核 DoS 回归修复】数字候选**逐值提取一次**（O(总长)），排列在
    # 短数字串上进行——不再对每个 200KB 级组合做 join+sub（12×200KB 实测 77s 根因）。
    # 原始拼接（email/坐标分片）先算总长再 join，超帽直接跳过。
    # 【V11 发现1】数字候选用 `_digit_cands`（含反转），每值贡献原/反两路候选。
    _digits = [_digit_cands(v) for v in vs]
    for r in range(2, max_r + 1):
        for idxs in itertools.permutations(range(len(vs)), r):
            for picks in itertools.product(*(_digits[i] for i in idxs)):
                nd = "".join(picks)
                if len(nd) >= 11 and _shape_search(nd):
                    return _shape_search(nd)
            if sum(len(vs[i]) for i in idxs) <= _CONCAT_CAP:
                nm = _shape_search("".join(vs[i] for i in idxs))
                if nm:
                    return nm
    return None


def _value_pii_shapes(text):
    """返回 params **值**上命中的 PII 形态名列表（无则空）。

    【第五轮 · 独立复核 V2 修复，第三轮复核再补】四层互补，任一层命中即算：
      ① **逐值形态**：解析后的每个标量值，先整串锚定（结构类+数字类规范化），
         再**多层**编码复检（URL/base64/hex，含双层 base64）；
      ② **跨值拼接**：`{"a":"138","b":"00138000"}` 这类**分片**规避 —— 把各值按序
         拼接后再扫内嵌形态（分片本身任何一层都看不出 PII，拼起来才现形）；
      ③ **文本级规范扫描**：JSON 非法/截断（`"event":013800138000` 因前导零不是合法
         JSON）时，直接对**规范化后的参数体原文**扫内嵌形态；
      ④ **文本级数字折叠**：`1_380_0138_000`（非法 JSON 的裸数字 token）连 ③ 都
         看不穿 —— 把数字间的分组分隔符删掉再扫。
    四层都只在 `consent_scope: []` 分支触发，故"多报"的代价只是多转人工（fail-closed）。
    """
    body = _PARAMS_OF(text).strip()
    if not body:
        return []
    obj = None
    try:
        obj = json.loads(body)
    except Exception:                                    # noqa: BLE001
        try:
            obj, _ = json.JSONDecoder().raw_decode(body)
        except Exception:                                # noqa: BLE001
            obj = None

    hits = set()
    values = list(_iter_scalar_values(obj)) if obj is not None else []

    # ① 逐值检测（含**多层**编码复检）。
    #    【第九轮对抗复核 DoS 修复】超长值（>64KB）跳过昂贵的锚定形态+多层解码，
    #    省掉 email 锚定正则对长串的贪心回溯。
    #    【V10 发现2】但"跳过"不能连**数字折叠**一起跳：表意/苏州码/〇 数字 NFKC
    #    不折叠、`\D` 剥离会销毁，超长值里藏表意手机号即漏（帽外失明）。改为：
    #    超长值做一次 `_digit_extract`（O(n) 折叠）+ 数字形态检查。
    #    【V11 DoS】值数无上限：50 万值让逐值扫描 ~35s。结构闸门已用 >12 → fail-closed，
    #    此处同阈值只扫前 12 值（>12 值样本由结构闸门 `excessive_value_count` 兜底，不损检测）。
    for s in values[:12]:
        s = s.strip()
        if not s:
            continue
        if len(s) > _FOLD_CAP:
            d = _digit_extract(s)
            for name, pat in _DIGIT_SHAPES.items():
                if pat.match(d):
                    hits.add(name)
                    break
            continue
        name = _shape_of(s)
        if name:
            hits.add(name)
            continue
        n2 = _encoded_pii_hit(s)             # URL / base64(含 urlsafe) / hex，逐层递归
        if n2:
            hits.add(n2 + "(encoded)")

    # ② 跨值排列（乱序/穿插分片规避，覆盖正序/乱序/带无关值）
    if values:
        n3 = _split_key_hit(values)
        if n3:
            hits.add(n3 + "(split)")

    # ③ + ④ 文本级规范扫描（非法/截断 JSON、值含前导零、裸数字 token 带分隔符）
    for v in _text_variants(body):
        n4 = _shape_search(v)
        if n4:
            hits.add(n4 + "(text)")
            break
    if not hits:
        for v in _text_variants(body):
            n5 = _shape_search(_collapse_digit_seps(v))
            if n5:
                hits.add(n5 + "(text)")
                break
    return sorted(hits)


def classify(text):
    """生产判定入口。规则引擎为主判层。

    fail-closed 原则：识别不出数据类型时，绝不轻易落 NONE→COMPLIANT。
      - 栈帧无混淆痕迹 → 视为真·无个人数据，判 NONE||COMPLIANT
      - 栈帧含混淆痕迹（短标识符）→ 无法确认，交人工复核
    """
    # 【V13 DoS】清空数字折叠缓存：只在本样本内复用（防超大串跨样本驻留内存）。
    _digit_extract.cache_clear()
    # 【V14 发现6 DoS】整个输入硬帽：超大 text 在任何 O(n) 前置扫描前直接拒绝。
    if len(text) > _MAX_TEXT_CHARS:
        return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                "confidence": 0.0, "source": "rules", "needs_review": True,
                "review_reason": "input_oversized", "tier": None}
    plat = _detect_platform(text) or _detect_stack_platform(text)
    # 平台兜底：标注值不在四端内（写错/新平台/缺失）时改为全平台搜索，
    # 否则会因"只在 windows 平台目录里找"而漏判成 NONE→COMPLIANT。
    if plat is not None and plat not in API_INDEX:
        plat = None
    dt, tier = _resolve_data_type(text, plat)

    # 识别失败：区分"真 NONE"与"混淆/多义导致不可判"
    if dt is None:
        if tier in ("class_ambiguous", "method_ambiguous"):
            return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                    "confidence": 0.0, "source": "rules", "needs_review": True,
                    "review_reason": "ambiguous_partial_identifier", "tier": tier}
        # 【第五轮修复】Tier1 命中但消歧失败（dt=None, tier="full_ambiguous"）
        # ⇒ 绝不能继续下坠到 none_verified（那会"把命中过的 API 洗成非 PII"）。
        if tier == "full_ambiguous":
            return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                    "confidence": 0.0, "source": "rules", "needs_review": True,
                    "review_reason": "ambiguous_api_contract_hit", "tier": tier}
        if detect_obfuscation(text):
            return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                    "confidence": 0.0, "source": "rules", "needs_review": True,
                    "review_reason": "obfuscated_identifier_unresolved",
                    "tier": tier}
        # 未知敏感 API 兜底：栈帧含敏感语义词、但 API 目录未收录（新增/变体/老 API）
        # → fail-closed 入复核，绝不落 NONE||COMPLIANT。
        # 这是"规则库完备性"不足时的安全网，直接服务于 99.9% 漏判率目标。
        if _sensitive_hint_in_stack(_STACK_OF(text), _PARAMS_OF(text)):
            return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                    "confidence": 0.0, "source": "rules", "needs_review": True,
                    "review_reason": "unknown_sensitive_api_hint", "tier": tier}
        # 【契约 v1.2 判别器 PC_SCOPE_CONTRACT=1 —— 必须排在"采集迹象"之前】
        # 信息论上，"真 NONE"与"信号字段被改名"在**旧契约下不可区分**（见下）。
        # v1.2 用**必填的 consent_scope** 打破这个对称：
        #   consent_scope 缺失       → 契约违约 → 转复核（≠ 假设无 PII）
        #   consent_scope = []       → 上游**显式声明**本次调用不涉及个人信息 → 可自动 COMPLIANT
        #   consent_scope = [类型…]  → Tier5 已用于恢复数据类型
        # 顺序要求：本判别器必须先于"采集迹象"执行，否则空数组会被当成采集证据而误转人工。
        _scope_declared_empty = False
        if _SCOPE_CONTRACT:
            m_sc = re.search(r'"consent_scope"\s*:\s*\[([^\]]*)\]', text, re.I)
            if m_sc is None:
                return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                        "confidence": 0.0, "source": "rules", "needs_review": True,
                        "review_reason": "contract_missing_consent_scope", "tier": tier}
            _vals = re.findall(r'"([A-Za-z_]+)"', m_sc.group(1))
            _bad = [v for v in _vals if v not in DATA_TYPES]
            if _bad:
                return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                        "confidence": 0.0, "source": "rules", "needs_review": True,
                        "review_reason": "contract_unknown_scope_value:" + ",".join(_bad[:3]),
                        "tier": tier}
            _scope_declared_empty = (len(_vals) == 0)
        # 【第五轮 · 空声明的**值级印证** —— 堵住红队实测可达的漏判】
        # `consent_scope: []` 只是上游的**自称**。若 params 的**值**里出现 PII 形态
        # （手机号/身份证/银行卡/坐标/邮箱/长编码串），则自称与观测矛盾 ⇒ fail-closed。
        # 与下方 dt-已识别分支的 `contract_scope_contradiction` 互补：
        #   那条处理"类型识别出来了但声明不含它"，本条处理"**类型没识别出来**（键名失明）
        #   但值暴露了 PII"——两条合起来把"空声明"从**特权**变成**待印证的自称**。
        # 零回归依据：干净数据 30000 条中显式空声明出现 **0** 次（实测），故不触发。
        if _SCOPE_CONTRACT and _scope_declared_empty:
            # 【第六轮复核 · 类 4 结构性修复】单一事实来源 + 三道硬性闸门：
            #   (1) **严格** `json.loads`：非法 / 有尾随内容（raw_decode 只返回首对象，
            #       尾随文本可夹带编码 PII）⇒ 一律不可作为放行依据；
            #   (2) **重复键** ⇒ 契约违约（正则首个 vs JSON 最后一个的双轨语义正是漏洞根源）；
            #   (3) 解析结果里的 `consent_scope` **必须**确为 `[]` —— 防"正则在字符串值/
            #       嵌套结构里匹配到 `consent_scope:[]` 字样"的伪装。
            _body0 = _PARAMS_OF(text).strip()
            # 【V14 发现6 DoS】超大 params 体硬帽：>4M 字符直接 fail-closed，不再
            # json.loads + 逐层 O(n) 扫描（20M/50M 实测 19s/49s）。
            if len(_body0) > _MAX_BODY_CHARS:
                return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                        "confidence": 0.0, "source": "rules", "needs_review": True,
                        "review_reason": "empty_scope_oversized_body", "tier": tier}
            try:
                _obj0 = json.loads(_body0, object_pairs_hook=_param_no_dup_hook)
            except _DupKeyError as _de:
                return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                        "confidence": 0.0, "source": "rules", "needs_review": True,
                        "review_reason": "empty_scope_duplicate_key", "tier": tier}
            except Exception:                          # noqa: BLE001
                return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                        "confidence": 0.0, "source": "rules", "needs_review": True,
                        "review_reason": "empty_scope_unparseable_params", "tier": tier}
            if not isinstance(_obj0, dict):
                return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                        "confidence": 0.0, "source": "rules", "needs_review": True,
                        "review_reason": "empty_scope_params_not_object", "tier": tier}
            _cs0 = _obj0.get("consent_scope")
            if not (isinstance(_cs0, list) and len(_cs0) == 0):
                return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                        "confidence": 0.0, "source": "rules", "needs_review": True,
                        "review_reason": "contract_scope_mismatch", "tier": tier}
            # ── 正交防线 1：撤销回路（该声明形态曾被检出过 ⇒ 永久不信任）────────
            # 粒度是"平台+键名集合+是否声明空"的指纹。上游**轮换键名**即可换指纹
            # （已知局限）——它拦的是"同一形态复发"，据此把漏判从期望 (1-p) 收敛到 0。
            _fp = _sa_fingerprint(text)
            if _sa_revoked(_fp):
                return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                        "confidence": 0.0, "source": "rules", "needs_review": True,
                        "review_reason": "scope_declaration_revoked", "tier": tier}
            _shapes = _value_pii_shapes(text)
            if _shapes:
                # 检出即撤销：本条之后，同形态一律转人工（写入受 scope_audit.revoke 的落盘门控）
                _sa_revoke(_fp, "empty_scope_contradicted_by_values:" + ",".join(_shapes[:3]))
                return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                        "confidence": 0.0, "source": "rules", "needs_review": True,
                        "review_reason": "empty_scope_contradicted_by_values:"
                                        + ",".join(_shapes[:3]),
                        "tier": tier}
            # 【第六轮复核 · 类 1/2/3 fail-closed 结构性兜底】
            # 值级印证只覆盖**已知形态**；红队第五轮实测：跨值分片重组、多层解码产物、
            # 嵌套伪装、解不出来但结构异常（7 层嵌套 / >12 值 / 密集 token / 短数字分片）
            # 均可绕过 `_value_pii_shapes`。逐个枚举追不上组合爆炸，故改用**机制级**兜底：
            #   空声明分支下，任何"值可被任一解码器解出非平凡产物"或"值数/嵌套深度/
            #   短数字分片/密集 token 超过启发式阈值" ⇒ 一律转人工。
            # **不判断产物是否 PII，不撤销**——嫌疑只是嫌疑；撤回权保留给确定性证据。
            # 零回归依据：干净调用无解码产物、无深嵌套/多值/密集 token 形态（实测 0 命中）。
            _susp = _scope_structurally_suspicious(_obj0)
            if _susp:
                return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                        "confidence": 0.0, "source": "rules", "needs_review": True,
                        "review_reason": "empty_scope_structure_suspicious:" + _susp,
                        "tier": tier}
            # ── 正交防线 2：确定性抽样审计（不可重投）───────────────────────────
            # 由服务端密钥 HMAC 决定，上游不可预测、不可重投改善；未配密钥时恒 False
            # （⇒ 默认零回归）。命中即转人工，用来**估计**上游违约率并给漏判一个上界 (1-p)。
            if _sa_selected(text):
                return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                        "confidence": 0.0, "source": "rules", "needs_review": True,
                        "review_reason": "scope_declaration_sampled_for_audit", "tier": tier}
        # 【采集迹象判据 · 2026-10-07 压力测试新增】
        # 出现任意合规信号字段（同意/传输/脱敏/目的/留存/去向…）⇒ 本次调用**确实发生了
        # 个人信息处理行为**，却未能识别数据类型 ⇒「行为存在 + 类型未知」。
        # 此时判 COMPLIANT 就是把"未知敏感 API"漏判成合规 —— 这正是 S2 压力测试暴露的
        # 26.86% 漏判来源。故 fail-closed 转复核。
        # 反向验证：真·NONE 样本（生成器产出的非敏感 SDK 调用）**不含任何信号字段**，
        # 故本判据对它们零影响（实测 OOD 108 条真 NONE 全部仍为 COMPLIANT，复核率不变）。
        _sig_probe, _po, _ = parse_signals(text)
        if _SCOPE_CONTRACT:
            # v1.2 下 consent_scope 是**判别器**而非"采集证据"，不参与本判据
            _sig_probe = {k: v for k, v in _sig_probe.items() if k != "consent_scope"}
        if _sig_probe:
            return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                    "confidence": 0.0, "source": "rules", "needs_review": True,
                    "review_reason": "unresolved_dtype_but_signal_present", "tier": tier}
        # 【P0-B 补充闸门】params 头存在、却完全解析不出 ⇒ "参数可见性失效"，
        # 不能当作"无证据"（原实现会一路走到 COMPLIANT）。转复核。
        if _PARAMS_OF(text).strip() and not _po:
            return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                    "confidence": 0.0, "source": "rules", "needs_review": True,
                    "review_reason": "params_unparseable_dtype_unknown", "tier": tier}
        # 【dtype 交叉校验哨兵】最后一道 fail-closed：用**独立信号路径**（字符 n-gram 语义）
        # 复核这条"即将被判为 NONE||COMPLIANT"的样本。若哨兵高置信认为是某个敏感数据类型，
        # 说明"API 目录未收录 + 语义不显"的残余漏洞被命中 → 改为入复核，绝不落 COMPLIANT。
        # 实测零额外复核成本（test/OOD 的 NONE 子集升级率 0.0000%）。
        _gs = _guard_says_sensitive(text)
        if _gs:
            return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                    "confidence": 0.0, "source": "rules", "needs_review": True,
                    "review_reason": f"dtype_guard_conflict:{_gs}", "tier": tier}
        # 【契约完整性 · 严格模式 PC_STRICT_NONE=1】
        # params 是合法 JSON、带若干键，却**一个契约信号字段都没有** ⇒ 无法区分
        #   (a) 真的没有个人信息（真 NONE）
        #   (b) 信号字段被改名/复数化/大小写变更（契约 §2 明令违约）
        # 这二者**在信息论上不可区分**：若上游违约把 PII 调用的信号字段改名，
        # 系统会误判成"真 NONE"→ COMPLIANT → 漏判（压力测试 S3 实测漏判 26.68%）。
        # 默认关闭以保持干净数据复核率；开启后真 NONE 一并转人工，换取零漏判。
        if _STRICT_NONE and _json_has_keys_no_signal(text):
            return {"combo": "UNKNOWN||UNKNOWN", "data_type": None, "violation": None,
                    "confidence": 0.0, "source": "rules", "needs_review": True,
                    "review_reason": "contract_signal_absent_strict", "tier": tier}
        # 说明：若无 SCOPE_CONTRACT，走到这里的样本必然"无信号字段"（否则上面已拦截）；
        # 若开启了 SCOPE_CONTRACT 且 consent_scope 合法存在，则已满足 v1.2 判别要求。
        # 【修正 · 第五轮】原此处是 `_ = _scope_declared_empty`（赋了值却从不使用 = 死代码），
        # 而契约文档 §0.1 却宣称"consent_scope = [] ⇒ 可自动判 NONE||COMPLIANT"。
        # 实测澄清：空声明**不是**一种特权，它只是"通过了契约闸门"，随后仍要过其余闸门
        # （API 契约 / 混淆 / 敏感语义 / 采集迹象 / dtype 哨兵），与旧的 strict 路径同源。
        # 真正的加固在下方 dt 已识别分支里的 `contract_scope_contradiction`：
        # 用 consent_scope 去**印证**而非**授权**。故此处不再保留死变量。
        # 无混淆痕迹 + 无敏感语义词 + 无 API 命中 + 无采集迹象 → 真·无个人数据
        # tier 标记为 "none_verified"：显式声明本结论**已通过 5 道闸门**
        #   (1) 无 API 契约命中  (2) 无混淆痕迹  (3) 无敏感语义词
        #   (4) params 无任何信号字段（无个人信息处理行为）  (5) dtype 哨兵无异议
        #   （严格模式 PC_STRICT_NONE=1 下再追加第 6 道：契约完整性）
        # 只有 tier ∈ {"full","none_verified"} 才允许输出 COMPLIANT（INV-1'）。
        # 【第五轮】本出口此前是**无条件** needs_review=False，即不受 λ 控制 ——
        # 那会让"真·NONE"成为 CRC 无法收紧的自动出口。现改为同样受 λ 约束：
        # λ ≤ 0.9 时照旧自动放行（默认行为不变）；λ > 0.9 时一并转复核。
        _nv_thr = _auto_lambda("none_verified")
        return {"combo": build_combo("NONE", "COMPLIANT"),
                "data_type": "NONE", "violation": "COMPLIANT",
                "confidence": 0.9, "source": "rules",
                "needs_review": bool(0.9 < _nv_thr),
                "review_reason": ("none_verified_below_lambda" if 0.9 < _nv_thr else None),
                "tier": "none_verified"}

    sig, parsed_ok, missing = parse_signals(text)
    if not parsed_ok:
        return {"combo": f"{dt}||UNKNOWN", "data_type": dt, "violation": None,
                "confidence": 0.0, "source": "rules", "needs_review": True,
                "review_reason": "params_unparseable", "tier": tier}

    # 【P0-C / P0-E】改用 decide_ex：
    #   · 类型不合契约（malformed）→ 证据不可用 → fail-closed 转人工，绝不静默当缺失
    #   · 合规元数据完全不可观测 → 不可判 + 部分识别区间 → 转人工（不猜违规也不猜合规）
    v, _malformed, _bounds = decide_ex(dt, sig)
    if _malformed:
        return {"combo": f"{dt}||UNKNOWN", "data_type": dt, "violation": None,
                "confidence": 0.0, "source": "rules", "needs_review": True,
                "review_reason": "signal_type_malformed:" + ",".join(_malformed[:4]),
                "tier": tier}
    if v is None:
        return {"combo": f"{dt}||UNKNOWN", "data_type": dt, "violation": None,
                "confidence": 0.0, "source": "rules", "needs_review": True,
                "review_reason": (_bounds or {}).get("reason", "indeterminate"),
                "bounds": _bounds, "tier": tier}
    # 置信度：核心信号（同意证据/传输/脱敏）存在即高置信；
    # 同意证据 = consent_state 或 consent_log 任一（替代证据路径）
    consent_ok = ("consent_state" in sig) or ("consent_log" in sig)
    transport_ok = ("crypto" in sig) or ("transport" in sig)
    mask_ok = "pii_mask" in sig
    n_missing_core = sum(1 for x in (consent_ok, transport_ok, mask_ok) if not x)
    if n_missing_core == 0:
        confidence = 0.99
    elif n_missing_core == 1:
        confidence = 0.8
    else:
        confidence = 0.55
    # 部分混淆态（仅类名/方法名可读）：即使信号齐全，也降级入复核
    reasons = []
    # 间接识别层一律不得高置信自动定论（契约 §0 表格：Tier2/3/4 均为"是"复核）。
    # 【2026-10-07 修正】原实现只覆盖 class/method，漏了 payload —— 与契约不一致：
    #   payload 层在信号齐全时 confidence 可达 0.99 → 自动出结论，违反契约。
    # 现改为：payload / consent（Tier5，本次新增）同 class/method 一并降级。
    if tier in ("class", "class_ambiguous", "method", "method_ambiguous"):
        confidence = min(confidence, 0.85)
        reasons.append("partial_identifier")
    elif tier in ("payload", "consent"):
        # 契约 §0 表格要求 Tier4(payload) 必须复核。但间接层若判定为**违规方向**，
        # 自动放行的风险只是"误报"（false alarm），**不产生漏判**——因为
        # 唯一能产生漏判的方向（判 COMPLIANT）已被下面的 INV-1' 无条件拦下。
        # 故提供 PC_INDIRECT_AUTOPASS=1：允许间接层在**非 COMPLIANT** 时自动定论，
        # 用"误报率"换"人工量"，**漏判率在数学上不受影响**。默认关闭（严格守契约）。
        if not (_INDIRECT_AUTOPASS and v != "COMPLIANT"):
            confidence = min(confidence, 0.85)
            reasons.append(f"indirect_tier:{tier}")
    # 【INV-1' 强制 · 2026-10-07】只有 tier=="full"（完整 API 契约命中）才允许输出 COMPLIANT。
    # 间接推断层（payload / consent）即使算出 COMPLIANT 也必须降级复核 ——
    # 因为"类型是推出来的"，真实类型可能与推断不同；而类型不同，违规结论就不同：
    #   consent_scope=["PHONE"] 但实际采集 ID_CARD → 应为 NO_CONSENT（范围外），
    #   按 PHONE 算却得 COMPLIANT → 漏判。故 fail-closed。
    if v == "COMPLIANT" and tier != "full":
        confidence = min(confidence, 0.85)
        reasons.append(f"indirect_tier_compliant:{tier}")
    # 【第五轮 · 契约自证矛盾检测（v1.2 的真实用法）】
    # `consent_scope` 是上游的**自我声明**。原实现把它当成"权限"（空数组即可自动合规），
    # 但 `_scope_declared_empty` 实际是**死代码**——真正让空声明通过的是
    # 「契约闸门过了 → 其余闸门都没意见 → 落到 none_verified 自动出口」这条路径。
    # 于是存在一个纯信任漏洞：上游**说谎**（声明空/未含该类型，实际却采集）时，
    # 我们可能自动判合规。正确的用法不是"信它"，而是**拿它做交叉印证**：
    #   · consent_scope = []      → 上游称"本次不涉及个人信息"
    #   · consent_scope = [其他]  → 上游称"未授权该类型"
    # 若引擎已从**独立证据**（API 契约 / payload 键名 / consent_scope 自身）推出 dt，
    # 而声明里不含 dt，两者矛盾 ⇒ 绝不自动输出 COMPLIANT（fail-closed 转人工）。
    # 这同时也让"上游说谎"从一个**不可见**的信任风险，变成一个**可审计**的信号
    # （review_reason = contract_scope_contradiction，可直接做比例监控与告警）。
    # 零回归验证：干净数据 4218 条自动合规样本的 scope **全部**含 dt，该分支触发 0 次。
    # 只对 v == "COMPLIANT" 生效：若结论本身已是违规（如"范围外"→NO_CONSENT），
    # 自动给出它是**正确**的，不必转人工 —— 否则会把合法建模的"范围外"违规
    # （实测干净数据有 1057 条 scope 不含 dt）全部转人工，白增人工成本而不降漏判。
    if (_SCOPE_CONTRACT and v == "COMPLIANT"
            and isinstance(sig.get("consent_scope"), list)
            and dt not in sig["consent_scope"]):
        confidence = min(confidence, 0.85)
        reasons.append("contract_scope_contradiction")
        # 检出即撤销：把"上游声明与独立证据矛盾"这一形态永久拉黑。
        # 诚实边界：这只在**已识别 dt** 时触发；若攻击者同时让键名失明（dt 识别不出），
        # 则由上方 `_scope_declared_empty` 的值级形态检测接管，两条互补、无重叠缺ロ。
        _sa_revoke(text, "contract_scope_contradiction")
    if not consent_ok:
        reasons.append("no_consent_evidence")
    if not transport_ok:
        reasons.append("no_transport_info")
    if not mask_ok:
        reasons.append("no_mask_info")
    # 【第五轮】自动放行阈值 = 校准得到的 λ（无校准文件时恒为 0.9，与原实现逐位等价）。
    # 逐 tier 取值：full 与间接层可各有自己的 λ（Mondrian 分组校准的落地方式）。
    _thr = _auto_lambda(tier)
    needs_review = confidence < _thr
    return {"combo": f"{dt}||{v}", "data_type": dt, "violation": v,
            "confidence": confidence, "source": "rules",
            "needs_review": needs_review,
            "review_reason": (",".join(reasons)) if needs_review else None,
            "tier": tier, "auto_lambda": _thr}


if __name__ == "__main__":
    import sys, json as _j
    txt = sys.stdin.read()
    print(_j.dumps(classify(txt), ensure_ascii=False, indent=2))
