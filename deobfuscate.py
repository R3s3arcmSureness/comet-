# -*- coding: utf-8 -*-
"""deobfuscate.py — L2 输入质量哨兵 + 兜底还原层（生产级 v2）

【契约前提（2026-10-07 用户澄清）】
上游（用户的逆向工具链）已完成**脱壳 / 解混淆 / 解密**，送入本服务的是
「明文 JAVA 调用堆栈 + 明文传参」。因此本层**不是主路径还原器**，而是：

  1. 输入质量哨兵（input_guard）：验证"明文"契约是否被上游遵守。
     · 干净明文 → 直接放行（正常路径零开销，不触发任何还原算子）
     · 有残留混淆/加密痕迹（高熵串 / sf: / b64: / 零宽 / 同形字）
       → fail-closed：**强制人工复核**，绝不猜测后自动判定
  2. 兜底真实还原（deobfuscate_text）：仅当上游偶有遗漏、且残留**可确定性还原**
     （base64/url/hex/unicode/零宽/StringFog）时，做安全还原后交回主判；
     启发式还原（ROT13/XOR）仅在极端情况下使用且必须过验证器。

以下为原 v1 的还原算子实现（保留，供哨兵与兜底复用）。

设计原则（来自反混淆前沿调研 DIMVA'25 / arXiv:2505.19887）：
1. 确定性优先：L1 层（编码类）100% 可逆，零假阳性风险
2. 迭代到不动点：处理嵌套编码（base64→URL→unicode），最多 10 轮
3. **验证器强制**：所有启发式还原（ROT13/XOR/base64）必须过验证器，
   否则丢弃还原结果——宁可不还原，也不能污染输入（假阳性会抬高误差地板）
4. 结构保护：不破坏 [platform=x]/stack:/params: 结构与 JSON 有效性
5. 可审计：每次还原记录 (原串, 还原串, 方法, 置信度)，供人工复核

接口：
    deobfuscate_text(text, max_iter=10) -> (normalized_text, report)
    report = {"applied": [...], "confidence": float, "suspected_encrypted": bool}
"""
import re
import base64
import binascii
import codecs
import html
import unicodedata
from urllib.parse import unquote

# ---------------- 零宽字符 / 隐藏字符 ----------------
ZERO_WIDTH = {
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u2060",  # WORD JOINER
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE (BOM)
    "\u00ad",  # SOFT HYPHEN
    "\u180e",  # MONGOLIAN VOWEL SEPARATOR
}
_ZW_RE = re.compile("[" + "".join(re.escape(c) for c in ZERO_WIDTH) + "]")

# ---------------- 可打印性验证器（防假阳性核心） ----------------
_PRINTABLE_ASCII_RE = re.compile(r"^[\x20-\x7e\s]+$")
# Java 标识符 / 包名 / API 名的合法字符（含 . : / _ $ 与中英文字母数字）
_IDENT_CHARS_RE = re.compile(r"^[\w\.\$:/\[\]\-\(\)\s<>,@#\*\+=&%\?\|!;'\"]+$", re.U)


def _printable_ratio(s):
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return ok / len(s)


def _is_plausible_text(s, min_len=4):
    """还原结果是否"像合法文本"：可打印占比高，或命中常见代码/中文特征。"""
    if len(s) < min_len:
        return False
    if _printable_ratio(s) < 0.9:
        return False
    # 至少包含一个字母/中文/常见符号，排除纯控制字符
    if not re.search(r"[A-Za-z\u4e00-\u9fff]", s):
        return False
    return True


def _looks_like_code_token(s):
    """还原结果是否像 API/包名/字段名（用于 base64 包装的标识符）"""
    if not _is_plausible_text(s, min_len=4):
        return False
    # 含点分标识符 / camelCase / 下划线，视为代码 token
    return bool(re.search(r"[A-Za-z]", s)) and re.search(
        r"[A-Za-z_][\w\$]*(\.[A-Za-z_][\w\$]*)+|_[a-z]|[a-z][A-Z]|wx\.|ohos", s)


# ---------------- L1 确定性还原 ----------------

def strip_zero_width(s):
    """剥离零宽/隐藏字符（100% 确定）"""
    new = _ZW_RE.sub("", s)
    return new, (new != s)


def nfkc(s):
    """NFKC 归一化：全角→半角、兼容字符折叠（100% 确定）"""
    new = unicodedata.normalize("NFKC", s)
    return new, (new != s)


def decode_unicode_escapes(s):
    """解码 \\uXXXX / \\UXXXXXXXX / \\xNN / \\NNN(八进制)（100% 确定）"""
    if "\\" not in s:
        return s, False
    orig = s

    def _u(m):
        return chr(int(m.group(1), 16))

    def _x(m):
        return chr(int(m.group(1), 16))

    def _o(m):
        return chr(int(m.group(1), 8))

    s = re.sub(r"\\u([0-9a-fA-F]{4})", _u, s)
    s = re.sub(r"\\U([0-9a-fA-F]{8})", _u, s)
    s = re.sub(r"\\x([0-9a-fA-F]{2})", _x, s)
    s = re.sub(r"\\([0-7]{3})", _o, s)
    return s, (s != orig)


def decode_html_entities(s):
    """解码 HTML 实体 &amp; / &#x..; / &#..;（100% 确定）"""
    if "&" not in s:
        return s, False
    new = html.unescape(s)
    return new, (new != s)


def decode_url(s):
    """URL 百分号编码 %XX / %uXXXX（100% 确定）"""
    if "%" not in s:
        return s, False
    orig = s
    # %uXXXX 形式（非标准但常见）
    s = re.sub(r"%u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    s = unquote(s)
    return s, (s != orig)


_B64_RE = re.compile(r"^[A-Za-z0-9+/\-_]{4,}={0,2}$")
_B64_PREFIXES = ("b64:", "base64:", "b64_", "b64=")


def decode_base64(s):
    """Base64 还原（带严格校验，防假阳性）。
    支持标准/URL-safe、带 b64: 前缀（前缀可信 → 放宽长度门槛，覆盖短值如
    4 字符的 http/self/name）；裸串启发式（严格，防误报）。"""
    raw = s.strip()
    low = raw.lower()
    has_prefix = False
    for p in _B64_PREFIXES:
        if low.startswith(p):
            raw = raw[len(p):].strip()
            has_prefix = True
            break
    core = raw.rstrip("=")
    min_core = 4 if has_prefix else 12          # 前缀可信→宽松；裸串→严格
    if len(core) < min_core or not _B64_RE.match(raw.replace(" ", "")):
        return s, False
    try:
        pad = (-len(core)) % 4
        candidate = core.replace("-", "+").replace("_", "/") + "=" * pad
        decoded = base64.b64decode(candidate, validate=True)
        text = decoded.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return s, False
    if has_prefix:
        # 显式前缀 → 可信，仅需"可打印"
        if not text or _printable_ratio(text) < 0.9:
            return s, False
    else:
        if not (_is_plausible_text(text) and _printable_ratio(text) > 0.95):
            return s, False
    return text, True


_HEX_RE = re.compile(r"^(?:0x)?([0-9a-fA-F]{2}){4,}$")


def decode_hex(s):
    """十六进制还原（带校验）。支持 0x 前缀、\\xNN 串、裸 hex。"""
    raw = s.strip()
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    raw = raw.replace(" ", "").replace("\\x", "")
    if not _HEX_RE.match(raw) or len(raw) < 8 or len(raw) % 2:
        return s, False
    try:
        decoded = bytes.fromhex(raw).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return s, False
    if not (_is_plausible_text(decoded) and _printable_ratio(decoded) > 0.95):
        return s, False
    return decoded, True


# ---------------- StringFog 风格：XOR + Base64（真实高频手法） ----------------
# StringFog 把字符串替换为 decrypt(bytes,key)：明文 = cipher XOR key（key 重复使用）
# 密文形如 sf:<b64key>:<b64cipher>，key 嵌入代码中 → 静态可确定性还原
_SF_RE = re.compile(r"^sf:([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$")


def decode_stringfog(s):
    """还原 StringFog 风格（XOR + Base64）字符串。格式 sf:<b64key>:<b64cipher>（100% 确定）"""
    m = _SF_RE.match(s.strip())
    if not m:
        return s, False
    try:
        key = base64.b64decode(m.group(1))
        cipher = base64.b64decode(m.group(2))
    except (binascii.Error, ValueError):
        return s, False
    if not key or not cipher:
        return s, False
    plain = bytes(c ^ key[i % len(key)] for i, c in enumerate(cipher))
    try:
        text = plain.decode("utf-8")
    except UnicodeDecodeError:
        return s, False
    # StringFog 格式明确（sf:key:cipher），解码即确定；仅需可打印校验
    # （注意：短值时不得用 min_len=4，否则 "raw"/"all" 等 3 字枚举会漏还原）
    if not _is_plausible_text(text, min_len=1):
        return s, False
    return text, True


# ---------------- Unicode 同形字折叠（homoglyph / confusable） ----------------
# NFKC 无法折叠同形字（如西里尔 а U+0430 vs 拉丁 a U+0061），需显式映射（UTR#39）
_CONFUSABLE = {
    # 西里尔 → 拉丁
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u0501": "d",
    "\u043a": "k", "\u043c": "m", "\u043d": "h", "\u0442": "t", "\u0432": "b",
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0420": "P", "\u0421": "C",
    "\u0425": "X", "\u0423": "Y", "\u0406": "I", "\u0405": "S", "\u041a": "K",
    "\u041c": "M", "\u041d": "H", "\u0422": "T", "\u0412": "B",
    # 希腊 → 拉丁
    "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03c1": "p", "\u03c4": "t",
    "\u03b9": "i", "\u03bd": "v", "\u03ba": "k", "\u03bc": "u", "\u03c7": "x",
    "\u03b3": "y", "\u039f": "O", "\u0391": "A", "\u0395": "E", "\u03a1": "P",
    "\u03a4": "T", "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u03a7": "X",
    # 常见数学/字母数字变体
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-",
    "\uff0e": ".", "\u2024": ".", "\u30fb": ".",
}
_CONF_RE = re.compile("[" + "".join(re.escape(k) for k in _CONFUSABLE) + "]")


def fold_confusables(s):
    """折叠 Unicode 同形字为拉丁等价字符（100% 确定，仅替换已知同形字）"""
    if not _CONF_RE.search(s):
        return s, False
    return _CONF_RE.sub(lambda m: _CONFUSABLE[m.group(0)], s), True


# ---------------- Unicode Tag（不可见标签字符 U+E0001-E007F） ----------------
_TAG_RE = re.compile(r"[\U000E0000-\U000E007F]")


def strip_unicode_tags(s):
    """剥离 Unicode Tag 字符（用于隐藏指令的不可见字符，100% 确定）"""
    if not _TAG_RE.search(s):
        return s, False
    return _TAG_RE.sub("", s), True


# ---------------- L2 启发式还原（必须过验证器） ----------------

# 代码词打分器：用于 rot13 等启发式还原的"方向"判定
# 关键：按 camelCase / snake_case / 数字边界切分为**子词**后整词匹配，
# 避免 "battery_pct"->"onggrel_cpg" 里子串 "on" 造成的误触发。
_CODE_WORDS = frozenset("""
get set send handle request response dispatch query fetch load save init create
start stop open close read write check verify update delete insert add remove register
unregister bind connect disconnect call exec run process parse format encode decode
encrypt decrypt sign login logout location manager device camera account contact record
activity service client provider store session token user phone sms message calllog
file image photo media audio video network wifi bluetooth telephony settings secure
content observer listener callback handler adapter helper bridge impl factory builder
config info data result error event state status action intent bundle context view page
app core sdk api system permission privacy consent policy auth credential identify
advertise os ui util on click did view appear disappear submit tap
analytics statistics stats map push pay payment vendor novel away geo extra torch
pearl river group soft base pro kit cloud function bank card face finger print
biometric scan mail inbox message compose health walk run record recognizer reader
tracker analytics observe notify notify sync cache remote local proxy request
""".split())

_SUBWORD_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+|[a-z]+")


def _subwords(s):
    return [w.lower() for w in _SUBWORD_RE.findall(s or "")]


def _code_score(s):
    """s 中包含的完整代码子词数量（整词匹配，防子串误报）"""
    return sum(1 for w in _subwords(s) if w in _CODE_WORDS)


def decode_rot13(s):
    """ROT13 还原（启发式）。rot13 与其逆等价 → 用子词级代码打分判定方向。
    两类安全信号：① 还原后命中已知枚举/数据类型（精确，短串也安全）
                  ② 还原后出现代码子词（要求原串≥6字符以限误报）"""
    if len(s) < 3 or not re.search(r"[A-Za-z]{2,}", s):
        return s, False
    # 守卫：原串已含代码子词 → 跳过，避免反向破坏
    if _code_score(s) >= 1:
        return s, False
    cand = codecs.decode(s, "rot_13")
    # 验证器1：还原后命中已知枚举值/数据类型（如 "tenatrq"->"granted"、"CUBAR"->"PHONE"）
    if cand.casefold() in _ENUM_CANON:
        return _ENUM_CANON[cand.casefold()], True
    # 验证器2：原串无代码子词，还原后出现代码子词（如 "NanylgvpfPyvrag"->"AnalyticsClient"）
    if len(s) >= 6 and _code_score(cand) >= 1:
        return cand, True
    return s, False


def _is_readable(s):
    """串是否已"可读"：可打印占比高 且 含 3+ 连续字母（词级片段）。
    可读串绝不送入 XOR/启发式，避免二次破坏。"""
    if not s:
        return False
    if _printable_ratio(s) < 0.85:
        return False
    return bool(re.search(r"[A-Za-z\u4e00-\u9fff]{3,}", s))


def decode_single_byte_xor(s):
    """单字节 XOR 暴力枚举（启发式，仅当还原结果高度像代码时采纳）。
    严格守卫：① 输入须为**高熵非可打印**串（真实 XOR 密文的特征）
    ② 还原结果须高度像文本 ③ 词级片段≥3。可读串、base64/hex 一律跳过。
    注：本算子极保守——无 XOR 特征的正常值（如 138****8888）绝不触发。"""
    if len(s) < 10:
        return s, False
    # 守卫1：可打印占比高 → 不是 XOR 密文（XOR 密文必含控制字符）→ 跳过
    if _printable_ratio(s) > 0.75:
        return s, False
    # 守卫2：疑似 base64/hex（已在确定性层处理）→ 跳过
    body = re.sub(r"^(b64:|base64:|0x|sf:)", "", s.strip(), flags=re.I)
    if _B64_RE.match(body) or _HEX_RE.match(body):
        return s, False
    best, best_score = s, 0
    for k in range(1, 256):
        try:
            cand = bytes(b ^ k for b in s.encode("latin-1", "ignore")).decode("utf-8", "ignore")
        except Exception:
            continue
        if len(cand) < 8 or not _is_plausible_text(cand):
            continue
        score = len(re.findall(r"[A-Za-z]{3,}|[\u4e00-\u9fff]", cand))
        if score > best_score:
            best, best_score = cand, score
    # 阈值：至少 3 个词级片段才算可信（防假阳性）
    if best_score >= 3:
        return best, True
    return s, False


# 反射/常量拼接还原：getMethod("get" + "Id" + "\u004eame") -> getIdName
_REFLECT_RE = re.compile(r'"([^"]*)"(?:\s*\+\s*"([^"]*)")+')


def resolve_string_concat(s):
    """还原字符串常量拼接（编译期折叠 / 反射拼接）（100% 确定）。
    例：\"get\"+\"Id\" -> getId（并去掉包裹引号，便于枚举/API 匹配）。"""
    if '"' not in s or "+" not in s:
        return s, False
    orig = s

    def _collapse(m):
        parts = re.findall(r'"([^"]*)"', m.group(0))
        return '"' + "".join(parts) + '"'

    new = _REFLECT_RE.sub(_collapse, s)
    if new == orig:
        return s, False
    # 若整串折叠为单一引号字面量 "ABC" → 去引号得 ABC（供枚举值/API 精确匹配）
    m2 = re.fullmatch(r'"([^"]*)"', new)
    if m2:
        new = m2.group(1)
    return new, True


# ---------------- 枚举值大小写归一化（还原 case 混淆） ----------------
# 真实的合规信号值是有限枚举（consent_state/crypto/data_destination/...）。
# 攻击者可能对代码内嵌字面量做大小写混淆（GrAnTeD），此处按已知词表归一化。
_ENUM_CANON = {}
for _v in [
    # 合规信号枚举
    "granted", "denied", "revoked", "withdrawn", "not_asked", "unknown", "absent",
    "masked", "raw", "partial", "self", "third_party", "minimal", "all",
    "https", "http", "true", "false", "none",
    # 加密套件
    "AES-256-GCM", "TLS1.3", "SM4-GCM", "RSA-OAEP", "ChaCha20-Poly1305",
    "DES-ECB", "AES-ECB",
    # 业务用途
    "core_function", "account_security", "verification", "identity_verification",
    "payment", "analytics", "security", "notification", "profile",
    "content_publish", "health_service", "navigation", "weather", "social", "backup",
    "video_call", "ad_recommend", "marketing", "performance", "user_profiling",
    "arbitrary_extend",
    # 数据类型（consent_scope / collect_scope 的取值）
    "PHONE", "ID_CARD", "BANK_CARD", "DEVICE_ID", "EMAIL", "NAME", "EXACT_IMAGE",
    "HEALTH", "LOCATION", "SMS", "CONTACTS", "BIOMETRIC", "CAMERA_MIC", "NONE",
]:
    _ENUM_CANON.setdefault(_v.casefold(), _v)


def canonicalize_enum(s):
    """若 s 大小写不敏感地匹配已知枚举值，归一化为规范形式（100% 确定）。
    仅整串匹配时替换，避免误伤 API 名/路径。"""
    if not s or len(s) > 40:
        return s, False
    canon = _ENUM_CANON.get(s.casefold())
    if canon is not None and canon != s:
        return canon, True
    return s, False


# ---------------- 迭代到不动点 ----------------
# 每轮按序应用全部还原算子；任一轮无变化即收敛
_DETERMINISTIC_OPS = [
    ("strip_zero_width", strip_zero_width),
    ("strip_unicode_tags", strip_unicode_tags),
    ("fold_confusables", fold_confusables),
    ("nfkc", nfkc),
    ("unicode_escape", decode_unicode_escapes),
    ("html_entity", decode_html_entities),
    ("url", decode_url),
    ("stringfog", decode_stringfog),          # 须在 base64 之前（自带 sf: 格式）
    ("string_concat", resolve_string_concat),
    ("base64", decode_base64),
    ("hex", decode_hex),
    ("canonicalize_enum", canonicalize_enum),  # 最后：枚举值大小写归一化
]
# 启发式（高风险，最后单轮执行）
_HEURISTIC_OPS = [
    ("rot13", decode_rot13),
    ("xor", decode_single_byte_xor),
]


def deobfuscate_token(s, max_iter=10, heuristics=True):
    """对一个 token/字符串值迭代还原到不动点。返回 (结果, applied 列表)"""
    applied = []
    cur = s
    if not isinstance(cur, str) or not cur:
        return cur, applied
    for _ in range(max_iter):
        changed = False
        for name, fn in _DETERMINISTIC_OPS:
            new, ok = fn(cur)
            if ok and new != cur:
                cur = new
                applied.append(name)
                changed = True
        if not changed:
            break
    if heuristics:
        for name, fn in _HEURISTIC_OPS:
            new, ok = fn(cur)
            if ok and new != cur:
                cur = new
                applied.append(name)
    return cur, applied


# ---------------- 结构化处理 ----------------

# 需要做还原的"可还原区"：JSON 字符串值、栈帧标识符
# 思路：只对「被引号包裹的字符串值」和「明显是 base64/hex/零宽的裸 token」还原，
# 避免误伤平台标记、结构关键字。
_JSON_STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

# 栈帧中的"可还原 token"联合模式（按真实混淆形态）：
#   StringFog(sf:key:cipher) / base64前缀 / hex / 拼接链 / 标识符
_STACK_TOKEN_RE = re.compile(
    r"sf:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+"
    r"|b64:[A-Za-z0-9+/=]+"
    r"|0x[0-9a-fA-F]{12,}"
    r"|(?:\"[^\"]*\"\s*\+\s*)+\"[^\"]*\""
    r"|[A-Za-z_][\w\.\$]{3,}"
)
# 仍留在文中的高熵不可还原 token（疑似真加密 → 提示需动态分析/人工复核）
_RESIDUAL_ENC_RE = re.compile(r"sf:[A-Za-z0-9+/=]{16,}|b64:[A-Za-z0-9+/=]{16,}|0x[0-9a-fA-F]{32,}")


def _deob_structural_line(line, report):
    """对一行栈帧中的可还原 token 逐一还原（含标识符 rot13 还原）。"""
    def _repl(m):
        tok = m.group(0)
        out, applied = deobfuscate_token(tok, heuristics=True)
        if applied and out != tok:
            report["applied"].extend([f"stack:{a}" for a in applied])
            return out
        return tok

    # 行级清理必须先做：零宽/Unicode Tag 夹在标识符段间会破坏 token 切割
    line, _ = strip_unicode_tags(line)
    line, _ = strip_zero_width(line)
    new = _STACK_TOKEN_RE.sub(_repl, line)
    new, _ = nfkc(new)
    return new


def _deob_params(params_raw, report):
    """对 params JSON 的每个字符串值做还原，保持 JSON 结构有效。"""
    import json
    try:
        obj = json.loads(params_raw)
    except Exception:
        # JSON 本身被混淆（整体 base64 等）：先整体还原
        decoded, applied = deobfuscate_token(params_raw, heuristics=False)
        if applied:
            report["applied"].extend([f"params-block:{a}" for a in applied])
            try:
                obj = json.loads(decoded)
            except Exception:
                return decoded if applied else params_raw
        else:
            return params_raw

    def _walk(v):
        if isinstance(v, str):
            out, applied = deobfuscate_token(v, heuristics=True)
            if applied and out != v:
                report["applied"].extend([f"param:{a}" for a in applied])
            return out
        if isinstance(v, dict):
            return {k: _walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [_walk(x) for x in v]
        return v

    try:
        return json.dumps(_walk(obj), ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return params_raw


def deobfuscate_text(text, max_iter=10, heuristics=True):
    """主入口：结构化反混淆整个输入。

    返回 (normalized_text, report)
    report = {"applied": [...], "confidence": float,
              "suspected_encrypted": bool, "changed": bool}
    """
    report = {"applied": [], "confidence": 1.0, "suspected_encrypted": False}
    if not isinstance(text, str) or not text:
        return text, report

    lines = text.split("\n")
    out = []
    params_buf = None
    params_started = False

    for ln in lines:
        if params_started:
            params_buf = (params_buf + "\n" + ln) if params_buf else ln
            continue
        if ln.startswith("params:"):
            params_started = True
            params_buf = ln[len("params:"):].lstrip()
            continue
        # 普通行（platform 标记 / stack 行）
        if ln.startswith("[platform="):
            out.append(ln)
        else:
            out.append(_deob_structural_line(ln, report))

    if params_started:
        new_p = _deob_params(params_buf, report) if params_buf else params_buf
        out.append("params: " + (new_p or ""))

    normalized = "\n".join(out)

    # 置信度：确定性还原 = 1.0；含启发式（rot13/xor）= 降级
    heur_hits = sum(1 for a in report["applied"] if a.endswith("rot13") or a.endswith("xor"))
    if heur_hits:
        report["confidence"] = max(0.5, 1.0 - 0.15 * heur_hits)

    # 疑似加密：仍有高熵不可读 token（无法确定性还原）
    residual = _RESIDUAL_ENC_RE.findall(normalized)
    if residual:
        report["suspected_encrypted"] = True

    report["changed"] = (normalized != text)
    report["applied"] = list(dict.fromkeys(report["applied"]))  # 去重保序
    return normalized, report


# ---------------- 输入质量哨兵 ----------------

# 干净输入中绝不该出现的高熵编码 token（用于判定"上游是否处理干净"）
# 注意：宁可漏报（交下游 fail-closed 兜底），也绝不误报——误报会把明文打回复核。
_GUARD_ENC_RE = re.compile(
    r"sf:[A-Za-z0-9+/=]{8,}:[A-Za-z0-9+/=]{8,}"        # StringFog 密文（显式格式）
    r"|b64:[A-Za-z0-9+/=_-]{8,}"                        # 显式 base64 前缀
    r"|base64:[A-Za-z0-9+/=_-]{8,}"
    r"|0x[0-9a-fA-F]{24,}"                              # 超长 hex
    r"|(?:\\u[0-9a-fA-F]{4}){6,}"                       # 密集 unicode 转义
    r"|(?:%[0-9a-fA-F]{2}){8,}"                         # 密集 URL 编码
)
# 裸 base64 候选：超长（≥40）且需二次校验（含大小写+数字，或有 +/= 特征）才判定
_BARE_B64_RE = re.compile(r"(?<![\w+/=])[A-Za-z0-9+/]{40,}={0,2}(?![\w+/=])")


def _has_bare_b64(text):
    """裸 base64 残留检测（高阈值，防误伤长驼峰标识符）。

    判据：长度 ≥40 且 ① 同时含大写/小写/数字，或 ② 含 + / = 特征字符。
    纯字母的长标识符（如 requestAuthorizationToShareTypes）一律不算。
    """
    for m in _BARE_B64_RE.finditer(text):
        t = m.group(0)
        if "+" in t or "/" in t or t.endswith("="):
            return True
        if re.search(r"[A-Z]", t) and re.search(r"[a-z]", t) and re.search(r"\d", t):
            return True
    return False


def input_guard(text):
    """输入质量哨兵：判断"明文"契约是否被上游遵守。

    与 deobfuscate_text 的区别：
      - deobfuscate_text = 「尽力还原」（可能改变输入）
      - input_guard     = 「只做判断，不改输入」（决定放行 / 拦截复核）

    返回 dict：
      {"clean": bool,          # True=干净明文，可直接进入判定
       "residual": [...],      # 检出的残留混淆类型
       "suspected_encrypted": bool,  # 是否疑似仍有加密/混淆未处理
       "action": "pass"|"review"|"preprocess"}
    """
    if not isinstance(text, str) or not text:
        return {"clean": False, "residual": ["empty"], "suspected_encrypted": False,
                "action": "review"}

    residual = []
    if _ZW_RE.search(text):
        residual.append("zero_width")
    if _TAG_RE.search(text):
        residual.append("unicode_tag")
    if _CONF_RE.search(text):
        residual.append("confusable")
    if _GUARD_ENC_RE.search(text) or _has_bare_b64(text):
        residual.append("encoded_token")

    suspected = "encoded_token" in residual

    if not residual:
        # 完全干净：直接放行，零开销
        return {"clean": True, "residual": [], "suspected_encrypted": False,
                "action": "pass"}

    # 低危残留（零宽/同形字/标签）：可确定性还原 → 建议先预处理再判
    if not suspected:
        return {"clean": False, "residual": residual, "suspected_encrypted": False,
                "action": "preprocess"}

    # 高危（编码密文残留）：上游未处理干净 → fail-closed，强制复核
    return {"clean": False, "residual": residual, "suspected_encrypted": True,
            "action": "review"}


if __name__ == "__main__":
    import sys, json as _j
    raw = sys.stdin.read()
    norm, rep = deobfuscate_text(raw)
    guard = input_guard(raw)
    print(_j.dumps({"normalized": norm, "report": rep, "guard": guard},
                   ensure_ascii=False, indent=2))
