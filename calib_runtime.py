# -*- coding: utf-8 -*-
"""calib_runtime.py — 校准参数的**运行时读取**（rules_engine / predict 共用）

背景（第五轮 · 前沿文献落地）
------------------------------------------------
第四轮报告确认：自动产出 COMPLIANT 的出口在结构上只有两个 ——
    tier == "full"          且 confidence ≥ 阈值
    tier == "none_verified" 且 confidence(=0.9) ≥ 阈值
其余 tier 一律被 INV-1' 强制转复核。因此"把置信阈值当成单调旋钮 λ"这件事
**在本架构下是可证明的**：λ 增大 ⇒ 自动集合单调收缩 ⇒ 漏判单调不增。

Conformal Risk Control（arXiv:2208.02814）给出的选 λ 公式：
    λ̂ = inf { λ : n/(n+1)·R̂ₙ(λ) + B/(n+1) ≤ α }
在交换性下保证 E[ℓ] ≤ α。`calibrate.py` 负责离线搜 λ̂ 并写入校准文件。

本模块只做一件事：**把校准文件读进来，解析成规则引擎能用的阈值**。

四条设计原则（都很重要）
------------------------------------------------
1. **默认零影响**：没有校准文件时 `auto_lambda()` 恒为 0.9 ——
   与改动前的硬编码 `confidence < 0.9` **逐位一致**，保证历史回归可比。
2. **只能收紧、不能凭空放松**：`guarantee=false` 的校准（合成/未验证）
   **不得**把 λ 压到 0.9 以下。否则一份在合成分布上"零漏判"的校准集
   就能把系统放松到自动放行 conf=0.55 的样本 —— 那是净增漏判。
3. **契约地板不可越**：Tier2/3/4(payload/consent) 的 confidence 上限是 0.85，
   λ 一旦 ≤0.85 就会让间接识别层自动定论，直接违反契约 §0。
   故对间接层强制 λ ≥ 0.86，与校准集无关。
4. **状态可查**：`calib_status()` 供 `check_runtime.py` C10 使用。
   没有校准集**不是运行错误**（系统仍能 fail-closed 运行），
   但"声称 99.9% 却拿不出校准证据"必须是**可见**的，不能像 P0-A 那样静默。
"""
import os
import json
import math

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_AUTO_LAMBDA = 0.9          # ← 历史行为，勿改
CALIB_PATH_DEFAULT = os.path.join(HERE, "models", "calibration.json")

# 【红队 P0-1 修复】**唯一可签发部署证书的目标 α**（= 生产目标 99.9% 漏判容忍）。
# 与 calibrate.ALPHA_TARGET 必须同值；此处独立复刻是刻意的——读取端**不得**
# 依赖写入端的常量，否则"伪造一份校准文件"就能绕过写入端的闸门。
ALPHA_TARGET = 0.001

# 间接识别层：契约要求必须复核（§0 表格 Tier2/3/4/5）
# 另含 "full_ambiguous"（Tier1 命中但 payload 证据冲突，第五轮 D4 修复新增）：
# 该 tier 的 COMPLIANT 结论已被 INV-1' 无条件阻断，此处再给它同等的阈值地板。
INDIRECT_TIERS = frozenset({
    "class", "class_ambiguous", "method", "method_ambiguous", "payload", "consent",
    "full_ambiguous",
})
CONTRACT_FLOOR = 0.86              # 严格大于间接层 0.85 的置信上限

_CACHE = {"loaded": False, "calib": None, "path": None, "error": None}


def calib_path():
    return os.environ.get("PC_CALIB_PATH") or CALIB_PATH_DEFAULT


def load_calibration(force=False):
    """读取校准文件。返回 (calib_dict_or_None, error_str_or_None)。

    绝不抛异常：调用方（规则引擎）必须在**任何**情况下都能继续 fail-closed 运行。
    读取失败只记录原因，由 C10 显式暴露。
    """
    if _CACHE["loaded"] and not force:
        return _CACHE["calib"], _CACHE["error"]
    p = calib_path()
    calib, err = None, None
    if not os.path.exists(p):
        err = "calibration_file_absent"
    else:
        try:
            with open(p, encoding="utf-8") as f:
                calib = json.load(f)
            if not isinstance(calib, dict):
                calib, err = None, "calibration_not_a_dict"
        except Exception as e:                       # noqa: BLE001
            calib, err = None, f"calibration_parse_error:{type(e).__name__}"
    _CACHE.update(loaded=True, calib=calib, path=p, error=err)
    return calib, err


def reload():
    """清缓存（测试 / 校准完成后热重载用）。"""
    _CACHE.update(loaded=False, calib=None, path=None, error=None)
    return load_calibration(force=True)


def _f(x):
    try:
        v = float(x)
        return v if v == v else None                  # 过滤 NaN
    except (TypeError, ValueError):
        return None


def n_min_required(alpha):
    """有限样本硬下界 `⌈1/α⌉ − 1`。α 不可用（含下溢/溢出）时返回 **None**。

    【第三轮独立复核 · 崩溃缺陷】原实现 `int(math.ceil(1.0 / alpha)) - 1` 在
    `alpha=5e-324`（最小次正规数）时 `1/alpha = inf` ⇒ `math.ceil(inf)` 抛
    `OverflowError` —— 而 `guarantee_verdict()` 在规则引擎的**每次 classify()** 里
    都会被调用，于是**伪造一份 `models/calibration.json` 就能让整条引擎崩掉**
    （fail-closed 的本意是"拒绝"，不是"抛异常"）。故任何不可计算都显式返回 None，
    由调用方按"拒绝"处理。inf 本身已被 `alpha > ALPHA_TARGET` 挡住，这里兜的是
    "α 比目标严得离谱"（1/α 上溢）这类**拒绝路径上的异常**。
    """
    if alpha is None:
        return None
    if isinstance(alpha, bool) or not isinstance(alpha, (int, float)):
        return None
    a = float(alpha)
    if a != a or a <= 0:
        return None
    try:
        inv = 1.0 / a
    except (ZeroDivisionError, OverflowError):
        return None
    if inv != inv or inv == float("inf") or inv > 1e18:
        return None
    if inv < 1.0:                       # α > 1（含 inf）⇒ 无意义，交由"比目标松"检查拒绝
        return None
    try:
        return int(math.ceil(inv)) - 1
    except (OverflowError, ValueError):
        return None


def effective_lambda(lam, tier=None, guarantee=True):
    """把"期望的 λ"映射为**实际生效**的 λ（单调不减）。规则：

      · 间接层（Tier2/3/4/5）→ 至少 CONTRACT_FLOOR（契约地板）
      · guarantee=False（合成/未验证校准）→ 至少 DEFAULT_AUTO_LAMBDA（不得放松）

    guarantee=True 仅表示"允许放松到 0.9 以下"，不表示 λ 一定 <0.9。
    """
    v = _f(lam)
    if v is None:
        v = DEFAULT_AUTO_LAMBDA
    if tier in INDIRECT_TIERS:
        v = max(v, CONTRACT_FLOOR)
    if not guarantee:
        v = max(v, DEFAULT_AUTO_LAMBDA)
    return v


def resolve_lambda(tier=None):
    """解析 λ（未施加地板），返回 (λ, 来源字符串)。"""
    env = _f(os.environ.get("PC_AUTO_LAMBDA"))
    if env is not None:
        return env, "env:PC_AUTO_LAMBDA"
    calib, _ = load_calibration()
    if isinstance(calib, dict):
        by_tier = calib.get("lambda_by_tier")
        if isinstance(by_tier, dict) and tier is not None:
            v = _f(by_tier.get(tier))
            if v is not None:
                return v, "calib:lambda_by_tier[%s]" % tier
        v = _f(calib.get("lambda_auto"))
        if v is not None:
            return v, "calib:lambda_auto"
    return DEFAULT_AUTO_LAMBDA, "default"


def guarantee_verdict(calib):
    """**独立复核**校准文件是否有资格把 λ 放松到 0.9 以下。返回 (ok, reason)。

    红队 P0-1 的核心教训：`guarantee=true` 是**文件里的一个字**。
    若读取端只信这个字，那么"用 `--alpha 1.5` 生成"甚至"手写一个 JSON"
    都能让系统放松 λ —— 那 99.9% 就是纸面数字。故读取端**必须重算不等式**：

      (1) `guarantee is True`
      (2) `alpha` 存在且 `alpha ≤ ALPHA_TARGET`（只允许比生产目标**更严**）
      (3) `n_violation ≥ ⌈1/alpha⌉ − 1`   （有限样本硬下界；
          分母**必须是** `n_violation`（条件口径的真违规数）。键缺失或类型不对一律拒绝，
          见 V1(a) 修复注释——不接受任何"退回总行数"的乐观降级）

    任何一项不满足 → 视为**未认证**（`guarantee=false` 的等价行为：λ 钳到 ≥0.9）。
    这是 fail-closed 方向：误判的风险是"多转人工"，不是"多漏判"。
    """
    if not isinstance(calib, dict):
        return False, "no_calibration"
    # 【类型严格性】与 `policy.py` 的既定契约一致：**绝不把"类型不对"静默当成合法值**。
    #   · `guarantee` 必须**严格**是布尔 True。用真值判断会让 `"false"`/`"no"` 这类
    #     非空字符串被当成 True（policy.py 已踩过一次同源的坑：`policy_disclosed="false"`）。
    #   · `alpha` 必须**是数字**；不接受 `"0.001"` 这种字符串（float() 会静默强转）。
    if calib.get("guarantee") is not True:
        return False, "guarantee_not_strict_true"
    raw_alpha = calib.get("alpha")
    if isinstance(raw_alpha, bool) or not isinstance(raw_alpha, (int, float)):
        return False, "alpha_not_numeric"
    alpha = float(raw_alpha)
    if alpha != alpha or alpha <= 0:                 # NaN / 非正
        return False, "alpha_missing_or_invalid"
    if alpha > ALPHA_TARGET + 1e-12:
        return False, "alpha_looser_than_target(%g>%g)" % (alpha, ALPHA_TARGET)
    # 【独立复核 V1(a) 修复】分母必须严格、且必须**存在**。
    # 原实现把"键存在但类型不对"（`{"n_violation": true}`、`{"n_violation": "1e5"}`）
    # **静默降级**为退回 `n` 再判 —— 攻击者只要随便塞一个错类型的 `n_violation`
    # （或干脆用 `true`），即可让读取端改用**总行数**当分母，而总行数恒大于等于
    # 真违规数 ⇒ 有限样本墙「n_den ≥ ⌈1/α⌉−1」被**白白放宽**。
    # 更要命的是：`n` 作为分母在**条件口径**下是**错误**的（条件口径的分母只能是
    # 真违规数），用它通过墙 = 用乐观分母换来的假认证。
    # 本次进一步收紧：连"键**缺失**就退回 `n`"也一并去掉。理由：
    #   · 本项目校准器**恒**同时写 `n_violation`（calibrate.py `"n_violation": n_viol`,
    #     其 `guarantee_type` 只取 marginal/train_cond/none，**从不**是"仅联合口径"）；
    #   · 官方指标是**条件**漏判率（miss_rate_on_violation），其分母**只能是**真违规数，
    #     所以任何拿不出 `n_violation` 的证书都**无法**支持所声称的条件保证；
    #   · 唯一代价是"拒绝一个本就无法验证的旧/外来证书"—— 正是 fail-closed 方向。
    _MISSING = object()
    n_den = calib.get("n_violation", _MISSING)
    if n_den is _MISSING:
        return False, "n_violation_missing"
    if isinstance(n_den, bool) or not isinstance(n_den, int):
        return False, "n_violation_wrong_type(%r)" % (n_den,)
    if n_den < 0:
        return False, "n_violation_negative(%d)" % n_den
    # 【第三轮独立复核】`n` 也必须严格：原实现 `isinstance(n, int)` 不成立就**静默跳过**
    # `≤ n` 一致性检查，于是 `{"n_violation": 1e6, "n": 5.0}`（5 行里 1e6 个违规，
    # 自相矛盾）仍被认证 —— `n="5"`、`n=true` 同样绕过。与 V1(a) 同根因：
    # **"键存在但类型不对"绝不能等价于"键不存在"**。
    n_all = calib.get("n", _MISSING)
    if n_all is not _MISSING:
        if isinstance(n_all, bool) or not isinstance(n_all, int):
            return False, "n_wrong_type(%r)" % (n_all,)
        if n_all < 0:
            return False, "n_negative(%d)" % n_all
        if n_den > n_all:
            return False, "n_violation_exceeds_n(%d>%d)" % (n_den, n_all)
    n_min = n_min_required(alpha)
    if n_min is None:
        # 含 `alpha=5e-324` 这类"1/α 上溢"的情形：无法计算 ⇒ 无法认证 ⇒ 拒绝（fail-closed）
        return False, "alpha_not_computable(%r)" % (alpha,)
    if n_den < n_min:
        return False, "n_violation_below_wall(%d<%d)" % (n_den, n_min)
    return True, "ok"


def _guarantee_flag():
    """是否允许把 λ 放松到 0.9 以下。

    【红队 P1-1 修复】原实现："只要 `PC_AUTO_LAMBDA` 存在就返回 True"，
    于是这个**环境变量**成了一个**未经认证的放松开关**：任何能设环境变量的路径
    （误操作、CI 变量、攻击者可控的部署脚本）都能让 λ=0.55 生效，
    使 tier="full" 且 confidence=0.55 的样本自动放行 —— 而 0.55 意味着
    三个核心信号（同意/传输/脱敏）缺了两个。这是净增漏判。

    【红队 P0-1 修复】校准文件路径原先直接 `bool(calib.get("guarantee"))` ——
    现在改为走 `guarantee_verdict()` 的**独立数值复核**（α 不得比目标松、
    违约分母不得低于有限样本墙）。见该函数 docstring。

    现收紧为：
      · 环境变量**不再**隐含"允许放松"；默认仍受 0.9 地板约束。
      · 只有显式 `PC_ALLOW_RELAX=1`（实验/`calibrate.py --verify` 专用）才放开。
      · 校准文件须通过 `guarantee_verdict()` 的全部数值校验。
    """
    if os.environ.get("PC_AUTO_LAMBDA") is not None:
        return os.environ.get("PC_ALLOW_RELAX") == "1"
    calib, _ = load_calibration()
    ok, _reason = guarantee_verdict(calib)
    return ok


def auto_lambda(tier=None):
    """返回该 tier 实际生效的自动放行阈值 λ。

    语义：**当且仅当 `confidence >= λ` 才允许自动出结论**（严格小于则转复核）。
    λ 越大越保守。
    """
    lam, _src = resolve_lambda(tier)
    return effective_lambda(lam, tier, _guarantee_flag())


def lambda_info(tier=None):
    """调试用：返回 (λ_生效, 来源, 是否被地板抬高)。"""
    lam, src = resolve_lambda(tier)
    eff = effective_lambda(lam, tier, _guarantee_flag())
    return eff, src, (eff > lam + 1e-12)


def calib_value(key, default=None):
    """从校准文件取一个标量配置（无校准文件/缺键 ⇒ default）。"""
    calib, _ = load_calibration()
    if isinstance(calib, dict):
        v = _f(calib.get(key))
        if v is not None:
            return v
    return default


def calib_status():
    """校准健康度（给 check_runtime C10 用）。"""
    calib, err = load_calibration()
    st = {
        "path": calib_path(),
        "present": calib is not None,
        "error": err,
        "guarantee": None,
        "guarantee_verified": False,
        "guarantee_verdict": "no_calibration",
        "alpha": None,
        "alpha_target": ALPHA_TARGET,
        "n": None,
        "n_violation": None,
        "n_min_required": None,
        "n_ok": None,
        "method": None,
        "source": None,
        "provenance": None,
        "lambda_auto": None,
        "lambda_by_tier": None,
        "created_utc": None,
        "using_default": calib is None,
        "contract_floor": CONTRACT_FLOOR,
        "default_lambda": DEFAULT_AUTO_LAMBDA,
    }
    if not isinstance(calib, dict):
        return st
    st["guarantee"] = bool(calib.get("guarantee"))
    _ok, _why = guarantee_verdict(calib)
    st["guarantee_verified"] = _ok
    st["guarantee_verdict"] = _why
    st["alpha"] = _f(calib.get("alpha"))
    st["n"] = calib.get("n")
    st["n_violation"] = calib.get("n_violation")
    st["method"] = calib.get("method")
    st["source"] = calib.get("source")
    st["provenance"] = calib.get("provenance")
    st["lambda_auto"] = _f(calib.get("lambda_auto"))
    st["lambda_by_tier"] = calib.get("lambda_by_tier")
    st["created_utc"] = calib.get("created_utc")
    # α 的有限样本硬下界：α=0.001、B=1、零漏判时也需 n_denom+1 ≥ 1/α ⇒ n_denom ≥ 999
    # 【P0-1】分母用**真违规条数**（条件口径）。
    # 【V1(a)】与 `guarantee_verdict` 严格对齐：必须排除 bool（`isinstance(True,int)` 为真），
    # 且**不接受**退回总行数——否则报告会说"n_ok=True"而判定实际拒绝，二者不自洽。
    _nv = st["n_violation"]
    _n_all = st["n"]
    # 【第三轮复核】用共享的 `n_min_required()`：α 不可计算（下溢/上溢）时 n_min=None。
    # `n_ok` 必须**完整镜像** `guarantee_verdict` 的分母相关判定（含 `n` 的类型与 `≤n`
    # 一致性），否则会出现「报告说 n_ok=True 而判定实际拒绝」的自相矛盾。
    _nmin = n_min_required(st["alpha"])
    _ok = (isinstance(_nv, int) and not isinstance(_nv, bool)
           and _nmin is not None and _nv >= _nmin)
    if _ok and _n_all is not None:
        _ok = (isinstance(_n_all, int) and not isinstance(_n_all, bool)
               and _n_all >= 0 and _nv <= _n_all)
    st["n_min_required"] = _nmin
    st["n_ok"] = _ok
    return st


if __name__ == "__main__":
    import pprint
    pprint.pprint({
        "status": calib_status(),
        "auto_lambda(full)": auto_lambda("full"),
        "auto_lambda(payload)": auto_lambda("payload"),
        "auto_lambda(none_verified)": auto_lambda("none_verified"),
        "lambda_info(payload)": lambda_info("payload"),
    })
