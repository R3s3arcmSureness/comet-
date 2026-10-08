# 部署与调试日志回传指南

> 面向：需要在**另一台服务器**上跑真实数据、并把**调试日志**回传以便继续优化的人。
> 全程 **纯 CPU**，无需 GPU、无需联网。

---

## 0. 包内有什么 / 没有什么

| 包含 | 说明 |
|---|---|
| 全部运行期源码 | `pipeline.py`（四层漏斗，**推荐入口**）、`predict.py`、`rules_engine.py`、`apis.py`、`deobfuscate.py`、`policy.py`、`labels.py`、`calib_runtime.py` |
| 观测与自检 | `debuglog.py`（调试日志）、`dbg_summary.py`（日志汇总）、`smoke_test.py`（部署自检，**55 项**，自包含）、`measure_path.py`、`check_robust.py`（轻量回归，自包含） |
| 上游日志导入 | `import_real_log.py`（把 Hook 采集的文本日志转成契约 JSONL，如你方格式不同可改这一段） |
| 生产模型 | `models/l3_struct/`（4.4 MB，含 `deploy_gate.json` 闸门）、`models/dtype_guard*.pkl`、`models/calibration.candidate.json` |
| 契约与文档 | `docs/hook_schema_contract.md`（**输入契约，必读**）、`README.md`、`reports/*.md`（含真实日志结论，便于对照） |
| 小样本 | `data/test_ood.jsonl`（10 MB，用于冒烟；**非必需**，可删） |

| **不包含**（刻意排除） | 原因 |
|---|---|
| `models/ft_transformer/`、`ft_mmbert_smoke/`、`ft_transformer_stale_v1/`（合计约 5 GB） | 需 torch，且**未过部署闸门**，生产不会采用；体积过大 |
| `models/clf.pkl` + `vec.pkl`（TF-IDF 降级后端，57 MB） | 只在 l3-struct 不可用时才用；本包含 l3-struct，故省略。**如需**降级兜底，从主仓库拷回即可 |
| `data/train.jsonl`（90 MB）等训练集 | 只是训练用，部署不需要 |
| `check_hardening.py`、`check_contract.py`、`check_data.py`、`check_runtime.py` | 需 90 MB 合成训练集才能跑；部署自检请用包内 `smoke_test.py`（自包含 55 项） |
| `calibrate.py`、`redteam*.py`、`train_*.py`、`generate_data.py`、`probe_*.py` | 训练/红队/一次性探针，均依赖合成数据集；留在主仓库 |
| `realdata/*.log`（真实客户日志） | **含个人信息，不外发** |

> 结论：解压后约 **25 MB**，可直接 scp 到内网服务器。

---

## 1. 安装（3 步）

```bash
# 1) 建虚拟环境（Python ≥ 3.8；推荐 3.10–3.13）
python3 -m venv .venv && . .venv/bin/activate

# 2) 装依赖（只有 numpy + scikit-learn，纯 CPU wheel）
pip install -r requirements.txt

# 3) 自检 —— 必须全绿再往下走
python smoke_test.py
```

`smoke_test.py` 会检查：环境/依赖、模型与**部署闸门**、四端目录覆盖、
判定不变式（`COMPLIANT` 只能来自完整匹配）、契约判别器、fail-closed、
以及**调试日志链路是否可写/可解析/已脱敏**。看到
`结果：通过 N 项，失败 0 项` 才算部署成功。

---

## 2. 输入格式

每条样本是**三段文本**（详见 `docs/hook_schema_contract.md` §1）：

```
[platform=android|ios|miniprogram|harmony]
stack: <栈帧1> <- <栈帧2> <- ...
params: { ...json... }
```

批量输入用 **JSONL**，每行至少含 `id` 与 `text` 两个字段：

```json
{"id": "00001", "text": "[platform=miniprogram]\nstack: wx.getSystemInfoSync\nparams: {\"api\":\"getSystemInfoSync\",\"consent_scope\":[]}"}
```

> **最重要的一条**：`params` 里请按契约带上**信号字段**
> （`consent_state` / `consent_scope` / `crypto` / `pii_mask` / `biz_purpose` …）。
> 没有它们，系统只能 fail-closed 全量转人工 —— **安全，但没有自动化收益**。
> 这正是我们上一轮在真实日志上实测到的瓶颈，也是这次回传日志要定位的东西。

---

## 3. 运行（推荐入口：`pipeline.py`）

```bash
# 批量；结果写 results.jsonl
python pipeline.py --in your_data.jsonl --out results.jsonl
```

两个入口的区别（**请优先用 pipeline**）：

| 入口 | 含义 | 何时用 |
|---|---|---|
| `pipeline.py` | **四层漏斗**：L2 输入哨兵 → L1 确定性规则（唯一可发 `COMPLIANT`）→ L3 本地模型 → L4a 外部 LLM（可选）→ L4b 人工复核。带 INV-1/2/3 不变式 | **生产判定**（推荐） |
| `predict.py` | 早期「规则 + 模型 + 冲突复核」混合路径 | 需要模型置信/冲突诊断时 |

输出字段：`decision`（`COMPLIANT` / 违规类别 / `null`=未定）、`data_type`、
`needs_human`、`final_layer`（哪一层给出结论）、`review_reason`（转人工原因）、`trace`（各层轨迹）。

---

## 4. ★ 开启调试日志（本次回传的核心）

**默认完全关闭**：不建目录、不开文件、不做字符串处理，判定结果逐位不变。

```bash
export PC_DEBUG_LOG=1
export PC_DEBUG_LOG_LEVEL=safe              # meta | safe | full，默认 safe
export PC_DEBUG_LOG_PATH=$PWD/logs/debug.jsonl
python pipeline.py --in your_data.jsonl --out results.jsonl
```

| 环境变量 | 默认 | 含义 |
|---|---|---|
| `PC_DEBUG_LOG` | *(关)* | `1` 开启 |
| `PC_DEBUG_LOG_LEVEL` | `safe` | `meta`=只记元信息不落文本；`safe`=**保留 API/栈帧/字段名，抹掉值**；`full`=原始明文（**可能含个人信息，仅限内网**） |
| `PC_DEBUG_LOG_PATH` | `<包>/logs/debug.jsonl` | 输出路径 |
| `PC_DEBUG_LOG_MAX_MB` | `64` | 超限自动轮转为 `.1` |
| `PC_DEBUG_LOG_TEXT_CAP` | `2000` | 单条文本落盘上限（防超大输入撑爆） |
| `PC_DEBUG_LOG_STDERR` | *(关)* | `1` 时同时把每样本一行摘要打到 stderr |
| `PC_DEBUG_LOG_KEEP_TEXT` | *(关)* | `1` 等价于把 `meta` 提升为 `safe` |

日志是 **JSONL，一行一事件**，事件类型：

| `ev` | 内容 |
|---|---|
| `run_start` | 本次运行的环境快照（含 `PC_*` 开关、Python/平台版本）+ 输入文件 + 条数 |
| `backend` | L3 后端选择过程：每一级是否可用、闸门值、降级原因 |
| `sample` | **主事件**，每条样本一行：出口（`AUTO_COMPLIANT`/`AUTO_VIOLATION`/`REVIEW`）、`l1_*`/`l3_*`/`l4a` 各层结论、`review_reason`、按阶段耗时 `ms`、`api`、`text`（按级别脱敏） |
| `error` | 任一阶段异常：类型 + 截断 traceback（含输入摘要，便于定位坏样本） |
| `run_end` | 汇总：条数、复核数、复核率、总耗时 |

### 脱敏说明（`safe` 级）

保留：**平台行、栈帧、`params` 的键名、短枚举值**（如 `consent_scope: ["DEVICE_ID"]`）、
API 名 —— 这些是定位「目录缺口 / 契约违约」的必要信息。
抹掉：手机号、身份证、银行卡、邮箱、经纬度、URL、密钥、长高熵串、以及
键名含 `phone/id/token/uid/openid/...` 的值（打码为 `<redacted:len=N:sha1=xxxxxxxxxx>`）。
用 `sha1` 前缀仍可**跨样本识别"同一个值"**（例如判断某设备 id 被重复上报），但不泄露原值。

---

## 5. 回传前：一键自查 PII

```bash
python dbg_summary.py logs/debug.jsonl --pii-scan
# 输出「PII 自查：未发现疑似明文（日志可安全外传）✅」即可外发
```

若提示命中，请改用 `PC_DEBUG_LOG_LEVEL=safe` 重跑，或人工确认后再外传。

---

## 6. 本地先看一份汇总（可选，但建议）

```bash
python dbg_summary.py logs/debug.jsonl --out summary.md
```

产出：环境快照 / 后端闸门 / 结论分布 / **复核原因 Top-N** / **按 API 的复核占比** /
L1 命中层级 / L3 置信分布 / 分阶段耗时（均值·p50·p95·max）/ 异常清单 /
**自动优化建议**（例如"第一大复核原因是 X，Top 未命中目录的 API 是 …"）。

---

## 7. 回传清单（请一并附上）

1. `logs/debug.jsonl`（必要时含轮转的 `logs/debug.jsonl.1`）——**必需**
2. `python dbg_summary.py logs/debug.jsonl --out summary.md` 产出的 `summary.md` —— 可选但省事
3. `python smoke_test.py` 的完整输出 —— 确认部署环境一致
4. 你的**输入样本格式说明**（哪个端、`params` 里实际有哪些键、是否含信号字段）
5. 若有**真值标注**（哪条真的违反了哪一类），一并给我 —— 只有带真值才能算真实准确率

> 提醒：日志里**没有**真值标签，所以我能从日志里优化的是
> 「复核率 / 目录覆盖 / 契约违约分布 / 模型表现 / 异常」，
> 而要证明 **99.9% 漏判率** 必须要有标注。

---

## 8. 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| stderr 出现 `mmBERT-finetuned unavailable (No module named 'torch')` | **正常**。本包不带 torch，直接降级到 `l3-struct`。`backend` 事件里能看到最终采用的后端 |
| 所有样本都 `needs_human=true`，`review_reason=contract_missing_consent_scope` | **符合设计**：上游没传 `consent_scope` 时系统 fail-closed。这是**我们要一起优化的上游问题**，不是 bug |
| 结果几乎没有 `COMPLIANT` | 同上；`COMPLIANT` 只由 L1 在**完整匹配**且无 fail-closed 时给出（INV-1） |
| `review_reason` 含 `obfuscated_identifier_unresolved` | 输入里还有未还原的混淆标识符，需上游完成反混淆 |
| `review_reason` 含 `L2_input_residual:encoded_token` | 输入里还有 base64/高熵/加密残留，L2 哨兵拦截（fail-closed） |
| 想跑得更快 | 关掉日志即可回到无观测开销；`PC_DEBUG_LOG_LEVEL=meta` 也能大幅减小日志体积 |
| `python` 找不到 | 用 `python3`，或先 `. .venv/bin/activate` |

---

## 9. 与主仓库的差异（便于你对照）

本包 = 主仓库的**运行期子集 + 新增观测三件套**：
`debuglog.py`（采集）、`dbg_summary.py`（分析）、`smoke_test.py`（自检）、
以及 `pipeline.py`/`predict.py` 中的日志接线（默认关闭，零行为变化）。

**未包含**：需要 90 MB 合成训练集才能运行的全套回归
（`check_hardening.py` / `check_contract.py` / `check_data.py` / `check_runtime.py`）
与训练/红队脚本（`calibrate.py`、`redteam*.py`、`train_*.py`、`generate_data.py`、
`finetune_transformer.py`、`probe_*.py`、`reports/_*.py`）。
它们留在主仓库，由我这边跑；你那边的自检请用包内自包含的 `smoke_test.py`
（**55 项**，覆盖环境/闸门/四端目录/不变式/契约判别器/fail-closed/日志链路/脱敏规则双向单测）。
