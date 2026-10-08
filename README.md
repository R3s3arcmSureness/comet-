# 移动安全隐私合规分类模型(comet-)
# 项目位于Demo阶段，后期可能出现较大调整

对逆向 Hook 层产出的**明文栈调用 + 参数 + 合规上下文字段**做多分类判定：**隐私数据类型 × 违规类型**（92 组合类），并输出校准置信度、判定来源与复核标记。覆盖 **安卓 / 小程序 / iOS / 鸿蒙** 四端，支持 CPU 训练。

> 基座对齐开源决策模型生态 **Laya**（经 [ollaya](https://github.com/ollaya-dev/ollaya) 本地化）。微调同家族 `jhu-clsp/mmBERT-small`（CPU 可训），生产可换 mmBERT-base（GPU）。

## 架构

```
逆向明文(栈+参数+合规信号)
  ├─► 规则引擎 ── 核心字段齐全(conf>=0.9) → 直接判定（唯一可输出 COMPLIANT 的层）
  └─► L3 模型兜底（低置信/缺字段时，逐级 fail-closed 降级）
        ① l3-struct  分层结构化（data_type 线性头 × violation 树头）
        ② mmBERT-finetuned（需部署闸门通过，否则跳过）
        ③ tfidf-fallback（旧基线，仅前两者不可用时兜底）
  置信 < 阈值 或 与规则冲突 → needs_review
```

## 核心特性

- **规则引擎主判**：按平台匹配真实 SDK API、缺字段降级、复核标记；策略由 `policy.py` 单一事实来源实现。
- **捷径消除**：多路径触发合成数据，最佳单字段决策树桩精度 29.4%，92 类全部可生成（均衡 1086~1089/类）。
- **CRC 校准**：离线校准 λ̂、双口径（条件/联合）、Mondrian 分组、PAC 口径、LTT 人工预算；读取端独立数值复核证书。
- **空声明安全网**：确定性抽样（HMAC）+ 撤销回路 + 值级 PII 形态印证。

## 目录

| 文件 | 说明 |
|---|---|
| `labels.py` | 标签体系单一事实来源：NONE\|\|COMPLIANT + 13 PII 类型 × 7 违规 = 92 类 |
| `policy.py` | 合规策略唯一实现（生成器/规则引擎共用） |
| `apis.py` | 四端真实 SDK API 目录 + OOD 变体策略 + 业务必要性映射 |
| `generate_data.py` | 合成数据生成器（多路径触发 + 噪声 + 字段缺失 + JSON 乱序） |
| `rules_engine.py` | 规则引擎：按平台匹配 API、缺字段降级、复核标记 |
| `deobfuscate.py` | L2 输入哨兵 + 三层反混淆 |
| `calibrate.py` / `calib_runtime.py` | 离线 CRC 校准 / 校准文件运行时读取与证书数值复核 |
| `scope_audit.py` | 空声明安全网（确定性抽样 + 撤销回路） |
| `check_runtime.py` / `check_hardening.py` | 运行时回归 C1–C12 / 加固自检 H1–H5 |
| `train_l3_struct.py` / `l3_features.py` | 分层结构化 L3 训练与特征抽取（训练/推理共用单一事实来源） |
| `finetune_transformer.py` | mmBERT 微调（dev 最优 checkpoint + 早停 + 温度校准） |
| `predict.py` | 生产推理入口（L3 后端逐级 fail-closed + 校准 + 复核队列） |
| `docs/hook_schema_contract.md` | Hook 输入 Schema 契约（字段枚举 + 缺失语义） |
| `THIRD_PARTY_NOTICES.md` | 第三方许可证声明（mmBERT MIT / transformers Apache-2.0） |

## 快速开始

```bash
# 1) 生成数据（v3 多路径版）
python generate_data.py --train 100000 --dev 10000 --test 20000 --ood 10000

# 2) 微调（生产全量：CPU 过夜或 GPU；--early_stop 按 dev 最优 checkpoint 保存）
python finetune_transformer.py --model jhu-clsp/mmBERT-small \
  --max_train 100000 --epochs 4 --batch 32 --maxlen 320 --eval_steps 500 --early_stop

# 3) 批量推理（自动加载 mmBERT；TF-IDF 自动降级）
python predict.py --in data/test.jsonl --out results.jsonl

# 4) 单条推理
echo '<text>' | python predict.py
```

## 保证层与安全网

四层漏斗：**L2 输入哨兵 → L1 确定性规则（唯一可输出 COMPLIANT）→ L3 本地模型 → L4a 外部 LLM（可选）→ L4b 人工复核**。

| 不变量 | 内容 |
|---|---|
| INV-1′ | 只有 `tier ∈ {full, none_verified}` 才允许自动输出 COMPLIANT |
| 证书不可自证 | 读取端独立复核 α 与违约分母（严格 int、`≤ n`），伪造即视为未认证，λ 钳回 ≥0.9 |
| 来源闸门 | 合成集哈希命中即拒 + 必须 `PC_ALLOW_REAL=1` |
| 契约地板 | 间接层 λ ≥ 0.86，与校准文件无关；合法证书也无法越过 |
| env 只能收紧 | λ、抽样率、审计开关只能收紧；放松须显式 `PC_ALLOW_RELAX=1` |

关键环境变量：`PC_SCOPE_CONTRACT`（契约 v1.2，默认 1）、`PC_REQUIRE_CALIB`、`PC_SCOPE_AUDIT_KEY`、`PC_ALLOW_REAL`、`PC_ALLOW_RELAX`。

```bash
python check_runtime.py    # C1–C12 运行时回归（含安全网）
python check_hardening.py  # H1–H5 加固自检
python measure_path.py     # 漏判率 / 降级率溯源
python calibrate.py --all --verify     # 校准 + 解析模型一致性
python calibrate.py --real --data real.jsonl --write   # 认证 → models/calibration.json
```

## 诚实声明

1. 规则引擎在合成数据上的 100% 一致是「策略实现自证」，**不构成模型能力证据**；模型独立精度见 `reports/finetune_metrics.json`。
2. 合规信号字段（`consent_state` 等）必须由 Hook 层提供（契约 §2）；缺字段时违规判定在信息论上不可达。
3. 所有精度数字基于合成分布，**上线前必须真实日志复测**。
4. **「99.9%」目前是「机制已就绪 + 契约合规输入下实测 0 漏判」，不是已签发的保证。** 签发保证需人工标注的真实日志（≥999 条真违规）→ `calibrate.py --real --write` → `guarantee=true` 的 `models/calibration.json`。
5. `--real` 是上游自证：读取端只做数值复核，无法证明标签经人工标注，该背书仍需人工审计。
6. 真实日志实测（某小程序，6364 条）：默认配置（契约 OFF）下实测漏判率 9.43%；开启契约后 0 漏判（代价：100% 人工复核）。合成数据上的 0.99 **不迁移**到真实分布，根因是上游输入不符合契约（无信号字段、标识符仍混淆、编码残留）。

## 许可证

依赖第三方组件许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
