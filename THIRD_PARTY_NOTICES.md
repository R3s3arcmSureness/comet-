# Third-Party Notices / 第三方组件声明

本项目（privacy_compliance）在生产部署中直接或间接使用以下开源组件，
按其许可证要求在此声明。商业使用时请随应用分发本文件。

## 模型权重

| 组件 | 来源 | 许可证 | 使用方式 |
|---|---|---|---|
| mmBERT (mmBERT-small / mmBERT-base) | https://huggingface.co/jhu-clsp/mmBERT-small (Johns Hopkins University CLSP) | MIT | 微调基座权重。MIT 要求：保留版权与许可声明 |
| Laya / ollaya 生态（架构参考） | https://github.com/ollaya-dev/ollaya | 参考其仓库声明 | 仅作"System-1 非生成式判定模型"的架构与部署形态参考，未复制代码/权重 |

## Python 库

| 组件 | 许可证 | 用途 |
|---|---|---|
| PyTorch | BSD-style | 训练/推理框架 |
| transformers (Hugging Face) | Apache-2.0 | 模型加载/训练器 |
| scikit-learn | BSD-3 | TF-IDF 基线、指标（macro-F1/classification_report）、决策树桩审计 |
| numpy / pandas | BSD-3 | 数值计算 |
| jieba | MIT | （已装未用，可移除） |

## 许可证义务摘要

- **MIT（mmBERT）**：在发布物（含模型权重的产品）中保留原作者版权声明与本声明文件即可；可商用、可修改、可闭源分发。
- **Apache-2.0（transformers）**：分发时保留 LICENSE 与 NOTICE；对库的修改需显著标注。
- 本项目的 `generate_data.py / policy.py / rules_engine.py / predict.py` 为自研代码，
  其中**策略逻辑（policy.py）**建议经法务评审后作为公司内部合规资产。

## 与"基于开源项目"的边界说明

- 规则引擎+模型混合判定架构思想参考 Microsoft Presidio（MIT）与 Laya/ollaya 的
  System-One 模型定位，未复制其代码。
- 校验和验证（Luhn/身份证 mod-11）参考 rizzo-pii（MIT）思路，实现为原创代码。
