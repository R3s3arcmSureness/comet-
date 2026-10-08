# 发行包清单（MANIFEST）

- 构建时间：2026-10-08T13:24:12
- 源目录：`C:\Users\42283\WorkBuddy\2026-10-07-11-18-55\privacy_compliance`
- Python（构建机）：3.13.14
- 文件数：**86**，解压后 **29.7MB**

## 未包含（刻意排除）

| 路径 | 原因 |
|---|---|
| `models/ft_transformer`、`ft_transformer_stale_v1`、`ft_l2`、`ft_mmbert_smoke` | 需 torch；且未过部署闸门，生产不采用（约 5 GB） |
| `models/clf.pkl`、`models/vec.pkl` | TF-IDF 降级后端（57 MB）；本包含 l3-struct，不需要 |
| `data/train.jsonl`、`test.jsonl`、`dev.jsonl`、`*.csv` | 训练/评测数据，部署不需要 |
| `realdata/` | 真实客户日志，**含个人信息**，不外发 |
| `logs/` | 运行期调试日志，每次运行自行生成 |
| `reports/_*.py`、`_*.log` | 实验中间脚本/日志（结论已汇总进 `reports/*.md`） |
| `check_hardening.py`、`check_contract.py`、`check_data.py`、`check_runtime.py` | 需 90 MB 合成训练集才能跑；部署自检请用包内 `smoke_test.py`（36 项，自包含） |
| `calibrate.py`、`redteam*.py`、`train_*.py`、`generate_data.py`、`obfuscate.py`、`probe_*.py`、`scope_audit.py`、`audit.py` | 训练/红队/一次性探针，均依赖合成数据集；留在主仓库 |

## 文件清单（含 SHA-256）

| 包内路径 | 大小 | SHA-256 |
|---|---:|---|
| `DEPLOY.md` | 10.2KB | `f8c1006211a038cc…` |
| `README.md` | 16.0KB | `d91eb2664a04cb67…` |
| `THIRD_PARTY_NOTICES.md` | 1.8KB | `6b3a67db102d84d1…` |
| `apis.py` | 16.1KB | `20f16426c8288e66…` |
| `apis_expanded.py` | 62.1KB | `01621f7ef3e8c617…` |
| `calib_runtime.py` | 16.7KB | `ece98591d1dfc7f0…` |
| `check_robust.py` | 3.2KB | `752f4d3212402a4b…` |
| `dbg_summary.py` | 14.8KB | `aee6d01e333eb21f…` |
| `debuglog.py` | 21.0KB | `28346f92a6900f0f…` |
| `deobfuscate.py` | 26.3KB | `7be99487f68c5850…` |
| `docs/hook_schema_contract.md` | 71.6KB | `9bc7772d38d26602…` |
| `import_real_log.py` | 5.5KB | `240ec12f8cd21664…` |
| `l3_features.py` | 5.6KB | `218f1264d1d7379c…` |
| `labels.py` | 3.1KB | `806ff4bdc6591193…` |
| `measure_path.py` | 5.4KB | `8bbe3c25fe46868a…` |
| `pipeline.py` | 14.2KB | `49b41996e2406e94…` |
| `policy.py` | 9.9KB | `9ce84c022e9cfb7d…` |
| `predict.py` | 18.2KB | `41a87a02a6c642d9…` |
| `reports/99.9%达成方案_最终决策.md` | 9.3KB | `3f5aeb9060a0cdda…` |
| `reports/_bench_cmo_summary.md` | 5.6KB | `b461b024c11dde82…` |
| `reports/_bench_cpu_routes_结论.md` | 9.5KB | `bed7662131e4f1b9…` |
| `reports/per_class_report.txt` | 7.0KB | `9a727bc13d3ac04a…` |
| `reports/不用外部大模型_可行性论证.md` | 12.6KB | `420cf02385a9bb67…` |
| `reports/全面检查报告_2026-10-07.md` | 10.1KB | `8aa6b402c8a346b1…` |
| `reports/反混淆调研与实现报告.md` | 7.7KB | `32ad3d045ce1a98a…` |
| `reports/多Agent评估与执行报告_第四轮.md` | 12.6KB | `fd6d93b4f1e82e8b…` |
| `reports/多Agent过拟合与质量审计报告.md` | 9.8KB | `387eb06715add7d1…` |
| `reports/多agent评估与优化方向_第六轮.md` | 10.1KB | `6236f02342c8e2de…` |
| `reports/彻底复查报告.md` | 6.3KB | `732adde07731bdc9…` |
| `reports/校准与基础风险_第五轮.md` | 71.3KB | `92c64cb795660055…` |
| `reports/核查报告.md` | 5.9KB | `165795e39c97d024…` |
| `reports/生产级优化执行报告.md` | 4.3KB | `c596d9d35e3dd063…` |
| `reports/真实日志评估_最终结论.md` | 7.7KB | `1772ad1dc9c433bb…` |
| `reports/第三轮多Agent复审报告_2026-10-07.md` | 20.3KB | `9ed242d61f572ce2…` |
| `reports/第二十轮对抗复核.md` | 13.2KB | `e980d24a7d120c8a…` |
| `reports/第十七轮对抗复核.md` | 14.2KB | `7e26050c9d080b2a…` |
| `reports/第十三轮对抗复核.md` | 9.7KB | `594e5433f48c1262…` |
| `reports/第十九轮对抗复核.md` | 10.8KB | `39cee19cf698290e…` |
| `reports/第十二轮对抗复核.md` | 6.1KB | `ff918a61a568377f…` |
| `reports/第十五轮对抗复核.md` | 14.6KB | `13133cbb03c70dc6…` |
| `reports/第十八轮对抗复核.md` | 11.9KB | `358500ebe7c50c61…` |
| `reports/第十六轮对抗复核.md` | 13.0KB | `6a4ac0c97b7270b5…` |
| `reports/第十四轮对抗复核.md` | 12.6KB | `13069fc8f3f058a9…` |
| `reports/红队对抗审查报告.md` | 21.8KB | `e6257afa275560f0…` |
| `reports/输入现实性红队报告.md` | 13.9KB | `5dda3a3734326140…` |
| `reports/部分混淆标识符识别实现报告.md` | 5.4KB | `1c60e90fae880514…` |
| `requirements.txt` | 978B | `5c17d785abea5796…` |
| `rules_engine.py` | 113.8KB | `94b1fff2746b5d40…` |
| `scope_audit.py` | 10.9KB | `3684dc39377f7cbd…` |
| `smoke_test.py` | 13.1KB | `097e7033b2bfcced…` |
| `train_dtype_guard_pure.py` | 6.5KB | `97ebd11f6fab9b42…` |
| `模型选型结论.md` | 14.2KB | `f79dfddcf834df0f…` |
| `docs/hook_schema_contract.md` | 71.6KB | `9bc7772d38d26602…` |
| `tools/gh_search.py` | 3.0KB | `49a6bff39cfec230…` |
| `reports/99.9%达成方案_最终决策.md` | 9.3KB | `3f5aeb9060a0cdda…` |
| `reports/不用外部大模型_可行性论证.md` | 12.6KB | `420cf02385a9bb67…` |
| `reports/全面检查报告_2026-10-07.md` | 10.1KB | `8aa6b402c8a346b1…` |
| `reports/反混淆调研与实现报告.md` | 7.7KB | `32ad3d045ce1a98a…` |
| `reports/多Agent评估与执行报告_第四轮.md` | 12.6KB | `fd6d93b4f1e82e8b…` |
| `reports/多Agent过拟合与质量审计报告.md` | 9.8KB | `387eb06715add7d1…` |
| `reports/多agent评估与优化方向_第六轮.md` | 10.1KB | `6236f02342c8e2de…` |
| `reports/彻底复查报告.md` | 6.3KB | `732adde07731bdc9…` |
| `reports/校准与基础风险_第五轮.md` | 71.3KB | `92c64cb795660055…` |
| `reports/核查报告.md` | 5.9KB | `165795e39c97d024…` |
| `reports/生产级优化执行报告.md` | 4.3KB | `c596d9d35e3dd063…` |
| `reports/真实日志评估_最终结论.md` | 7.7KB | `1772ad1dc9c433bb…` |
| `reports/第三轮多Agent复审报告_2026-10-07.md` | 20.3KB | `9ed242d61f572ce2…` |
| `reports/第二十轮对抗复核.md` | 13.2KB | `e980d24a7d120c8a…` |
| `reports/第十七轮对抗复核.md` | 14.2KB | `7e26050c9d080b2a…` |
| `reports/第十三轮对抗复核.md` | 9.7KB | `594e5433f48c1262…` |
| `reports/第十九轮对抗复核.md` | 10.8KB | `39cee19cf698290e…` |
| `reports/第十二轮对抗复核.md` | 6.1KB | `ff918a61a568377f…` |
| `reports/第十五轮对抗复核.md` | 14.6KB | `13133cbb03c70dc6…` |
| `reports/第十八轮对抗复核.md` | 11.9KB | `358500ebe7c50c61…` |
| `reports/第十六轮对抗复核.md` | 13.0KB | `6a4ac0c97b7270b5…` |
| `reports/第十四轮对抗复核.md` | 12.6KB | `13069fc8f3f058a9…` |
| `reports/红队对抗审查报告.md` | 21.8KB | `e6257afa275560f0…` |
| `reports/输入现实性红队报告.md` | 13.9KB | `5dda3a3734326140…` |
| `reports/部分混淆标识符识别实现报告.md` | 5.4KB | `1c60e90fae880514…` |
| `models/l3_struct/deploy_gate.json` | 219B | `29c5038482bbec73…` |
| `models/l3_struct/model.pkl` | 4.4MB | `a0db2b632eb941cd…` |
| `models/dtype_guard.pkl` | 10.9MB | `18991cadc9725cbf…` |
| `models/dtype_guard_pure.pkl` | 3.5MB | `2f4628a77768b354…` |
| `models/calibration.candidate.json` | 3.2KB | `b553b21a7e29bffc…` |
| `data/test_ood.jsonl` | 9.7MB | `85d991407f988eb6…` |
| `data/stats.json` | 3.1KB | `e6634d7b575999fb…` |

> 校验方式：`python -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" <文件>`（完整哈希见下节）。

## 完整 SHA-256

```
f8c1006211a038cc57428effdb7980bc8b17c0d48570248c19c2612a1fd66797  DEPLOY.md
d91eb2664a04cb67be6de06d0986e78efee9619e9c36c75641a5774f43f1625c  README.md
6b3a67db102d84d14698e680edbdd44886b3637030cdd5d1f63a22519c91f86a  THIRD_PARTY_NOTICES.md
20f16426c8288e66e31eaf2772f15fa1e57918b9995ac3e5df7450402b4ad444  apis.py
01621f7ef3e8c617e11a143727e0f066ce93f3e9e58f68fe32b7b9dcecb11e62  apis_expanded.py
ece98591d1dfc7f01a145d1b25c426d17fe8c4ab0f84201c7d3591849f07827f  calib_runtime.py
752f4d3212402a4b5480f93e7106bc2b6dcf7037856d94e35b2c4de9ee00bda1  check_robust.py
aee6d01e333eb21f3a347302d38825f8a63b05ed765cf74bc3e5e69d58d3c49a  dbg_summary.py
28346f92a6900f0ff875ac2368bb97bdab8524fda0642b4e1755b76e67045269  debuglog.py
7be99487f68c585093767119c21d7488e9a28da8a3d2075fa73bbdebc9bb3c79  deobfuscate.py
9bc7772d38d266029d3923369f31de4e5d9236b1b1ec7983d7b36fadfbe18369  docs/hook_schema_contract.md
240ec12f8cd216646b1ce3e11bbdca544bf6df12db6577e04cd085ea32466cca  import_real_log.py
218f1264d1d7379cae4e48054c1744d851038817c2d128440a2db61541cf2bbc  l3_features.py
806ff4bdc659119359161ab79c32ccdd43f84a5a3dd6719230b4ea2a5d05f9e6  labels.py
8bbe3c25fe46868ac1244a3a0584208dabaae34c382082e5a72966502c1d1d1f  measure_path.py
49b41996e2406e946fcc5d3d1415887f7dd9638aa308e5e26cd98b02b22394fd  pipeline.py
9ce84c022e9cfb7d310486dccdd099b4e763d21af9c6e215e9dca6fbead3e785  policy.py
41a87a02a6c642d9be2ab57bbe87c28fbd6a726dc10cdb8ca2a8e89b21dcb769  predict.py
3f5aeb9060a0cdda735eef3d9a15bd2761e8cdb436e404fda36c3d47bcad85e6  reports/99.9%达成方案_最终决策.md
b461b024c11dde82cb54f65bcf37d0b479a03856c26e555a3a4125bc4593a8da  reports/_bench_cmo_summary.md
bed7662131e4f1b9b0b8b8d32693c225df634ef4a732c54442ecdca473ae8a78  reports/_bench_cpu_routes_结论.md
9a727bc13d3ac04a0dce54501a73c29e97e1d34639bbd6036b5d32f42e6e7157  reports/per_class_report.txt
420cf02385a9bb67f946130527bd6a37973e4e2a1000fd9b3c554536c04bdaff  reports/不用外部大模型_可行性论证.md
8aa6b402c8a346b1cadcdc6f9c70e1da0d1477f3166f4f380474336709b9cd74  reports/全面检查报告_2026-10-07.md
32ad3d045ce1a98a0f20a447282ca549261f74133380113336e94f2e582deb6f  reports/反混淆调研与实现报告.md
fd6d93b4f1e82e8b360f916925634aae438f287160dc25fd9e0c906914f9f601  reports/多Agent评估与执行报告_第四轮.md
387eb06715add7d1096c286077fd865b0440c9214a6b7a473b9293fd44f83ea2  reports/多Agent过拟合与质量审计报告.md
6236f02342c8e2dec7a6360b1f4f13d1a70909de9c6f700d44f77e754b3bb505  reports/多agent评估与优化方向_第六轮.md
732adde07731bdc98b0326962b420b57ad10e40123505f6ab873329422cc27d1  reports/彻底复查报告.md
92c64cb79566005568407e739c76c6134250a0045ad14021f74689e703a61b74  reports/校准与基础风险_第五轮.md
165795e39c97d024c4e2d86062e9cf578a05027c50ae2cf0526e644c6de12e83  reports/核查报告.md
c596d9d35e3dd063d8d38cf1d04a8b4059bd71c2ebe63f4471c2f95fa941da62  reports/生产级优化执行报告.md
1772ad1dc9c433bba97f88bb0b5f6a4de7033d35dfbf23039a0f4034973f505e  reports/真实日志评估_最终结论.md
9ed242d61f572ce2e56589e1ec7b1b687ea6bd4f26bbe89816f98fca06f05b8e  reports/第三轮多Agent复审报告_2026-10-07.md
e980d24a7d120c8a42c8b5955875ac65effb530b94780a8e088f3248952649aa  reports/第二十轮对抗复核.md
7e26050c9d080b2a02d429d584bc1d9be632b2a35f69798558d2f52051a351bc  reports/第十七轮对抗复核.md
594e5433f48c126210697bbf74af125ba3ecdef05c55c6cc7d842b31844ccbc8  reports/第十三轮对抗复核.md
39cee19cf698290e29c97676b3d7f3b67a8a26efafd7099a69098ff5a3cdf30c  reports/第十九轮对抗复核.md
ff918a61a568377f6374ba47d83e20d6ecd65e01da99abe178d4a91d4504c9c1  reports/第十二轮对抗复核.md
13133cbb03c70dc678b40dac6790f0ec8077f3d2f1f3b1e037c0ba69be9048bd  reports/第十五轮对抗复核.md
358500ebe7c50c618b8aa6bd5ae6027a5fba913085a771067443c2986215d241  reports/第十八轮对抗复核.md
6a4ac0c97b7270b5899e94045958411970a9265acec60a098ca8acf249aad552  reports/第十六轮对抗复核.md
13069fc8f3f058a9a850eebc8d6d8cbce0e4fadf865a94f0ef7233f38dffe0fe  reports/第十四轮对抗复核.md
e6257afa275560f01dd260ba84bbbf21e9a5084e2aea478b4f4346a706dcda30  reports/红队对抗审查报告.md
5dda3a37343261408d6f25202cc265d36b2c7101eae39c420a2f40472269bf96  reports/输入现实性红队报告.md
1c60e90fae880514786b1c86b3f0aac5cb85ff2702b716a35d28f4816a7806cd  reports/部分混淆标识符识别实现报告.md
5c17d785abea579605f210a7c06b429a1d8afe3cae088f4fc1100ad89b8d978b  requirements.txt
94b1fff2746b5d40db3fb7e9b20bea2ae89c15bca11aaea43bde392ce2c185b2  rules_engine.py
3684dc39377f7cbda02489d632fc9b091cee92ca74b3dc23a1d98f98aae313bf  scope_audit.py
097e7033b2bfcced54f0f9f6f12f91cb08c3b7f42da98b974a05e10096c08c72  smoke_test.py
97ebd11f6fab9b42404e29240668ce1edaa1755814cc3d2fed799290df698615  train_dtype_guard_pure.py
f79dfddcf834df0f00e1b23d162c47235d5c34e98cc1897039a5a4aacb7639af  模型选型结论.md
9bc7772d38d266029d3923369f31de4e5d9236b1b1ec7983d7b36fadfbe18369  docs/hook_schema_contract.md
49a6bff39cfec230339e6b6ced325a60d9187c720872e180ba1b3471ca256442  tools/gh_search.py
3f5aeb9060a0cdda735eef3d9a15bd2761e8cdb436e404fda36c3d47bcad85e6  reports/99.9%达成方案_最终决策.md
420cf02385a9bb67f946130527bd6a37973e4e2a1000fd9b3c554536c04bdaff  reports/不用外部大模型_可行性论证.md
8aa6b402c8a346b1cadcdc6f9c70e1da0d1477f3166f4f380474336709b9cd74  reports/全面检查报告_2026-10-07.md
32ad3d045ce1a98a0f20a447282ca549261f74133380113336e94f2e582deb6f  reports/反混淆调研与实现报告.md
fd6d93b4f1e82e8b360f916925634aae438f287160dc25fd9e0c906914f9f601  reports/多Agent评估与执行报告_第四轮.md
387eb06715add7d1096c286077fd865b0440c9214a6b7a473b9293fd44f83ea2  reports/多Agent过拟合与质量审计报告.md
6236f02342c8e2dec7a6360b1f4f13d1a70909de9c6f700d44f77e754b3bb505  reports/多agent评估与优化方向_第六轮.md
732adde07731bdc98b0326962b420b57ad10e40123505f6ab873329422cc27d1  reports/彻底复查报告.md
92c64cb79566005568407e739c76c6134250a0045ad14021f74689e703a61b74  reports/校准与基础风险_第五轮.md
165795e39c97d024c4e2d86062e9cf578a05027c50ae2cf0526e644c6de12e83  reports/核查报告.md
c596d9d35e3dd063d8d38cf1d04a8b4059bd71c2ebe63f4471c2f95fa941da62  reports/生产级优化执行报告.md
1772ad1dc9c433bba97f88bb0b5f6a4de7033d35dfbf23039a0f4034973f505e  reports/真实日志评估_最终结论.md
9ed242d61f572ce2e56589e1ec7b1b687ea6bd4f26bbe89816f98fca06f05b8e  reports/第三轮多Agent复审报告_2026-10-07.md
e980d24a7d120c8a42c8b5955875ac65effb530b94780a8e088f3248952649aa  reports/第二十轮对抗复核.md
7e26050c9d080b2a02d429d584bc1d9be632b2a35f69798558d2f52051a351bc  reports/第十七轮对抗复核.md
594e5433f48c126210697bbf74af125ba3ecdef05c55c6cc7d842b31844ccbc8  reports/第十三轮对抗复核.md
39cee19cf698290e29c97676b3d7f3b67a8a26efafd7099a69098ff5a3cdf30c  reports/第十九轮对抗复核.md
ff918a61a568377f6374ba47d83e20d6ecd65e01da99abe178d4a91d4504c9c1  reports/第十二轮对抗复核.md
13133cbb03c70dc678b40dac6790f0ec8077f3d2f1f3b1e037c0ba69be9048bd  reports/第十五轮对抗复核.md
358500ebe7c50c618b8aa6bd5ae6027a5fba913085a771067443c2986215d241  reports/第十八轮对抗复核.md
6a4ac0c97b7270b5899e94045958411970a9265acec60a098ca8acf249aad552  reports/第十六轮对抗复核.md
13069fc8f3f058a9a850eebc8d6d8cbce0e4fadf865a94f0ef7233f38dffe0fe  reports/第十四轮对抗复核.md
e6257afa275560f01dd260ba84bbbf21e9a5084e2aea478b4f4346a706dcda30  reports/红队对抗审查报告.md
5dda3a37343261408d6f25202cc265d36b2c7101eae39c420a2f40472269bf96  reports/输入现实性红队报告.md
1c60e90fae880514786b1c86b3f0aac5cb85ff2702b716a35d28f4816a7806cd  reports/部分混淆标识符识别实现报告.md
29c5038482bbec737e08e4b9cc6b34a6d91fb7caa8027f02ca4ec5b5ce6d247f  models/l3_struct/deploy_gate.json
a0db2b632eb941cd3b54fbb169eb53b84397b7469ce0af8b304e5f42c38077b5  models/l3_struct/model.pkl
18991cadc9725cbfccb5adcdb3922c3e25e393531855902da59d606529b3290e  models/dtype_guard.pkl
2f4628a77768b354dfc850a6628065e19a1a07bb97523fffc59ed4eca2cf4178  models/dtype_guard_pure.pkl
b553b21a7e29bffcde964cc3d273715d99b189f68060923f0ba39330472dd1bf  models/calibration.candidate.json
85d991407f988eb678cb3335b10e51a44346d38334d4e56c58d4263f85d3e0f4  data/test_ood.jsonl
e6634d7b575999fbae3b01f072a0f03b7e490f70c70825f6d741bee9d591b7f1  data/stats.json
```
