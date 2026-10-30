# KFSI — 关键字段识别与辅助的二进制协议字段边界推断

代码与数据：*Field Boundary Inference for Binary Protocol Security Analysis:
Key-Field Identification and Recursive Splitting*（投稿 *Computers & Security*）。

KFSI（Key-Field-assisted Splitting and Inference）在不依赖协议规范、不依赖标注
数据的条件下，从真实流量中恢复二进制协议的字段边界。其核心思路是**“先分裂、
后推断”**：先识别两类关键字段——结构标识字段（SIF）与长度字段（LF），用它们
把异构报文集合递归分裂为结构同质、偏移一致的子区域，再在子区域上做细粒度
边界推断；边界结论由位置级证据与最大后验（MAP）解码联合给出。

---

## 1. 目录结构

```
KFSI/
├── src/                     方法实现
│   ├── pipeline.py          KFSI 主引擎（分裂 + 证据 + 解码）
│   ├── keyfields.py         结构标识字段、长度字段判据
│   ├── semantics.py         可直接验证的语义锚点（CRC/序号/时间戳）
│   ├── features.py          18 维位置级证据特征
│   ├── inference.py         证据融合与 MAP 解码
│   ├── baselines.py         BinaryInferno / REInPro / PFT 的复现实现
│   ├── reference.py         tshark PDML 参考解析与匹配口径
│   └── pcapio.py            pcap 读取
├── scripts/
│   ├── train_gap_model.py   标定语料拟合 + 去污染 + 阈值扫描
│   ├── run_main.py          主实验（批量推断 / 完全隔离两种设定）
│   ├── run_baselines.py     三种基线（独立标定集选参）
│   ├── ablation.py          消融实验
│   ├── eval_keyfields.py    关键字段识别效果
│   ├── run_scopes.py        四种参考粒度（V1–V4）
│   ├── sensitivity.py       参数敏感性
│   ├── make_figures.py      生成图 1–6
│   └── build_paper.py       生成论文 Word 文档（全部数字读 outputs/）
├── data/
│   ├── train_protocol/      标定语料（9 个公开抓包）
│   ├── dev_protocol/        开发语料（5 个公开抓包，仅用于选阈值）
│   ├── test_protocol/       评测集（8 个抓包）
│   └── splits/manifest.json 划分清单（文件名、协议、来源、MD5、字节数、报文数）
├── models/gap_model.json    标定所得模型（18 维权重 + 阈值）
├── outputs/                 全部实验结果（JSON）与插图（PNG）
└── config/                  预设配置
```

## 2. 环境

```bash
pip install -r requirements.txt
```

参考解析需要 `tshark`（Wireshark）在 PATH 中可用；`scikit-learn` 仅用于权重
拟合，缺失时脚本自动降级为先验权重（“免训练”配置）。

## 3. 一键复现

```bash
# 1) 标定：去污染后拟合权重，在开发集上扫描决策阈值
python scripts/train_gap_model.py --train data/train_protocol \
        --holdout data/dev_protocol --decontaminate data/test_protocol \
        --out models/gap_model.json

# 2) 主实验：批量推断 + 完全隔离两种设定
python scripts/run_main.py --setting both --model models/gap_model.json \
        --out outputs/main.json

# 3) 基线（超参在独立标定集上选取）
python scripts/run_baselines.py --calibrate --out outputs/baselines/baselines.json

# 4) 消融、关键字段、参考粒度、敏感性
python scripts/ablation.py      --model models/gap_model.json --out outputs/ablation.json
python scripts/eval_keyfields.py --model models/gap_model.json --out outputs/keyfields.json
python scripts/run_scopes.py    --model models/gap_model.json --out outputs/scopes_global.json
python scripts/sensitivity.py   --model models/gap_model.json --out outputs/sensitivity.json

# 5) 插图与论文
python scripts/make_figures.py --out outputs/fig
python scripts/build_paper.py  --out 论文.docx
```

`build_paper.py` 直接读取 `outputs/` 下的 JSON，因此论文中的每个数字都与上述
脚本的输出一致；不依赖任何手工录入的结果。

## 4. 数据划分与去污染

标定、开发、评测三部分**在文件级与报文级都不重叠**：

| 部分 | 抓包数 | 报文数 | 用途 |
|---|---|---|---|
| `train_protocol`（标定） | 9 | 2268 | 拟合 18 维权重 |
| `dev_protocol`（开发） | 5 | 344 | 扫描决策阈值 θ |
| `test_protocol`（评测） | 8 | 1110 | 报告全部结果 |

公开抓包与评测集可能存在报文级重复，因此 `train_gap_model.py` 在标定前执行
**报文级去污染**：以评测集全部报文的字节哈希为黑名单，逐一剔除（本数据集实际
剔除 IEC 104 的 11 条、MQTT 的 4 条）。HART-IP 的公开抓包与评测集同源度过高，
已整体排除在标定与开发集之外，故其成绩为**零样本**结果。

关闭去污染：`--decontaminate ""`。

## 5. 主要结果（V3 一级字段，位置容差 ±1 字节）

| 方法 | 精度 | 召回 | F1 | 宏平均 F1 | 区间 IoU-F1 |
|---|---|---|---|---|---|
| KFSI（批量推断） | 0.8252 | 0.6938 | **0.7539** | 0.7669 | 0.7180 |
| KFSI（隔离设定） | 0.5777 | 0.6821 | 0.6256 | 0.6584 | 0.5508 |
| REInPro | 0.4722 | 0.4926 | 0.4822 | 0.5999 | — |
| PFT | 0.3893 | 0.6373 | 0.4833 | 0.5454 | — |
| BinaryInferno | 0.2981 | 0.7871 | 0.4324 | 0.5997 | — |

“隔离设定”指引擎只能看到每个协议后 30% 的报文。基线另给出“评测集最优上界”
0.4915 / 0.5177 / 0.5113，KFSI 仍领先 45.7%。逐协议 F1 见 `outputs/main.json`。

## 6. 引用

```bibtex
@article{kfsi2026,
  title   = {Field Boundary Inference for Binary Protocol Security Analysis:
             Key-Field Identification and Recursive Splitting},
  author  = {<作者>},
  journal = {Computers \& Security},
  year    = {2026}
}
```

## 7. 许可

MIT（见 `LICENSE`）。抓包数据来自 Wireshark 等公开样本库，其来源与 MD5 记录于
`data/splits/manifest.json`。
