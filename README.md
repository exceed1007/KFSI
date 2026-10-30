# KFSI — 关键字段识别与辅助的二进制协议字段边界推断

仓库地址：<https://github.com/exceed1007/KFSI>

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
│   └── make_figures.py      生成图 1–6
├── data/
│   └── test_protocol/       评测集（8 个抓包）
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

## 3. 运行说明

```bash
# 1) 主实验：批量推断 + 完全隔离两种设定
python scripts/run_main.py --setting both --model models/gap_model.json \
        --out outputs/main.json

# 2) 基线（超参在独立标定集上选取）
python scripts/run_baselines.py --calibrate --out outputs/baselines/baselines.json

# 3) 消融、关键字段、参考粒度、敏感性
python scripts/ablation.py      --model models/gap_model.json --out outputs/ablation.json
python scripts/eval_keyfields.py --model models/gap_model.json --out outputs/keyfields.json
python scripts/run_scopes.py    --model models/gap_model.json --out outputs/scopes_global.json
python scripts/sensitivity.py   --model models/gap_model.json --out outputs/sensitivity.json
```

## 4. 主要结果（V3 一级字段，位置容差 ±1 字节）

| 方法 | 精度 | 召回 | F1 | 宏平均 F1 | 区间 IoU-F1 |
|---|---|---|---|---|---|
| KFSI（批量推断） | 0.8252 | 0.6938 | **0.7539** | 0.7669 | 0.7180 |
| KFSI（隔离设定） | 0.5777 | 0.6821 | 0.6256 | 0.6584 | 0.5508 |
| REInPro | 0.4722 | 0.4926 | 0.4822 | 0.5999 | — |
| PFT | 0.3893 | 0.6373 | 0.4833 | 0.5454 | — |
| BinaryInferno | 0.2981 | 0.7871 | 0.4324 | 0.5997 | — |
