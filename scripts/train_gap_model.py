# -*- coding: utf-8 -*-
"""标定位置级切分证据模型（逻辑回归）。

流程：
  1. 对每个标定样本，用 tshark 参考解析得到“一级字段”起始位置作为标签；
  2. 跑一遍 KFSI 的关键字段识别与递归分裂，在**叶子区域**逐位置采集证据特征；
  3. 用逻辑回归拟合“该位置是字段边界”的后验概率；
  4. 在留出样本上扫描决策阈值 θ，取 F1 最优；
  5. 导出 ``models/gap_model.json``。

标定样本与测试样本不重叠（不同抓包文件）；``--exclude`` 可指定协议名，
用于“留一协议”泛化实验。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from src.pcapio import ProtocolDataLoader
from src.reference import ReferenceIndex, Metrics
from src.pipeline import KFSIEngine
from src.inference import GapModel, FEATURE_NAMES
from run_eval import load_protocol, message_timestamps, BASE_CFG

logger = logging.getLogger('kfsi.train')


def build_blacklist(test_dir: Path) -> set:
    """评测集全部报文的字节哈希，用于标定语料去污染。"""
    loader = ProtocolDataLoader(BASE_CFG)
    out = set()
    for p in sorted(Path(test_dir).glob('*.pcap')):
        msgs, _, _, _ = load_protocol(p, loader)
        out.update(hashlib.md5(m).hexdigest() for m in msgs)
    return out


def collect_from(pcap: Path, ref: ReferenceIndex,
                 scope: str = 'V3_一级字段',
                 blacklist: set = frozenset()) -> Tuple[List[dict], List[float]]:
    loader = ProtocolDataLoader(BASE_CFG)
    msgs, _, dirs, frames = load_protocol(pcap, loader)
    if len(msgs) < 8:
        return [], []
    ts = message_timestamps(pcap, frames)
    frame_fields, payload_info = ref.load(str(pcap))
    gt: List[set] = []
    keep = []
    dropped = 0
    for i, m in enumerate(msgs):
        # 去污染：与评测集逐字节相同的报文不参与标定
        if blacklist and hashlib.md5(m).hexdigest() in blacklist:
            dropped += 1
            continue
        keep.append(i)
        fields = ReferenceIndex.fields_for_frames(
            frames[i] if i < len(frames) else [], frame_fields, payload_info, len(m))
        scoped = ReferenceIndex.scope_fields(fields, scope)
        gt.append(set(ReferenceIndex.positions(scoped, len(m))))
    if dropped:
        logger.info(f'{pcap.stem}: 去污染剔除 {dropped} 条与评测集重复的报文')
    if len(keep) < 8:
        return [], []

    engine = KFSIEngine()
    coll: List[Tuple[dict, float]] = []
    engine.analyze([msgs[i] for i in keep], timestamps=[ts[i] for i in keep],
                   directions=[dirs[i] for i in keep], gt=gt, collector=coll)
    X = [c[0] for c in coll]
    y = [c[1] for c in coll]
    return X, y


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--train', default=str(ROOT / 'data' / 'train_protocol'))
    ap.add_argument('--holdout', default=str(ROOT / 'data' / 'dev_protocol'),
                    help='开发集目录：仅用于扫描决策阈值 theta')
    ap.add_argument('--decontaminate', default=str(ROOT / 'data' / 'test_protocol'),
                    help='去污染参照目录：与其中报文逐字节相同的训练报文被剔除；'
                         '传空串可关闭')
    ap.add_argument('--exclude', default=None, help='排除的协议名（留一协议实验）')
    ap.add_argument('--out', default=str(ROOT / 'models' / 'gap_model.json'))
    ap.add_argument('--theta-grid', default='-1.0,-0.5,0.0,0.5,1.0,1.5,2.0,2.5,3.0,3.5,4.0')
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)s %(name)s: %(message)s')
    ref = ReferenceIndex()
    excl = {s.strip().lower() for s in args.exclude.split(',')} if args.exclude else set()

    files = sorted(Path(args.train).glob('*.pcap'))
    files = [f for f in files if f.stem.lower() not in excl]
    if not files:
        logger.error('没有标定样本')
        return

    blacklist = set()
    if args.decontaminate:
        blacklist = build_blacklist(Path(args.decontaminate))
        logger.info(f'去污染参照集：{len(blacklist)} 条评测报文的哈希')

    X, y = [], []
    for f in files:
        xs, ys = collect_from(f, ref, blacklist=blacklist)
        if not xs:
            continue
        X.extend(xs); y.extend(ys)
        logger.info(f'{f.stem}: {len(xs)} 个位置样本，正例率 '
                    f'{np.mean(ys):.2f}')

    if not X:
        logger.error('标定样本为空')
        return
    X = np.array([[x.get(k, 0.0) for k in FEATURE_NAMES] for x in X])
    y = np.array(y)
    pos = (y > 0.5).astype(int)
    logger.info(f'总样本 {len(y)}，正例率 {pos.mean():.3f}')

    from sklearn.linear_model import LogisticRegression
    clf = LogisticRegression(max_iter=2000, C=1.0, class_weight='balanced')
    clf.fit(X, pos)

    weights = {n: float(w) for n, w in zip(FEATURE_NAMES, clf.coef_[0])}
    bias = float(clf.intercept_[0])
    logger.info('权重: ' + ', '.join(f'{k}={v:+.2f}' for k, v in weights.items()))
    logger.info(f'bias={bias:+.2f}')

    # 阈值扫描：只在**开发集**上做，开发集既不参与拟合也不参与评测
    dev_files = (sorted(Path(args.holdout).glob('*.pcap'))
                 if args.holdout and Path(args.holdout).exists() else [])
    if not dev_files:
        logger.warning('未提供开发集，theta 取网格中位数')
        model = GapModel(weights=weights, bias=bias)
        model.theta = 0.0
    else:
        model = GapModel(weights=weights, bias=bias)
        grid = [float(v) for v in args.theta_grid.split(',')]
        best = None
        for theta in grid:
            model.theta = theta
            tp = fp = fn = 0
            for f in dev_files:
                p = _eval_file(f, model, ref)
                if p is None:
                    continue
                tp += p[0]; fp += p[1]; fn += p[2]
            m = Metrics.prf(tp, fp, fn)
            logger.info(f'theta={theta:+.2f}  P={m["precision"]:.3f} '
                        f'R={m["recall"]:.3f} F1={m["f1"]:.3f}')
            if best is None or m['f1'] > best[1]:
                best = (theta, m['f1'], m)
        model.theta = best[0]
        logger.info(f'开发集最佳 theta={best[0]:+.2f}  F1={best[1]:.3f}')

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    model.save(args.out)
    logger.info(f'模型已保存: {args.out}')


def _eval_file(pcap: Path, model: GapModel, ref: ReferenceIndex):
    loader = ProtocolDataLoader(BASE_CFG)
    msgs, _, dirs, frames = load_protocol(pcap, loader)
    if len(msgs) < 8:
        return None
    ts = message_timestamps(pcap, frames)
    engine = KFSIEngine(model=model)
    res = engine.analyze(msgs, timestamps=ts, directions=dirs)
    frame_fields, payload_info = ref.load(str(pcap))
    tp = fp = fn = 0
    for i, m in enumerate(msgs):
        fields = ReferenceIndex.fields_for_frames(
            frames[i] if i < len(frames) else [], frame_fields, payload_info, len(m))
        gt = ReferenceIndex.positions(
            ReferenceIndex.scope_fields(fields, 'V3_一级字段'), len(m))
        pred = [p for p in res.boundaries[i] if 0 < p < len(m)]
        a, b, c = Metrics.match_positions(pred, gt, tol=1)
        tp += a; fp += b; fn += c
    return tp, fp, fn


if __name__ == '__main__':
    main()
