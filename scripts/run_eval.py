# -*- coding: utf-8 -*-
"""统一实验入口：加载样本 → KFSI 分析 → 与 tshark 参考解析比对。

用法::

    python scripts/run_eval.py --data data/test_protocol --out outputs/eval
    python scripts/run_eval.py --method kfsi --tol 1
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.pcapio import ProtocolDataLoader
from src.reference import (ReferenceIndex, Metrics, DEFAULT_LENGTH_PATTERN,
                           DEFAULT_STRUCTURE_PATTERN)
from src.pipeline import KFSIEngine
from src.inference import GapModel

logger = logging.getLogger('kfsi.eval')

BASE_CFG = {'feature': {'ascii_threshold': 0.4},
            'data': {'output_dir': './outputs'},
            'evaluation': {'output_dir': './outputs/evaluation'}}


# ----------------------------------------------------------------------
# 样本加载
# ----------------------------------------------------------------------
def load_protocol(pcap: str, loader: ProtocolDataLoader):
    """返回 (msgs, timestamps, directions, frame_lists)。"""
    df = loader.load_pcap(str(pcap))
    if df is None or len(df) == 0:
        return [], [], [], []
    sessions = loader.extract_sessions(df)
    sessions = loader.filter_binary_protocols(sessions)
    msgs, ts, dirs, frames, sess_ids = [], [], [], [], []
    for si, s in enumerate(sessions):
        ms = [m for m in s.get_messages() if m and len(m) >= 4]
        if not ms:
            continue
        # 每条消息的帧号：TCP 会话沿用 PSH 重组映射；UDP 一包一消息
        if getattr(s, 'reassembled', False):
            from src.reference_base import FieldSplitEvaluator
            ev = FieldSplitEvaluator(BASE_CFG, loader)
            fmap = ev._map_messages_to_frames(ms, s.packets)
        else:
            fmap = [[p.get('frame_number')] for p in s.packets if p.get('payload')]
        for k, m in enumerate(ms):
            msgs.append(m)
            dirs.append(si)                 # 会话号兼作“方向组”分组键
            ts.append(float(s.packets[0].get('timestamp', 0)) if s.packets else 0.0)
            frames.append(fmap[k] if k < len(fmap) else [])
    return msgs, ts, dirs, frames


def message_timestamps(pcap: str, frames: List[List[int]]) -> List[float]:
    """按帧号取时间戳（用于时间戳字段检测）。"""
    try:
        from scapy.all import rdpcap
        pkts = rdpcap(str(pcap))
    except Exception:
        return [0.0] * len(frames)
    out = []
    for fl in frames:
        t = 0.0
        if fl:
            f0 = fl[0]
            if f0 and 0 < f0 <= len(pkts):
                t = float(pkts[f0 - 1].time)
        out.append(t)
    return out


# ----------------------------------------------------------------------
# 评价
# ----------------------------------------------------------------------
def evaluate_protocol(pcap: Path, engine: KFSIEngine, ref: ReferenceIndex,
                      scope: str = 'V3_一级字段', tol: int = 1) -> dict:
    loader = ProtocolDataLoader(BASE_CFG)
    msgs, _, dirs, frames = load_protocol(pcap, loader)
    if not msgs:
        return {}
    ts = message_timestamps(pcap, frames)

    t0 = time.time()
    res = engine.analyze(msgs, timestamps=ts, directions=dirs)
    elapsed = time.time() - t0

    frame_fields, payload_info = ref.load(str(pcap))

    tp = fp = fn = 0
    itp = ifp = ifn = 0
    gt_len_pos, gt_type_pos = set(), set()
    for i, m in enumerate(msgs):
        fields = ReferenceIndex.fields_for_frames(
            frames[i] if i < len(frames) else [], frame_fields, payload_info, len(m))
        scoped = ReferenceIndex.scope_fields(fields, scope)
        gt = ReferenceIndex.positions(scoped, len(m))
        pred = [p for p in res.boundaries[i] if 0 < p < len(m)]
        a, b, c = Metrics.match_positions(pred, gt, tol=tol)
        tp += a; fp += b; fn += c

        # 区间口径
        pred_iv = [(0, 0)]
        cuts = [0] + sorted(set(pred)) + [len(m)]
        pred_iv = [(cuts[k], cuts[k + 1]) for k in range(len(cuts) - 1)]
        gt_iv = sorted({(f['start'], min(f['end'], len(m))) for f in scoped
                        if f['start'] < len(m)})
        a2, b2, c2 = Metrics.match_intervals_iou(pred_iv, gt_iv, 0.5)
        itp += a2; ifp += b2; ifn += c2

        for f in ReferenceIndex.length_fields(scoped):
            gt_len_pos.add(f['start'])
        for f in ReferenceIndex.structure_fields(scoped):
            gt_type_pos.add(f['start'])

    pm = Metrics.prf(tp, fp, fn)
    im = Metrics.prf(itp, ifp, ifn)

    # 关键字段识别（位置口径）
    pred_len = {f.start for f in res.key_fields if f.label == 'length'}
    pred_type = {f.start for f in res.key_fields if f.label == 'type'}
    lm = _pos_prf(pred_len, gt_len_pos, tol)
    tm = _pos_prf(pred_type, gt_type_pos, tol)

    return {
        'protocol': pcap.stem,
        'messages': len(msgs),
        'gt_boundaries': int(tp + fn),
        'pred_boundaries': int(tp + fp),
        'P': round(pm['precision'], 4), 'R': round(pm['recall'], 4),
        'F1': round(pm['f1'], 4),
        'iou_P': round(im['precision'], 4), 'iou_R': round(im['recall'], 4),
        'iou_F1': round(im['f1'], 4),
        'len_P': round(lm['precision'], 4), 'len_R': round(lm['recall'], 4),
        'len_F1': round(lm['f1'], 4),
        'type_P': round(tm['precision'], 4), 'type_R': round(tm['recall'], 4),
        'type_F1': round(tm['f1'], 4),
        'seconds': round(elapsed, 2),
        'tp': tp, 'fp': fp, 'fn': fn,
        'itp': itp, 'ifp': ifp, 'ifn': ifn,
    }


def _pos_prf(pred: set, gt: set, tol: int) -> dict:
    pred = sorted(pred); gt = sorted(gt)
    if not pred and not gt:
        return {'precision': 1.0, 'recall': 1.0, 'f1': 1.0}
    tp, fp, fn = Metrics.match_positions(pred, gt, tol=tol)
    return Metrics.prf(tp, fp, fn)


# ----------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', default=str(ROOT / 'data' / 'test_protocol'))
    ap.add_argument('--out', default=str(ROOT / 'outputs' / 'eval'))
    ap.add_argument('--model', default=None, help='GapModel 权重文件')
    ap.add_argument('--tol', type=int, default=1)
    ap.add_argument('--scope', default='V3_一级字段')
    ap.add_argument('--only', default=None, help='只跑指定协议（逗号分隔）')
    ap.add_argument('--theta', type=float, default=None,
                    help='决策阈值 θ（覆盖模型内的取值）')
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)s %(name)s: %(message)s')
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)

    model = GapModel.load(args.model) if args.model else GapModel()
    if args.theta is not None:
        model.theta = args.theta
    engine = KFSIEngine(model=model)
    ref = ReferenceIndex()

    files = sorted(Path(args.data).glob('*.pcap'))
    if args.only:
        keep = {s.strip().lower() for s in args.only.split(',')}
        files = [f for f in files if f.stem.lower() in keep]

    rows = []
    for f in files:
        r = evaluate_protocol(f, engine, ref, scope=args.scope, tol=args.tol)
        if r:
            rows.append(r)
            logger.info(f"{r['protocol']:<10} msgs={r['messages']:>4} "
                        f"P={r['P']:.3f} R={r['R']:.3f} F1={r['F1']:.3f} "
                        f"| iouF1={r['iou_F1']:.3f} "
                        f"| lenF1={r['len_F1']:.3f} typeF1={r['type_F1']:.3f}")

    if not rows:
        logger.error('没有可用样本')
        return

    tp = sum(r['tp'] for r in rows); fp = sum(r['fp'] for r in rows)
    fn = sum(r['fn'] for r in rows)
    itp = sum(r['itp'] for r in rows); ifp = sum(r['ifp'] for r in rows)
    ifn = sum(r['ifn'] for r in rows)
    micro = Metrics.prf(tp, fp, fn)
    micro_iou = Metrics.prf(itp, ifp, ifn)
    macro_f1 = float(np.mean([r['F1'] for r in rows]))

    summary = {
        'protocols': len(rows),
        'messages': sum(r['messages'] for r in rows),
        'micro_P': round(micro['precision'], 4),
        'micro_R': round(micro['recall'], 4),
        'micro_F1': round(micro['f1'], 4),
        'macro_F1': round(macro_f1, 4),
        'iou_micro_P': round(micro_iou['precision'], 4),
        'iou_micro_R': round(micro_iou['recall'], 4),
        'iou_micro_F1': round(micro_iou['f1'], 4),
        'len_F1': round(float(np.mean([r['len_F1'] for r in rows])), 4),
        'type_F1': round(float(np.mean([r['type_F1'] for r in rows])), 4),
        'seconds': round(sum(r['seconds'] for r in rows), 1),
    }
    print('\n==== Summary ====')
    for k, v in summary.items():
        print(f'  {k}: {v}')

    with open(out / 'results.json', 'w', encoding='utf-8') as fh:
        json.dump({'summary': summary, 'rows': rows}, fh,
                  ensure_ascii=False, indent=1)
    with open(out / 'results.csv', 'w', newline='', encoding='utf-8-sig') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    return summary


if __name__ == '__main__':
    main()
