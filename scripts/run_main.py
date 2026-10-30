# -*- coding: utf-8 -*-
"""主实验：在**与标定/开发集完全不相交**的评测集上评估 KFSI。

两种推断设定：
  batch    —— 每个协议的全部报文一次性送入引擎（批量推断，与同类工作一致）；
  isolated —— 仅把按时间顺序切出的后 30% 报文送入引擎（可用流量受限的设定）。

模型权重与决策阈值均来自 data/train_protocol 与 data/dev_protocol，
评测集 data/test_protocol 既不参与拟合也不参与阈值选择。

用法::

    python scripts/run_main.py                 # 两种设定都跑
    python scripts/run_main.py --setting batch
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.filterwarnings('ignore')

import numpy as np

from src.pcapio import ProtocolDataLoader
from src.reference import ReferenceIndex, Metrics
from src.pipeline import KFSIEngine
from src.inference import GapModel
from run_eval import load_protocol, message_timestamps, BASE_CFG

SCOPE = 'V3_一级字段'
PROTOS = ['bacnet', 'DCERPC', 'dnp3', 'hart_ip', 'IEC104', 'modbus', 'MQTT', 'S7comm']
TEST_DIR = ROOT / 'data' / 'test_protocol'


def load_all(pcap: Path) -> dict:
    loader = ProtocolDataLoader(BASE_CFG)
    msgs, _, dirs, frames = load_protocol(str(pcap), loader)
    ts = message_timestamps(str(pcap), frames)
    ref = ReferenceIndex()
    ff, pi = ref.load(str(pcap))
    gt = []
    for i, m in enumerate(msgs):
        fields = ReferenceIndex.fields_for_frames(
            frames[i] if i < len(frames) else [], ff, pi, len(m))
        scoped = ReferenceIndex.scope_fields(fields, SCOPE)
        gt.append(set(ReferenceIndex.positions(scoped, len(m))))
    return {'msgs': msgs, 'ts': ts, 'dirs': dirs, 'gt': gt}


def split_idx(dirs, r=(0.5, 0.2, 0.3)):
    """按会话分组，组内按时间顺序切分；过短会话整体归入前段。"""
    by = defaultdict(list)
    for i, d in enumerate(dirs):
        by[d].append(i)
    tr, dv, te = [], [], []
    for _, idx in sorted(by.items()):
        n = len(idx)
        if n < 3:
            tr += idx
            continue
        a = max(1, int(n * r[0]))
        b = min(max(a + 1, int(n * (r[0] + r[1]))), n - 1)
        tr += idx[:a]; dv += idx[a:b]; te += idx[b:]
    return sorted(tr), sorted(dv), sorted(te)


def _slice(d, idxs):
    return ([d['msgs'][i] for i in idxs], [d['ts'][i] for i in idxs],
            [d['dirs'][i] for i in idxs], [d['gt'][i] for i in idxs])


def evaluate(d, idxs, model):
    ms, ts, dd, _ = _slice(d, idxs)
    if not ms:
        return 0, 0, 0
    res = KFSIEngine(model=model).analyze(ms, timestamps=ts, directions=dd)
    tp = fp = fn = 0
    for k, i in enumerate(idxs):
        m = ms[k]
        pred = [q for q in res.boundaries[k] if 0 < q < len(m)]
        a, b, c = Metrics.match_positions(pred, d['gt'][i], tol=1)
        tp += a; fp += b; fn += c
    return tp, fp, fn


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return round(p, 4), round(r, 4), round(f, 4)


def iou_counts(d, idxs, model):
    """区间口径（IoU>=0.5 一一配对）的 tp/fp/fn。"""
    ms, ts, dd, gt = _slice(d, idxs)
    if not ms:
        return 0, 0, 0
    res = KFSIEngine(model=model).analyze(ms, timestamps=ts, directions=dd)
    tp = fp = fn = 0
    for k, m in enumerate(ms):
        L = len(m)
        cuts = [0] + sorted({q for q in res.boundaries[k] if 0 < q < L}) + [L]
        pred = [(cuts[j], cuts[j + 1]) for j in range(len(cuts) - 1)]
        ref_ = [0] + sorted({q for q in gt[k] if 0 < q < L}) + [L]
        ref = [(ref_[j], ref_[j + 1]) for j in range(len(ref_) - 1)]
        a, b, c = Metrics.match_intervals_iou(pred, ref, 0.5)
        tp += a; fp += b; fn += c
    return tp, fp, fn


def report(data, idxs_map, model, name, with_iou=True):
    rows, tp, fp, fn = [], 0, 0, 0
    itp = ifp = ifn = 0
    for p in PROTOS:
        a, b, c = evaluate(data[p], idxs_map[p], model)
        tp += a; fp += b; fn += c
        P, R, F = prf(a, b, c)
        if with_iou:
            ia, ib, ic = iou_counts(data[p], idxs_map[p], model)
        else:
            ia = ib = ic = 0
        itp += ia; ifp += ib; ifn += ic
        rows.append({'protocol': p, 'n': len(idxs_map[p]), 'tp': a,
                     'fp': b, 'fn': c, 'P': P, 'R': R, 'F1': F,
                     'iou': prf(ia, ib, ic) if with_iou else None})
    P, R, F = prf(tp, fp, fn)
    macro = round(float(np.mean([r['F1'] for r in rows])), 4)
    print(f'\n=== {name} ===  micro P={P} R={R} F1={F}  macroF1={macro}'
          + (f'  IoU-F1={prf(itp, ifp, ifn)[2]:.4f}' if with_iou else ''))
    for r in rows:
        s = (f"   {r['protocol']:<9} n={r['n']:>4} tp={r['tp']:>5} "
             f"fp={r['fp']:>5} fn={r['fn']:>5} F1={r['F1']:.4f}")
        if with_iou:
            s += f"  IoU={r['iou'][2]:.4f}"
        print(s)
    return {'name': name, 'theta': model.theta, 'micro_P': P, 'micro_R': R,
            'micro_F1': F, 'macro_F1': macro,
            'iou_micro_P': prf(itp, ifp, ifn)[0] if with_iou else None,
            'iou_micro_R': prf(itp, ifp, ifn)[1] if with_iou else None,
            'iou_micro_F1': prf(itp, ifp, ifn)[2] if with_iou else None,
            'tp': tp, 'fp': fp, 'fn': fn, 'rows': rows}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--setting', default='both',
                    choices=['batch', 'isolated', 'both'])
    ap.add_argument('--model', default=str(ROOT / 'models' / 'gap_model.json'))
    ap.add_argument('--out', default=str(ROOT / 'outputs' / 'main.json'))
    args = ap.parse_args()

    model = GapModel.load(args.model)
    print(f'模型 {args.model}  theta={model.theta:+.2f}', flush=True)

    data = {}
    for p in PROTOS:
        f = TEST_DIR / f'{p}.pcap'
        data[p] = load_all(f)
        print(f'  {p:<9} msgs={len(data[p]["msgs"])}', flush=True)

    splits = {p: split_idx(data[p]['dirs']) for p in PROTOS}
    out = {'model': args.model, 'theta': model.theta}

    if args.setting in ('batch', 'both'):
        allidx = {p: list(range(len(data[p]['msgs']))) for p in PROTOS}
        out['batch'] = report(data, allidx, model, '批量推断（全部报文为上下文）')

    if args.setting in ('isolated', 'both'):
        te = {p: splits[p][2] for p in PROTOS}
        out['isolated'] = report(data, te, model, '隔离设定（仅引入后 30% 报文）')

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    json.dump(out, open(args.out, 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    print(f'\n写入 {args.out}')


if __name__ == '__main__':
    main()
