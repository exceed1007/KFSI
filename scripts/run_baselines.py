# -*- coding: utf-8 -*-
"""在统一口径下评测基线方法。

用法::

    python scripts/run_baselines.py --method nemesys --data data/test_protocol
    python scripts/run_baselines.py --calibrate      # 在标定集上选阈值
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from src.pcapio import ProtocolDataLoader
from src.reference import ReferenceIndex, Metrics
from src.baselines import BASELINES
from run_eval import load_protocol, BASE_CFG

logger = logging.getLogger('kfsi.base')


def _gt_for(pcap: Path, msgs, frames, ref: ReferenceIndex) -> List[List[int]]:
    ff, pi = ref.load(str(pcap))
    out = []
    for i, m in enumerate(msgs):
        fields = ReferenceIndex.fields_for_frames(
            frames[i] if i < len(frames) else [], ff, pi, len(m))
        out.append(ReferenceIndex.positions(
            ReferenceIndex.scope_fields(fields, 'V3_一级字段'), len(m)))
    return out


def eval_dir(files, method: str, ref: ReferenceIndex, tol: int = 1,
             **kw) -> Dict:
    fn = BASELINES[method]
    tp = fp = nn = 0
    rows = []
    for p in files:
        msgs, _, dirs, frames = load_protocol(p, ProtocolDataLoader(BASE_CFG))
        if len(msgs) < 8:
            continue
        pred = fn(msgs, **kw)
        gt = _gt_for(p, msgs, frames, ref)
        a = b = c = 0
        for i, m in enumerate(msgs):
            x, y, z = Metrics.match_positions(
                [q for q in pred[i] if 0 < q < len(m)], gt[i], tol=tol)
            a += x; b += y; c += z
        tp += a; fp += b; nn += c
        m = Metrics.prf(a, b, c)
        rows.append({'protocol': p.stem, 'messages': len(msgs),
                     'P': round(m['precision'], 4), 'R': round(m['recall'], 4),
                     'F1': round(m['f1'], 4)})
    micro = Metrics.prf(tp, fp, nn)
    return {'method': method, 'micro_P': micro['precision'],
            'micro_R': micro['recall'], 'micro_F1': micro['f1'],
            'macro_F1': float(np.mean([r['F1'] for r in rows])) if rows else 0.0,
            'rows': rows}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--method', default='all')
    ap.add_argument('--data', default=str(ROOT / 'data' / 'test_protocol'))
    ap.add_argument('--calib', default=str(ROOT / 'data' / 'train_protocol'))
    ap.add_argument('--out', default=str(ROOT / 'outputs' / 'baselines'))
    ap.add_argument('--calibrate', action='store_true')
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)s %(name)s: %(message)s')

    ref = ReferenceIndex()
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    methods = list(BASELINES) if args.method == 'all' else args.method.split(',')

    grids = {
        'binaryinferno': [{'thr': t} for t in (0.05, 0.15, 0.25, 0.35, 0.45, 0.6)],
        'pft': [{'merge_mi': m} for m in (0.40, 0.55, 0.70, 0.80, 0.90, 0.95)],
        'reinpro': [{'min_gain': g, 'det_jump': d, 'ent_jump': e}
                    for g in (0.04, 0.08, 0.15, 0.25)
                    for d in (0.25, 0.45) for e in (0.25, 0.45)],
    }

    test_files = sorted(Path(args.data).glob('*.pcap'))
    calib_files = sorted(Path(args.calib).glob('*.pcap'))
    results = {}
    for m in methods:
        kw = {}
        if args.calibrate:
            best = None
            for cand in grids[m]:
                r = eval_dir(calib_files, m, ref, **cand)
                logger.info(f'{m} {cand} -> calib F1={r["micro_F1"]:.3f}')
                if best is None or r['micro_F1'] > best[1]:
                    best = (cand, r['micro_F1'])
            kw = best[0]
        r = eval_dir(test_files, m, ref, **kw)
        results[m] = {**r, 'params': kw}
        logger.info(f'{m}: P={r["micro_P"]:.3f} R={r["micro_R"]:.3f} '
                    f'F1={r["micro_F1"]:.3f} params={kw}')

    with open(out / 'baselines.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=1)
    rows = []
    for m, r in results.items():
        for row in r['rows']:
            row['method'] = m
            rows.append(row)
    if rows:
        with open(out / 'baselines.csv', 'w', newline='',
                  encoding='utf-8-sig') as f:
            w = csv.DictWriter(f, fieldnames=['method', 'protocol', 'messages',
                                              'P', 'R', 'F1'])
            w.writeheader(); w.writerows(rows)


if __name__ == '__main__':
    main()
