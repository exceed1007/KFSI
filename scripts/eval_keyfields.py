# -*- coding: utf-8 -*-
"""关键字段（长度字段 LF / 结构标识字段 SIF）识别效果评测。

位置口径：把“检出的关键字段起点”与该协议参考解析中所有同类字段的起点
做容差匹配，统计 P/R/F1。分别在 V3（一级字段）与 V1（全部字段，含嵌套）
两种参考粒度下统计——前者对应“报文顶层是否有一个长度/类型字段”，后者
对应“协议里任何一层是否存在这样的字段”。

用法::

    python scripts/eval_keyfields.py --out outputs/keyfields.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from run_eval import load_protocol, message_timestamps, BASE_CFG  # noqa: E402
from src.pcapio import ProtocolDataLoader  # noqa: E402
from src.pipeline import KFSIEngine  # noqa: E402
from src.reference import ReferenceIndex, Metrics  # noqa: E402
from src.inference import GapModel  # noqa: E402


def _prf(pred, gt, tol=1):
    if not pred and not gt:
        return {'precision': 1.0, 'recall': 1.0, 'f1': 1.0,
                'tp': 0, 'fp': 0, 'fn': 0}
    tp, fp, fn = Metrics.match_positions(sorted(pred), sorted(gt), tol=tol)
    m = Metrics.prf(tp, fp, fn)
    m['tp'], m['fp'], m['fn'] = tp, fp, fn
    return m


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', default=str(ROOT / 'data' / 'test_protocol'))
    ap.add_argument('--tol', type=int, default=1)
    ap.add_argument('--only', default=None)
    ap.add_argument('--out', default=str(ROOT / 'outputs' / 'keyfields.json'))
    ap.add_argument('--model', default=str(ROOT / 'models' / 'gap_model.json'))
    args = ap.parse_args(argv)

    loader = ProtocolDataLoader(BASE_CFG)
    ref = ReferenceIndex()
    eng = KFSIEngine(model=GapModel.load(args.model))
    files = sorted(Path(args.data).glob('*.pcap'))
    if args.only:
        keep = {s.strip().lower() for s in args.only.split(',')}
        files = [f for f in files if f.stem.lower() in keep]

    rows = []
    for f in files:
        msgs, _, dirs, frames = load_protocol(f, loader)
        if not msgs:
            continue
        res = eng.analyze(msgs, timestamps=message_timestamps(f, frames),
                          directions=dirs)
        ff, pi = ref.load(str(f))
        gt = {'V3_一级字段': {'len': set(), 'type': set()},
              'V1_全部字段': {'len': set(), 'type': set()}}
        for i, m in enumerate(msgs):
            fields = ReferenceIndex.fields_for_frames(
                frames[i] if i < len(frames) else [], ff, pi, len(m))
            for s in gt:
                sc = ReferenceIndex.scope_fields(fields, s)
                for x in ReferenceIndex.length_fields(sc):
                    gt[s]['len'].add(x['start'])
                for x in ReferenceIndex.structure_fields(sc):
                    gt[s]['type'].add(x['start'])
        row = {'protocol': f.stem, 'messages': len(msgs)}
        for label, key in (('len', 'length'), ('type', 'type')):
            pred = {k.start for k in res.key_fields if k.label == key}
            row[f'{label}_n_pred'] = len(pred)
            for s in gt:
                m = _prf(pred, gt[s][label], tol=args.tol)
                tag = 'v1' if s.startswith('V1') else 'v3'
                for k in ('precision', 'recall', 'f1'):
                    row[f'{label}_{tag}_{k[0]}'] = round(m[k], 4)
                row[f'{label}_{tag}_gt'] = len(gt[s][label])
        rows.append(row)
        print(f"{f.stem:<9} lenF1(v3)={row['len_v3_f']:.3f} "
              f"lenF1(v1)={row['len_v1_f']:.3f} "
              f"typeF1(v3)={row['type_v3_f']:.3f} "
              f"typeF1(v1)={row['type_v1_f']:.3f}")

    print('\n==== 宏平均 ====')
    for k in ('len_v3', 'len_v1', 'type_v3', 'type_v1'):
        print(f'  {k}_F1 = {np.mean([r[k + "_f"] for r in rows]):.4f}')
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    json.dump(rows, open(args.out, 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    return rows


if __name__ == '__main__':
    main()
