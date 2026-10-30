# -*- coding: utf-8 -*-
"""决策阈值 θ 与宽度先验的敏感性扫描。

一次加载样本与参考解析（tshark 最耗时），随后在网格上重算指标，
避免重复解析 pcap。

用法::

    python scripts/sweep_theta.py --data data/test_protocol --grid 0,0.5,1,1.5,2
    python scripts/sweep_theta.py --data data/train_protocol --grid 0,1,2
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


def prepare(data_dir: Path, scope='V3_一级字段', only=None):
    loader = ProtocolDataLoader(BASE_CFG)
    ref = ReferenceIndex()
    items = []
    files = sorted(data_dir.glob('*.pcap'))
    if only:
        keep = {s.strip().lower() for s in only.split(',')}
        files = [f for f in files if f.stem.lower() in keep]
    for f in files:
        msgs, _, dirs, frames = load_protocol(f, loader)
        if not msgs:
            continue
        ts = message_timestamps(f, frames)
        ff, pi = ref.load(str(f))
        gts = []
        for i, m in enumerate(msgs):
            fields = ReferenceIndex.fields_for_frames(
                frames[i] if i < len(frames) else [], ff, pi, len(m))
            scoped = ReferenceIndex.scope_fields(fields, scope)
            gts.append(ReferenceIndex.positions(scoped, len(m)))
        items.append({'name': f.stem, 'msgs': msgs, 'ts': ts,
                      'dirs': dirs, 'gt': gts})
        print(f'  prepared {f.stem}: {len(msgs)} msgs')
    return items


def score(items, engine, tol=1, key='gt'):
    tp = fp = fn = 0
    per = []
    for it in items:
        res = engine.analyze(it['msgs'], timestamps=it['ts'],
                             directions=it['dirs'])
        a = b = c = 0
        for i, m in enumerate(it['msgs']):
            pred = [p for p in res.boundaries[i] if 0 < p < len(m)]
            x, y, z = Metrics.match_positions(pred, it[key][i], tol=tol)
            a += x; b += y; c += z
        tp += a; fp += b; fn += c
        per.append((it['name'], a, b, c))
    m = Metrics.prf(tp, fp, fn)
    m['macro_F1'] = float(np.mean([
        Metrics.prf(a, b, c)['f1'] for _, a, b, c in per]))
    return m, per


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', default=str(ROOT / 'data' / 'test_protocol'))
    ap.add_argument('--grid', default='0,0.5,1.0,1.5,2.0,2.5,3.0')
    ap.add_argument('--tol', type=int, default=1)
    ap.add_argument('--only', default=None)
    ap.add_argument('--out', default=None)
    args = ap.parse_args(argv)

    items = prepare(Path(args.data), only=args.only)
    if not items:
        print('no samples'); return

    rows = []
    for th in [float(s) for s in args.grid.split(',') if s.strip()]:
        model = GapModel()
        model.theta = th
        eng = KFSIEngine(model=model)
        m, _ = score(items, eng, tol=args.tol)
        rows.append({'theta': th, **{k: round(v, 4) for k, v in m.items()}})
        print(f"theta={th:<5} P={m['precision']:.4f} R={m['recall']:.4f} "
              f"F1={m['f1']:.4f} macro={m['macro_F1']:.4f}")
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        json.dump(rows, open(args.out, 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=1)
    return rows


if __name__ == '__main__':
    main()
