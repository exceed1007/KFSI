# -*- coding: utf-8 -*-
"""多口径评测：一次分析，同时给出 V1/V2/V3/V4 四种参考粒度下的指标。

用法::

    python scripts/run_scopes.py --data data/test_protocol --out outputs/scopes.json
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
from src.reference import ReferenceIndex, Metrics, GT_SCOPES  # noqa: E402
from src.inference import GapModel  # noqa: E402


def load_all(data_dir: Path, only=None):
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
        gts = {s: [] for s in GT_SCOPES}
        for i, m in enumerate(msgs):
            fields = ReferenceIndex.fields_for_frames(
                frames[i] if i < len(frames) else [], ff, pi, len(m))
            for s in GT_SCOPES:
                sc = ReferenceIndex.scope_fields(fields, s)
                gts[s].append(ReferenceIndex.positions(sc, len(m)))
        items.append({'name': f.stem, 'msgs': msgs, 'ts': ts,
                      'dirs': dirs, 'gts': gts})
        print(f'  prepared {f.stem}: {len(msgs)} msgs')
    return items


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', default=str(ROOT / 'data' / 'test_protocol'))
    ap.add_argument('--tol', type=int, default=1)
    ap.add_argument('--only', default=None)
    ap.add_argument('--local-gain', action='store_true')
    ap.add_argument('--out', default=None)
    ap.add_argument('--model', default=str(ROOT / 'models' / 'gap_model.json'))
    args = ap.parse_args(argv)

    items = load_all(Path(args.data), args.only)
    eng = KFSIEngine(cfg={'use_keymark': 'all', 'shrink_k': 0.0,
                          'keyfield': {'sif_local_gain': args.local_gain}},
                     model=GapModel.load(args.model))

    out = {}
    for s in GT_SCOPES:
        tp = fp = fn = 0
        per = []
        for it in items:
            res = eng.analyze(it['msgs'], timestamps=it['ts'],
                              directions=it['dirs'])
            a = b = c = 0
            for i, m in enumerate(it['msgs']):
                pred = [p for p in res.boundaries[i] if 0 < p < len(m)]
                x, y, z = Metrics.match_positions(pred, it['gts'][s][i],
                                                  tol=args.tol)
                a += x; b += y; c += z
            tp += a; fp += b; fn += c
            per.append({'protocol': it['name'], **Metrics.prf(a, b, c)})
        m = Metrics.prf(tp, fp, fn)
        out[s] = {'micro': m,
                  'macro_F1': float(np.mean([p['f1'] for p in per])),
                  'per_protocol': per}
        print(f'\n[{s}] micro P={m["precision"]:.4f} R={m["recall"]:.4f} '
              f'F1={m["f1"]:.4f} macroF1={out[s]["macro_F1"]:.4f}')
        for p in per:
            print(f'   {p["protocol"]:<9} P={p["precision"]:.3f} '
                  f'R={p["recall"]:.3f} F1={p["f1"]:.3f}')
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        json.dump(out, open(args.out, 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=1)
    return out


if __name__ == '__main__':
    main()
