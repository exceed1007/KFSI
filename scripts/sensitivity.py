# -*- coding: utf-8 -*-
"""参数敏感性实验：逐个参数扫过取值区间，观察微平均 F1 的变化。

用法::

    python scripts/sensitivity.py --out outputs/sensitivity.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from sweep_theta import prepare, score  # noqa: E402
from src.pipeline import KFSIEngine  # noqa: E402
from src.inference import GapModel  # noqa: E402

GRIDS = [
    ('theta', [0.0, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0]),
    ('sif_split_gain', [0.02, 0.04, 0.06, 0.08, 0.12, 0.20]),
    ('sif_split_score', [0.35, 0.45, 0.55, 0.65, 0.75]),
    ('lf_split_score', [0.15, 0.25, 0.35, 0.45, 0.60]),
    ('min_group', [3, 4, 6, 8, 12]),
    ('max_width', [16, 32, 64, 128, 256]),
    ('min_cut_coverage', [0.4, 0.5, 0.6, 0.75, 0.9]),
]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', default=str(ROOT / 'data' / 'test_protocol'))
    ap.add_argument('--out', default=str(ROOT / 'outputs' / 'sensitivity.json'))
    ap.add_argument('--model', default=str(ROOT / 'models' / 'gap_model.json'))
    args = ap.parse_args(argv)

    items = prepare(Path(args.data))
    out = {}
    for name, vals in GRIDS:
        cur = []
        for v in vals:
            m, _ = score(items, KFSIEngine(cfg={name: v}, model=GapModel.load(args.model)))
            cur.append({'value': v, 'P': round(m['precision'], 4),
                        'R': round(m['recall'], 4), 'F1': round(m['f1'], 4),
                        'macro_F1': round(m['macro_F1'], 4)})
            print(f'{name}={v:<8} P={m["precision"]:.4f} R={m["recall"]:.4f} '
                  f'F1={m["f1"]:.4f} macro={m["macro_F1"]:.4f}')
        out[name] = cur
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    json.dump(out, open(args.out, 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    return out


if __name__ == '__main__':
    main()
