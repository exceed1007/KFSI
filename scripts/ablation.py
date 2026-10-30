# -*- coding: utf-8 -*-
"""消融实验：逐个关闭方法组件，观察性能变化。

用法::

    python scripts/ablation.py --data data/test_protocol --out outputs/ablation.json
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

VARIANTS = [
    ('KFSI_full', {}),
    ('w/o 水平分裂', {'use_horizontal': False}),
    ('w/o 垂直分裂', {'use_vertical': False}),
    ('w/o 水平+垂直', {'use_horizontal': False, 'use_vertical': False}),
    ('w/o 关键字段端点', {'use_keymark': False}),
    ('w/o 语义锚点', {'use_semantic': False}),
    ('w/o 跨结构迁移', {'use_transfer': False}),
    ('w/o 宽度先验', {'use_width_prior': False}),
    ('w/o MAP 解码', {'decoder': 'thr'}),
    ('w/o 比特级 SIF', {'keyfield': {'use_bit_sif': False}}),
    ('w/o 学习权重', {}),
    ('w/o 局部结构增益', {'keyfield': {'sif_local_gain': True}}),
]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', default=str(ROOT / 'data' / 'test_protocol'))
    ap.add_argument('--tol', type=int, default=1)
    ap.add_argument('--only', default=None)
    ap.add_argument('--out', default=None)
    ap.add_argument('--model', default=str(ROOT / 'models' / 'gap_model.json'),
                    help='学到的位置级证据模型；供 w/o 学习权重 之外的所有变体使用')
    args = ap.parse_args(argv)

    items = prepare(Path(args.data), only=args.only)
    if not items:
        print('no samples'); return

    rows = []
    base = GapModel.load(args.model)
    for name, cfg in VARIANTS:
        if name == 'w/o 学习权重':
            model = GapModel()          # 免训练默认权重，阈值同基础模型
            model.theta = base.theta
        else:
            model = GapModel.load(args.model)
        eng = KFSIEngine(cfg=cfg, model=model)
        m, per = score(items, eng, tol=args.tol)
        rows.append({'variant': name, **{k: round(v, 4) for k, v in m.items()}})
        print(f'{name:<18} P={m["precision"]:.4f} R={m["recall"]:.4f} '
              f'F1={m["f1"]:.4f} macro={m["macro_F1"]:.4f}', flush=True)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        json.dump(rows, open(args.out, 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=1)
    return rows


if __name__ == '__main__':
    main()
