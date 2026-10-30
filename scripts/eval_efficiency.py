# -*- coding: utf-8 -*-
"""效率评测：各方法的运行时间与内存占用对比。

用法::

    python scripts/eval_efficiency.py --out outputs/efficiency.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import tracemalloc
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from run_eval import load_protocol, message_timestamps, BASE_CFG  # noqa: E402
from src.pcapio import ProtocolDataLoader  # noqa: E402
from src.pipeline import KFSIEngine  # noqa: E402
from src.baselines import BASELINES  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', default=str(ROOT / 'data' / 'test_protocol'))
    ap.add_argument('--out', default=str(ROOT / 'outputs' / 'efficiency.json'))
    args = ap.parse_args(argv)

    loader = ProtocolDataLoader(BASE_CFG)
    files = sorted(Path(args.data).glob('*.pcap'))
    rows = []
    for f in files:
        msgs, _, dirs, frames = load_protocol(f, loader)
        if not msgs:
            continue
        ts = message_timestamps(f, frames)
        nbytes = sum(len(m) for m in msgs)

        # 计时与统计内存分开做：tracemalloc 会显著拖慢执行，混在一起
        # 会把运行时间抬高 5~10 倍。
        t0 = time.perf_counter()
        KFSIEngine().analyze(msgs, timestamps=ts, directions=dirs)
        dt = time.perf_counter() - t0
        tracemalloc.start()
        KFSIEngine().analyze(msgs, timestamps=ts, directions=dirs)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        row = {'protocol': f.stem, 'messages': len(msgs), 'bytes': nbytes,
               'kfsi_s': round(dt, 3), 'kfsi_kb': round(peak / 1024, 1)}
        for name, fn in BASELINES.items():
            t0 = time.perf_counter()
            fn(msgs)
            row[f'{name}_s'] = round(time.perf_counter() - t0, 3)
        rows.append(row)
        print(f"{f.stem:<9} kfsi={row['kfsi_s']:.2f}s/{row['kfsi_kb']:.0f}KB  "
              + '  '.join(f'{k}={row[k + "_s"]:.2f}s' for k in BASELINES))

    print('\n合计:')
    tot = {k: round(float(np.sum([r[k] for r in rows])), 3)
           for k in rows[0] if k.endswith('_s')}
    print(' ', tot, ' messages=', sum(r['messages'] for r in rows))
    tot['messages'] = sum(r['messages'] for r in rows)
    tot['bytes'] = sum(r['bytes'] for r in rows)
    tot['kfsi_kb'] = round(float(np.mean([r['kfsi_kb'] for r in rows])), 1)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    json.dump({'rows': rows, 'total': tot}, open(args.out, 'w',
              encoding='utf-8'), ensure_ascii=False, indent=1)
    return rows


if __name__ == '__main__':
    main()
