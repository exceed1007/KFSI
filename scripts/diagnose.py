# -*- coding: utf-8 -*-
"""跨协议误差剖析：统计 FP/FN 的位置分布与其处的参考字段名。

用法::

    python scripts/diagnose.py                 # 全部协议
    python scripts/diagnose.py --only MQTT
    python scripts/diagnose.py --theta 2.0
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from run_eval import load_protocol, message_timestamps, BASE_CFG  # noqa: E402
from src.pcapio import ProtocolDataLoader  # noqa: E402
from src.pipeline import KFSIEngine  # noqa: E402
from src.reference import ReferenceIndex, Metrics  # noqa: E402
from src.inference import GapModel  # noqa: E402


def match_map(pred, gt, tol=1):
    """返回被命中的预测点集合与未命中的参考点集合。"""
    preds = sorted(pred); gts = sorted(gt)
    n = len(preds); used = [False] * n
    hit_g = set(); k = 0
    for g in gts:
        while k < n and preds[k] < g - tol:
            k += 1
        j = k
        while j < n and preds[j] <= g + tol:
            if not used[j]:
                used[j] = True
                hit_g.add(g)
                break
            j += 1
    hit_p = {preds[i] for i in range(n) if used[i]}
    return hit_p, hit_g


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', default=str(ROOT / 'data' / 'test_protocol'))
    ap.add_argument('--only', default=None)
    ap.add_argument('--scope', default='V3_一级字段')
    ap.add_argument('--theta', type=float, default=0.0)
    ap.add_argument('--top', type=int, default=14)
    args = ap.parse_args(argv)

    loader = ProtocolDataLoader(BASE_CFG)
    ref = ReferenceIndex()
    files = sorted(Path(args.data).glob('*.pcap'))
    if args.only:
        keep = {s.strip().lower() for s in args.only.split(',')}
        files = [f for f in files if f.stem.lower() in keep]

    model = GapModel(); model.theta = args.theta
    eng = KFSIEngine(model=model)

    glob_fp = Counter(); glob_fn = Counter()
    for f in files:
        msgs, _, dirs, frames = load_protocol(f, loader)
        if not msgs:
            continue
        ts = message_timestamps(f, frames)
        res = eng.analyze(msgs, timestamps=ts, directions=dirs)
        ff, pi = ref.load(str(f))
        fp = Counter(); fn = Counter()
        names_at = defaultdict(list)
        inside = Counter()
        for i, m in enumerate(msgs):
            fields = ReferenceIndex.fields_for_frames(
                frames[i] if i < len(frames) else [], ff, pi, len(m))
            scoped = ReferenceIndex.scope_fields(fields, args.scope)
            gt = ReferenceIndex.positions(scoped, len(m))
            pred = [p for p in res.boundaries[i] if 0 < p < len(m)]
            hp, hg = match_map(pred, gt)
            for p in pred:
                if p not in hp:
                    fp[p] += 1
                    # 该预测点落在哪个参考字段内部？
                    for x in scoped:
                        if x['start'] <= p < min(x['end'], len(m)):
                            inside[x['name']] += 1
                            break
            for g in gt:
                if g not in hg:
                    fn[g] += 1
            for x in scoped:
                names_at[x['start']].append(x['name'])
        print(f'\n--- {f.stem} ({len(msgs)} msgs) '
              f'FP={sum(fp.values())} FN={sum(fn.values())}')
        print('  FP pos:', [(int(k), v) for k, v in fp.most_common(args.top)])
        print('  FN pos:', [(int(k), v) for k, v in fn.most_common(args.top)])
        print('  FP inside field:', inside.most_common(8))
        for q, _ in fp.most_common(6):
            print(f'    FP@{q}: gt_starts={list(dict.fromkeys(names_at.get(q, [])))[:3]}')
        for q, _ in fn.most_common(6):
            print(f'    FN@{q}: gt_starts={list(dict.fromkeys(names_at.get(q, [])))[:3]}')
        glob_fp.update(fp); glob_fn.update(fn)

    print('\n==== global FP positions ====')
    print([(int(k), v) for k, v in glob_fp.most_common(args.top)])
    print('==== global FN positions ====')
    print([(int(k), v) for k, v in glob_fn.most_common(args.top)])


if __name__ == '__main__':
    main()
