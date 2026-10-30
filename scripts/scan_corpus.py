"""扫描已知协议语料库，筛选可用于标定/训练的样本。"""
import sys, subprocess, json, re
from pathlib import Path
from collections import Counter
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.reference import ReferenceIndex

base = Path(sys.argv[1] if len(sys.argv)>1 else ROOT/'data/known_protocol')
ref = ReferenceIndex()
out=[]
for p in sorted(base.rglob('*.pcap')):
    try:
        ff, pi = ref.load(str(p))
    except Exception:
        continue
    if not ff: continue
    nmsg = sum(1 for k,v in pi.items() if v.get('payload_len',0) > 4)
    if nmsg < 40: continue
    names=set()
    for f in range(1, min(len(ff),30)):
        for fl in ff.get(f,[]):
            if fl.get('parent') is None and fl['name']:
                names.add(fl['name'])
    if len(names) < 5: continue
    proto = Counter(n.split('.')[0] for n in names).most_common(1)[0][0]
    out.append({'file':str(p),'msgs':nmsg,'fields':len(names),'proto':proto})
out.sort(key=lambda r:(-r['msgs']))
print(json.dumps(out[:80], ensure_ascii=False, indent=0))
print('total', len(out))
