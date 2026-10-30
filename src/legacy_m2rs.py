# -*- coding: utf-8 -*-
"""
M2RS 字段边界推断引擎（第4章「四机制协同分析框架」的落地实现）。

整体流程
--------
  M1 长度分层（Length Stratification）
      等长报文同格式的先验（Netzob/NEMESYS 的基本假设）。把会话内报文按长度
      分层，层内构造无填充矩阵，避免零填充列污染列证据。

  M2 多机制证据 + 判别模型（General Feature Set G）
      在每个候选切点 j 上提取 36 维结构特征（相邻列同质性、单列属性、位置
      先验、语义区域、邻位上下文、规模量），送入**在 known_protocol 上千个已知
      协议样本上训练**的梯度提升判别器，得到该位置是字段边界的后验 p_j。
      语义区域特征（可打印串游程、零游程、字母数字率）使模型能够识别「字符串
      字段内部不应再切分」。

  M3 生成式字段结构先验（Field Structure Prior）
      从已知协议统计得到的字段宽度先验 P(w)，并区分「中间字段」与「末尾字段」
      （末尾通常是变长载荷，宽度分布明显更长）。它决定了「应切出多少个字段」，
      避免了手工阈值的标定困难。

  M4 多尺度证据融合 + 最大后验解码（MAP Decoding）
      层内样本不足时（很多协议过半长度层只有 1~2 条报文），改用**会话内所有
      覆盖到该列的报文**重新统计，扩充证据量后与原证据在对数几率空间融合。
      最后在一维偏移上做动态规划，最大化

          Σ_{t∈T} (l_t − θ) + Σ_{blocks} log P(w)

      θ 为置信度阈值，用于精确率/召回率权衡。

模型文件（models/mmfi/）
----------------------
  boundary_scorer.joblib  —— 位置级边界判别器（在已知协议上训练）
  boundary_scorer_lr.json —— 逻辑回归版判别器（无 sklearn 依赖时的降级方案）
  len_prior.json          —— 字段宽度先验 P_mid(w) / P_last(w)

若模型文件缺失，引擎自动降级为「纯先验 + 位置启发式」，保证流水线不中断。
"""

import json
import math
import os
import time
from collections import Counter
from typing import Dict, List, Optional, Sequence

import numpy as np

try:  # 项目根目录（src/ 的上一级）
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
except NameError:  # pragma: no cover
    PROJECT_ROOT = os.getcwd()

MODEL_DIR = os.path.join(PROJECT_ROOT, 'models', 'mmfi')
NEG = -1e18

DEFAULT_CFG = {
    'theta': -2.8,          # 置信度阈值（对数几率空间的偏移量）
    'min_support': 2,       # 层内最少报文数
    'pool_max_n': 4,        # 层内报文数不超过该值时启用跨层证据融合
    'pool_w': 1.0,          # 融合权重
    'widen_prior': 1.0,     # 宽度先验的缩放系数
    'max_len': 0,           # 单个字段的最大宽度（0=不限）
    'kind': 'gb',           # gb=梯度提升；lr=逻辑回归
    # ---- 消融实验开关（默认全部开启，即完整方法）----
    'use_stratify': True,   # M1 等长报文分层
    'use_scorer': True,     # M2 判别式位置打分（关闭则用无监督同质性启发式）
    'use_prior': True,      # M3 字段宽度先验
    'use_fusion': True,     # M4 多尺度证据融合
    'use_map': True,        # M5 最大后验解码（关闭则用局部贪心）
    'drop_features': '',    # 逗号分隔的特征名，置为训练集均值（特征族消融）
}

# 特征族（用于消融实验中的整族剔除）
FEATURE_FAMILIES = {
    '语义区域': ['strl', 'strr', 'strboth', 'prun', 'prun_both', 'zrun',
                 'txt_rate'],
    '长度序号': ['selflen1', 'selflen2', 'totlen1', 'totlen2', 'idxcorr',
                 'cntinc', 'lencorr'],
    '位置先验': ['relpos', 'logpos', 'even2', 'even4', 'is2tok'],
    '邻位上下文': ['prev_cardchg', 'prev_hchg', 'prev_const', 'next_cardchg',
                   'next_hchg', 'next_const'],
}


# ----------------------------------------------------------------------
# 基础统计
# ----------------------------------------------------------------------
def entropy_bits(counts: Sequence[int], n: int) -> float:
    """经验熵（bit），含 Miller-Madow 偏置校正。"""
    if n <= 0 or not counts:
        return 0.0
    h = 0.0
    m = 0
    for c in counts:
        if c <= 0:
            continue
        m += 1
        p = c / n
        h -= p * math.log2(p)
    return max(0.0, h + (m - 1) / (2.0 * n))


def pearson(x, y) -> float:
    x = np.asarray(x, dtype=np.float64)
    y = np.asarray(y, dtype=np.float64)
    if x.size < 3 or np.ptp(x) == 0 or np.ptp(y) == 0:
        return 0.0
    with np.errstate(invalid='ignore', divide='ignore'):
        c = float(np.corrcoef(x, y)[0, 1])
    return c if np.isfinite(c) else 0.0


def mutual_information(a: np.ndarray, b: np.ndarray) -> float:
    n = len(a)
    ha = entropy_bits(list(Counter(a.tolist()).values()), n)
    hb = entropy_bits(list(Counter(b.tolist()).values()), n)
    hab = entropy_bits(list(Counter(zip(a.tolist(), b.tolist())).values()), n)
    return max(0.0, ha + hb - hab)


def col_stats(M: np.ndarray, j: int) -> Dict[str, float]:
    v = M[:, j]
    c = Counter(v.tolist())
    n = len(v)
    return {'card': len(c), 'H': entropy_bits(list(c.values()), n),
            'const': len(c) == 1,
            'zero': float(np.mean(v == 0)),
            'printable': float(np.mean([(32 <= b <= 126) for b in v]))}


# ----------------------------------------------------------------------
# 位置级特征提取（训练与推理严格一致）
# ----------------------------------------------------------------------
def _run_length(mask_rows: np.ndarray) -> np.ndarray:
    """逐行求 True 游程长度（每个位置填其所在游程的长度）。"""
    n, L = mask_rows.shape
    run = np.zeros((n, L), dtype=np.int32)
    for r in range(n):
        i = 0
        while i < L:
            if mask_rows[r, i]:
                j = i
                while j + 1 < L and mask_rows[r, j + 1]:
                    j += 1
                run[r, i:j + 1] = j - i + 1
                i = j + 1
            else:
                i += 1
    return run


def features_for_stratum(M: np.ndarray, L: int,
                         row_len: Sequence[int] = None
                         ) -> List[Dict[str, float]]:
    """
    对宽度为 L 的无填充矩阵，给出 j=1..L-1 各切点的特征。

    row_len: 每条报文的真实总长度（跨层全局视图中各行长度不同）。
             缺省时认为层内等长，取 L。长度/序号字段类特征依赖它。
    """
    n = M.shape[0]
    cs = [col_stats(M, j) for j in range(L)]
    lens_arr = (np.asarray(row_len, dtype=np.int64) if row_len is not None
                else np.full(n, L, dtype=np.int64))
    idx_arr = np.arange(n, dtype=np.float64)
    isp = np.array([[(32 <= b <= 126) or b in (9, 10, 13) for b in row]
                    for row in M], dtype=bool) if n else np.zeros((0, L), bool)
    run = _run_length(isp)
    runz = _run_length(M == 0)
    rows: List[Dict[str, float]] = []
    for j in range(1, L):
        l, r = cs[j - 1], cs[j]
        lm1 = cs[j - 2] if j >= 2 else None
        rp1 = cs[j + 1] if j + 1 < L else None
        pair = M[:, j - 1:j + 1]
        cpair = len({tuple(x) for x in pair.tolist()})
        pair_int = np.array([int.from_bytes(x.tobytes(), 'big')
                             for x in pair], dtype=np.float64)
        lens = np.full(n, float(L))
        d: Dict[str, float] = {}
        # A 相邻列同质性
        d['cardchg'] = abs(math.log(l['card'] + 1) - math.log(r['card'] + 1))
        d['hchg'] = abs(l['H'] - r['H'])
        d['prchg'] = abs(l['printable'] - r['printable'])
        d['zchg'] = abs(l['zero'] - r['zero'])
        d['mi'] = mutual_information(M[:, j - 1], M[:, j])
        d['dep'] = 1.0 - cpair / max(1, l['card'] * r['card'])
        # 多字节字段决定性
        d['pairdet'] = max(l['card'], r['card']) / max(1, cpair)
        d['lgain'] = math.log((cpair + 1) / (max(l['card'], r['card']) + 1))
        d['corrnum'] = abs(pearson(M[:, j - 1], M[:, j]))
        # B 单列属性
        d['maxcard'] = math.log(1 + max(l['card'], r['card'])) / math.log(1 + n)
        d['mincard'] = math.log(1 + min(l['card'], r['card'])) / math.log(1 + n)
        d['constl'] = float(l['const'])
        d['constr'] = float(r['const'])
        d['leftH'] = l['H']
        d['rightH'] = r['H']
        # C 位置先验
        d['relpos'] = j / L
        d['logpos'] = math.log(1 + j)
        d['even2'] = float(j % 2 == 0)
        d['even4'] = float(j % 4 == 0)
        d['is2tok'] = float(j in (2, 4, 8))
        # F 语义区域
        d['strl'] = l['printable']
        d['strr'] = r['printable']
        d['strboth'] = min(l['printable'], r['printable'])
        d['prun'] = float(np.minimum(run[:, j - 1], run[:, j]).mean()) / L
        d['prun_both'] = float((run[:, j - 1] + run[:, j]).mean()) / (2 * L)
        d['zrun'] = float(np.minimum(runz[:, j - 1], runz[:, j]).mean()) / L
        d['txt_rate'] = float(np.mean([
            (48 <= M[i, j - 1] <= 57 or 65 <= M[i, j - 1] <= 90
             or 97 <= M[i, j - 1] <= 122 or M[i, j - 1] == 32)
            and (48 <= M[i, j] <= 57 or 65 <= M[i, j] <= 90
                 or 97 <= M[i, j] <= 122 or M[i, j] == 32)
            for i in range(n)])) if n else 0.0
        # D 邻位上下文
        d['prev_cardchg'] = (abs(math.log(lm1['card'] + 1)
                                 - math.log(l['card'] + 1))
                             if lm1 is not None else 0.0)
        d['prev_hchg'] = abs(lm1['H'] - l['H']) if lm1 is not None else 0.0
        d['prev_const'] = float(lm1['const']) if lm1 is not None else 1.0
        d['next_cardchg'] = (abs(math.log(r['card'] + 1)
                                 - math.log(rp1['card'] + 1))
                             if rp1 is not None else 0.0)
        d['next_hchg'] = abs(r['H'] - rp1['H']) if rp1 is not None else 0.0
        d['next_const'] = float(rp1['const']) if rp1 is not None else 1.0
        # E 规模与长度相关
        d['lencorr'] = abs(pearson(pair_int, lens))
        d['nn'] = math.log(1 + n)
        d['invL'] = math.log(1 + L)
        # G 长度字段 / 序号字段证据（协议中最强的两种确定性结构）
        rem = lens_arr - j
        if n:
            ok1 = (rem >= 0) & (rem <= 255)
            d['selflen1'] = float(
                np.mean((M[:, j - 1].astype(np.int64) == rem) & ok1))
            ok2 = (rem >= 0) & (rem <= 65535)
            if j >= 2:
                be = (M[:, j - 2].astype(np.int64) << 8) | M[:, j - 1]
                le = (M[:, j - 1].astype(np.int64) << 8) | M[:, j - 2]
                d['selflen2'] = max(float(np.mean((be == rem) & ok2)),
                                    float(np.mean((le == rem) & ok2)))
                d['totlen2'] = max(float(np.mean(be == lens_arr)),
                                   float(np.mean(le == lens_arr)))
            else:
                d['selflen2'] = 0.0
                d['totlen2'] = 0.0
            d['totlen1'] = float(
                np.mean(M[:, j - 1].astype(np.int64) == (lens_arr & 0xFF)))
            d['idxcorr'] = max(
                abs(pearson(M[:, j - 1].astype(np.float64), idx_arr)),
                abs(pearson(M[:, j].astype(np.float64), idx_arr)))
            d['cntinc'] = (float(np.mean(
                (M[1:, j - 1].astype(np.int32) - M[:-1, j - 1].astype(np.int32))
                == 1)) if n >= 3 else 0.0)
        else:
            d['selflen1'] = d['selflen2'] = 0.0
            d['totlen1'] = d['totlen2'] = 0.0
            d['idxcorr'] = d['cntinc'] = 0.0
        rows.append(d)
    return rows


def features_global(msgs: Sequence[bytes], L_true: int,
                    ctx: int = 2) -> List[Optional[Dict[str, float]]]:
    """
    跨层「全局视图」特征：对每个切点 j，改用会话内所有覆盖到 j 的报文统计。
    实现上截取 [j-1-ctx, j+1+ctx] 的子矩阵复用同一套特征，再把与绝对位置
    相关的特征改回真值。
    """
    n_all = len(msgs)
    if n_all == 0:
        return []
    W = max(len(m) for m in msgs)
    G = np.zeros((n_all, W), dtype=np.uint8)
    for i, m in enumerate(msgs):
        G[i, :len(m)] = np.frombuffer(m, dtype=np.uint8)
    lens = np.array([len(m) for m in msgs], dtype=np.int64)
    out: List[Optional[Dict[str, float]]] = []
    for j in range(1, L_true):
        mask = lens > j
        if int(mask.sum()) < 2:
            out.append(None)
            continue
        lo = max(0, j - 1 - ctx)
        hi = min(W, j + 1 + ctx)
        sub = G[mask, lo:hi]
        w = sub.shape[1]
        rel = j - lo
        if rel < 1 or rel > w - 1:
            out.append(None)
            continue
        d = features_for_stratum(sub, w, row_len=lens[mask])[rel - 1]
        nn = int(mask.sum())
        d['relpos'] = j / L_true
        d['logpos'] = math.log(1 + j)
        d['even2'] = float(j % 2 == 0)
        d['even4'] = float(j % 4 == 0)
        d['is2tok'] = float(j in (2, 4, 8))
        d['nn'] = math.log(1 + nn)
        d['invL'] = math.log(1 + L_true)
        s = w / max(1, L_true)
        d['prun'] *= s
        d['prun_both'] *= s
        d['zrun'] *= s
        out.append(d)
    return out


# ----------------------------------------------------------------------
# 判别器 / 先验
# ----------------------------------------------------------------------
class BoundaryScorer:
    """位置级边界后验判别器。"""

    def __init__(self, kind: str = 'gb', model_dir: str = None,
                 drop: Sequence[str] = ()):
        self.kind = kind
        self.dir = model_dir or MODEL_DIR
        self.gb = None
        self.names = None
        self.mu = self.sd = self.w = None
        self.b = 0.0
        self.ready = False
        # 被剔除的特征（消融用）：推理时置为训练集均值，即标准化后取 0
        self.drop_idx: List[int] = []
        self._drop = set(drop or ())
        if kind == 'gb':
            self._load_gb()
        if not self.ready:
            self._load_lr()
        if self.names is not None and self._drop:
            self.drop_idx = [i for i, n in enumerate(self.names)
                             if n in self._drop]

    def _load_gb(self):
        path = os.path.join(self.dir, 'boundary_scorer.joblib')
        try:
            import joblib
            d = joblib.load(path)
            self.gb = d['model']
            self.names = list(d['names'])
            self.mu = np.asarray(d['mu'], dtype=np.float64)
            self.sd = np.asarray(d['sd'], dtype=np.float64)
            self.ready = True
        except Exception:
            self.gb = None

    def _load_lr(self):
        path = os.path.join(self.dir, 'boundary_scorer_lr.json')
        try:
            with open(path, 'r', encoding='utf-8') as f:
                d = json.load(f)
            self.names = list(d['names'])
            self.mu = np.array(d['mu'], dtype=np.float64)
            self.sd = np.array(d['sd'], dtype=np.float64)
            self.w = np.array(d['coef'], dtype=np.float64)
            self.b = float(d.get('intercept', 0.0))
            self.ready = True
        except Exception:
            self.ready = False

    def _vector(self, rows) -> np.ndarray:
        X = np.array([[r[k] for k in self.names] for r in rows],
                     dtype=np.float64)
        if self.drop_idx:
            for i in self.drop_idx:
                X[:, i] = self.mu[i]
        return X

    def prob(self, rows) -> np.ndarray:
        if not self.ready:
            # 降级：仅用位置先验（越靠前越可能是边界）
            return np.array([max(0.02, min(0.9, 0.6 - r.get('relpos', 0)))
                             for r in rows], dtype=np.float64)
        X = self._vector(rows)
        Z = (X - self.mu) / self.sd
        if self.gb is not None:
            return self.gb.predict_proba(Z)[:, 1]
        z = Z @ self.w + self.b
        return 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))


class WidthPrior:
    """字段宽度先验，区分中间字段与末尾字段。"""

    def __init__(self, path: str = None):
        self.path = path or os.path.join(MODEL_DIR, 'len_prior.json')
        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                d = json.load(f)
            self.maxw = int(d['max_len'])
            self.p_mid = {int(k): float(v) for k, v in d['p_mid'].items()}
            self.p_last = {int(k): float(v) for k, v in d['p_last'].items()}
            self.tr_mid = float(d.get('tail_rate_mid', 0.35))
            self.tr_last = float(d.get('tail_rate_last', 0.02))
        except Exception:
            # 与 models/mmfi/len_prior.json（1~8 字节项）一致的兜底取值，
            # 保证缺少模型文件时先验与论文 4.4.1 节报告的值相同。
            self.maxw = 8
            self.p_mid = {1: 0.4966935385811154, 2: 0.30635893338826026,
                          3: 0.014170620306773447, 4: 0.09220400934192803,
                          5: 0.010675453904030399, 6: 0.006990332805486097,
                          7: 0.0010257553573267643, 8: 0.018159668918599752}
            self.p_last = {1: 0.15609522335446002, 2: 0.20194819521483265,
                           3: 0.009755951459653751, 4: 0.08487677769898763,
                           5: 0.0117071417515845, 6: 0.019511902919307503,
                           7: 0.028292259232995873, 8: 0.05170654273616488}
            self.tr_mid, self.tr_last = 0.35, 0.02
        self._c: Dict[tuple, float] = {}

    def phi(self, w: int, last: bool = False) -> float:
        key = (w, last)
        v = self._c.get(key)
        if v is not None:
            return v
        table = self.p_last if last else self.p_mid
        rate = self.tr_last if last else self.tr_mid
        p = table.get(w)
        if p is not None:
            v = math.log(max(p, 1e-9))
        else:
            v = math.log(max(min(table.values()), 1e-9)) - rate * (w - self.maxw)
        self._c[key] = v
        return v


# ----------------------------------------------------------------------
# 最大后验解码
# ----------------------------------------------------------------------
def decode_map(L: int, logits: Sequence[float], prior: WidthPrior,
               theta: float = 0.0, max_len: int = 0,
               widen_prior: float = 1.0) -> List[int]:
    """
    maximize  Σ_{t∈T}(l_t − θ) + Σ_{blocks} log P(w)

    最后一个字段使用「末尾字段」宽度先验，其余使用「中间字段」先验。
    """
    if L <= 1:
        return []
    s = np.array([float(x) - theta for x in logits], dtype=np.float64)
    limit = max_len if max_len and max_len > 0 else L
    dp = np.full(L + 1, NEG, dtype=np.float64)
    bk = np.zeros(L + 1, dtype=np.int64)
    dp[0] = 0.0
    for j in range(1, L + 1):
        best, bs = NEG, 0
        for a in range(max(0, j - limit), j):
            if dp[a] == NEG:
                continue
            v = dp[a] + widen_prior * prior.phi(j - a, last=False)
            if a > 0:
                v += s[a - 1]
            if v > best:
                best, bs = v, a
        dp[j] = best
        bk[j] = bs
    best, blast = NEG, 0
    for a in range(max(0, L - limit), L):
        if dp[a] == NEG:
            continue
        v = dp[a] + widen_prior * prior.phi(L - a, last=True)
        if a > 0:
            v += s[a - 1]
        if v > best:
            best, blast = v, a
    if best == NEG:
        return []
    out = []
    j = blast
    while j > 0:
        a = int(bk[j])
        if a > 0:
            out.append(a)
        j = a
    return sorted(out)


def decode_greedy(L: int, logits: Sequence[float], prior: WidthPrior,
                  theta: float = 0.0, max_len: int = 0,
                  widen_prior: float = 1.0) -> List[int]:
    """
    局部贪心解码（消融用）：自左向右只在「当前切分收益为正」处落刀，
    不做全局最优搜索。收益定义为

        s_j + widen * ( phi(w) + phi(1) - phi(w+1) )

    即「把当前块封口在宽度 w」相对于「继续增长到 w+1」的先验增益。
    """
    if L <= 1:
        return []
    s = np.array([float(x) - theta for x in logits], dtype=np.float64)
    limit = max_len if max_len and max_len > 0 else L
    cuts: List[int] = []
    last = 0
    for j in range(1, L):
        w = j - last
        if limit and w + 1 > limit:      # 超出最大字段宽度，强制落刀
            cuts.append(j)
            last = j
            continue
        gain = s[j - 1] + widen_prior * (prior.phi(w) + prior.phi(1)
                                         - prior.phi(w + 1))
        if gain > 0:
            cuts.append(j)
            last = j
    return cuts


def homogeneity_logits(rows: Sequence[Dict[str, float]],
                       ref: Sequence[float] = None) -> np.ndarray:
    """
    无监督启发式打分（消融中替代 M2 判别器）：相邻列的同质性变化越大，
    越可能是字段边界；字符串区域内部则抑制落刀。

    ref 给定时，把启发式分数线性对齐到 ref 的均值与方差，保证两种打分
    处于同一决策尺度（θ 无需重新标定）。
    """
    if not rows:
        return np.zeros(0, dtype=np.float64)
    h = np.array([
        r.get('cardchg', 0.0) + r.get('hchg', 0.0)
        + 0.5 * r.get('prchg', 0.0) + 0.5 * r.get('zchg', 0.0)
        - 0.5 * r.get('strboth', 0.0)
        for r in rows], dtype=np.float64)
    sd = float(h.std())
    if sd < 1e-9:
        return np.full(len(h), float(np.mean(ref)) if len(ref) else 0.0)
    z = (h - float(h.mean())) / sd
    if ref is None or len(ref) == 0:
        return z
    r = np.asarray(ref, dtype=np.float64)
    rsd = float(r.std())
    return z * (rsd if rsd > 1e-9 else 1.0) + float(r.mean())


def _logit(p) -> np.ndarray:
    q = np.clip(np.asarray(p, dtype=np.float64), 1e-6, 1 - 1e-6)
    return np.log(q / (1 - q))


# ----------------------------------------------------------------------
# 引擎
# ----------------------------------------------------------------------
class M2RSBoundaryEngine:
    """M2RS 字段边界推断引擎。"""

    def __init__(self, config: Optional[Dict] = None, model_dir: str = None):
        cfg = dict(DEFAULT_CFG)
        mcfg = (((config or {}).get('boundary') or {}).get('m2rs') or {})
        cfg.update({k: v for k, v in mcfg.items() if k in DEFAULT_CFG})
        self.cfg = cfg
        drop = [x.strip() for x in str(cfg.get('drop_features') or '').split(',')
                if x.strip()]
        # 支持按「特征族」整族剔除
        fam = [FEATURE_FAMILIES[x] for x in drop if x in FEATURE_FAMILIES]
        if fam:
            drop = [x for x in drop if x not in FEATURE_FAMILIES] + \
                [n for f in fam for n in f]
        self.drop_features = drop
        self.scorer = BoundaryScorer(cfg.get('kind', 'gb'), model_dir,
                                     drop=self.drop_features)
        self.prior = WidthPrior(
            os.path.join(model_dir or MODEL_DIR, 'len_prior.json'))
        self.max_len = int(cfg.get('max_len', 0))
        self.timing: Dict[str, float] = {}

    # --- 计时 ---
    def reset_timing(self):
        self.timing = {}

    def _tick(self, key: str, t0: float):
        self.timing[key] = self.timing.get(key, 0.0) + (time.time() - t0)

    # --- 单层推断 ---
    def infer_matrix(self, M: np.ndarray, L: int,
                     all_msgs: Sequence[bytes] = None,
                     n_local: int = 0) -> List[int]:
        """给定无填充字节矩阵（n×L），推断该层的字段边界。"""
        t0 = time.time()
        rows = features_for_stratum(M, L)
        self._tick('特征提取', t0)
        t0 = time.time()
        logs = _logit(self.scorer.prob(rows))
        if not self.cfg.get('use_scorer', True):
            logs = homogeneity_logits(rows, ref=logs)
        self._tick('判别打分', t0)
        # 多尺度融合
        if (self.cfg.get('use_fusion', True) and all_msgs is not None
                and n_local <= int(self.cfg.get('pool_max_n', 4))
                and float(self.cfg.get('pool_w', 1.0)) > 0):
            t0 = time.time()
            grows = features_global(all_msgs, L)
            w = float(self.cfg.get('pool_w', 1.0))
            sel = [i for i, row in enumerate(grows)
                   if i < len(logs) and row is not None]
            if sel:
                if self.cfg.get('use_scorer', True):
                    # 批量打分：一次性送入判别器，避免逐位置调用的固定开销
                    vals = _logit(self.scorer.prob([grows[i] for i in sel]))
                else:
                    vals = np.array([homogeneity_logits([grows[i]],
                                                        ref=logs[i:i + 1])[0]
                                     for i in sel], dtype=np.float64)
                lg = logs.copy()
                for i, v in zip(sel, vals):
                    lg[i] = float(v)
                logs = (1 - w) * logs + w * lg
            self._tick('证据融合', t0)
        t0 = time.time()
        theta = float(self.cfg.get('theta', -2.8))
        widen = (float(self.cfg.get('widen_prior', 1.0))
                 if self.cfg.get('use_prior', True) else 0.0)
        if self.cfg.get('use_map', True):
            T = decode_map(L, logs, self.prior, theta=theta,
                           max_len=self.max_len, widen_prior=widen)
        else:
            T = decode_greedy(L, logs, self.prior, theta=theta,
                              max_len=self.max_len, widen_prior=widen)
        self._tick('解码', t0)
        return [b for b in T if 0 < b < L]

    def infer_stratum(self, msgs: Sequence[bytes], idxs: Sequence[int],
                      all_msgs: Sequence[bytes], L: int) -> List[int]:
        sub = [msgs[i] for i in idxs]
        M = np.zeros((len(sub), L), dtype=np.uint8)
        for r, m in enumerate(sub):
            M[r, :len(m)] = np.frombuffer(m, dtype=np.uint8)
        return self.infer_matrix(M, L, all_msgs, n_local=len(idxs))

    def predict_messages(self, msgs: Sequence[bytes]) -> List[List[int]]:
        """对会话内每条报文给出其字段边界位置列表。"""
        preds: List[List[int]] = [[] for _ in msgs]
        if not msgs:
            return preds
        # 消融变体：不做等长分层，全部报文零填充对齐为单一矩阵
        if not self.cfg.get('use_stratify', True):
            t0 = time.time()
            L = max(len(m) for m in msgs)
            if L < 3:
                return preds
            M = np.zeros((len(msgs), L), dtype=np.uint8)
            for r, m in enumerate(msgs):
                M[r, :len(m)] = np.frombuffer(m, dtype=np.uint8)
            T = self.infer_matrix(M, L, msgs, n_local=len(msgs))
            self._tick('分层与调度', t0)
            for i, m in enumerate(msgs):
                preds[i] = [b for b in T if 0 < b < len(m)]
            return preds
        t0 = time.time()
        strata: Dict[int, List[int]] = {}
        for i, m in enumerate(msgs):
            strata.setdefault(len(m), []).append(i)
        self._tick('分层与调度', t0)
        min_support = int(self.cfg.get('min_support', 2))
        templates: Dict[int, List[int]] = {}
        supported: List[tuple] = []
        for L in sorted(strata):
            idxs = strata[L]
            if len(idxs) < min_support or L < 3:
                templates[L] = []
                continue
            templates[L] = self.infer_stratum(msgs, idxs, msgs, L)
            supported.append((L, templates[L], len(idxs)))
        # 低支撑层：借用可包容它的最大支撑层的模板
        for L in sorted(strata):
            if templates.get(L):
                continue
            cands = [(Lp, Tp) for (Lp, Tp, _) in supported if Lp >= L]
            if not cands:
                cands = [(Lp, Tp) for (Lp, Tp, _) in supported]
            if not cands:
                continue
            Lp, Tp = max(cands, key=lambda x: x[0])
            templates[L] = [b for b in Tp if 0 < b < L]
        for L, idxs in strata.items():
            T = templates.get(L) or []
            for i in idxs:
                preds[i] = list(T)
        return preds

    def predict_global(self, msgs: Sequence[bytes]) -> List[int]:
        """给出会话级（全局）边界，用于可视化与字段切分展示。"""
        preds = self.predict_messages(msgs)
        if not preds:
            return []
        cnt: Dict[int, int] = {}
        for p in preds:
            for b in p:
                cnt[b] = cnt.get(b, 0) + 1
        keep = [b for b, c in cnt.items() if c >= max(1, len(preds) // 3)]
        return sorted(keep)
