# -*- coding: utf-8 -*-
"""边界证据与最大后验解码。

给定一个“同结构、同区域”的报文集，逐位置计算“此处应切分”的证据，
再用动态规划在字段宽度先验下求全局最优切分：

    F* = argmax_F  Σ_{p∈F} (s_p − θ) + Σ_{w∈F} log P(w)

其中 ``s_p`` 为位置 p 的切分对数几率，``θ`` 为决策阈值，``P(w)`` 为字段
宽度先验（由已知协议统计得到）。该式等价于在“切分收益”与“字段过碎/
过粗”的代价之间取得平衡。
"""

from __future__ import annotations

import json
import math
import os
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

from . import features as F

FEATURE_NAMES = [
    'mi_indep',      # 1 - 归一化互信息：两侧列越独立越可能是字段边界
    'pair_coh',      # 归一化互信息（两侧列的“同字段”程度）
    'is_edge',       # 是否靠近区域首尾
    'det_jump',      # 相邻列众数占比之差
    'det_prev',      # 左侧列确定性
    'det_cur',       # 右侧列确定性
    'ent_jump',      # 相邻列归一化熵之差
    'ent_cur',       # 右侧列归一化熵
    'const_break',   # 左侧恒定 / 右侧变化（或反之）
    'run_len',       # 左侧连续恒定列长度（截断到 4）
    'is_payload',    # 是否为载荷区起点
    'in_str',        # 两侧都在可打印串内
    'anchor_start',  # 是否为语义字段起点
    'anchor_inside', # 是否落在语义字段内部
    'pos_ratio',     # 相对位置
    'ent_left4',     # 左侧 4 列平均归一化熵
    'ent_right4',    # 右侧 4 列平均归一化熵
    'mi_raw',        # 原始互信息
]

DEFAULT_THETA = 2.0

# 依赖列统计量的特征。这类特征的标准误与 1/sqrt(N) 成正比：样本少时
# “众数占比高”极可能只是抽样偶然，不能当作强证据。解码时按样本量收缩。
STAT_FEATURES = (
    'mi_indep', 'pair_coh', 'det_jump', 'det_prev', 'det_cur', 'ent_jump',
    'ent_cur', 'const_break', 'run_len', 'ent_left4', 'ent_right4', 'mi_raw',
)

# 收缩强度：conf = N / (N + SHRINK_K)。N=300 时几乎不收缩，N=10 时收缩
# 到 ~0.5，N=6 时收缩到 ~0.33。默认关闭（0）：在标定集上开启收缩并未带来
# 收益，因为决策阈值 θ 已经承担了抑制过分割的作用。
SHRINK_K = 0.0

# 默认证据权重（先验设定；可在已知协议上标定后覆盖）
DEFAULT_WEIGHTS = {
    'mi_indep': 2.6,
    'det_jump': 1.0,
    'const_break': 0.6,
    'ent_jump': 0.7,
    'in_str': -2.5,
    'anchor_start': 3.5,
    'anchor_inside': -6.0,
    'is_edge': 0.4,
    'pos_ratio': -0.30,
    'is_payload': 1.2,
}

def default_width_logprob():
    """字段宽度先验 log P(w)。

    头部字段以 1~4 字节为主，8 字节（时间戳/双精度）次之，其余按幂律长尾，
    使“整段载荷作为一个长字段”仍然具有可观的先验概率。
    """
    core = {1: -0.50, 2: -0.42, 3: -1.35, 4: -0.95,
            5: -2.10, 6: -2.10, 7: -2.30, 8: -1.25}
    out = dict(core)
    for w in range(9, 513):
        out[w] = -1.9 - 1.05 * math.log(w)
    return out


DEFAULT_WIDTH_LOGPROB = default_width_logprob()


class GapModel:
    """位置级切分证据模型（逻辑回归权重，可离线标定）。"""

    def __init__(self, weights: Optional[Dict[str, float]] = None,
                 bias: float = -2.0, theta: float = DEFAULT_THETA,
                 width_logprob: Optional[Dict[int, float]] = None,
                 shrink_k: float = SHRINK_K):
        self.weights = dict(DEFAULT_WEIGHTS) if not weights else dict(weights)
        self.bias = bias
        self.theta = theta
        self.shrink_k = float(shrink_k)
        self.width_logprob = dict(width_logprob) if width_logprob else dict(DEFAULT_WIDTH_LOGPROB)

    # -- 序列化 --------------------------------------------------------
    @classmethod
    def load(cls, path: str) -> 'GapModel':
        with open(path, 'r', encoding='utf-8') as f:
            d = json.load(f)
        wl = {int(k): v for k, v in (d.get('width_logprob') or {}).items()}
        return cls(weights=d.get('weights') or {}, bias=d.get('bias', -2.0),
                   theta=d.get('theta', DEFAULT_THETA), width_logprob=wl,
                   shrink_k=d.get('shrink_k', SHRINK_K))

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({'weights': self.weights, 'bias': self.bias,
                       'theta': self.theta,
                       'shrink_k': self.shrink_k,
                       'width_logprob': {str(k): v for k, v in
                                         self.width_logprob.items()}},
                      f, ensure_ascii=False, indent=1)

    # -- 打分 ----------------------------------------------------------
    def confidence(self, n_samples: Optional[int]) -> float:
        if not n_samples or n_samples <= 0 or self.shrink_k <= 0:
            return 1.0
        return float(n_samples) / (float(n_samples) + self.shrink_k)

    def logit(self, feats: Sequence[Dict[str, float]],
              n_samples: Optional[int] = None) -> np.ndarray:
        out = np.full(len(feats), self.bias, dtype=np.float64)
        conf = self.confidence(n_samples)
        for name, w in self.weights.items():
            ww = w * conf if name in STAT_FEATURES else w
            if ww == 0.0:
                continue
            for i, f in enumerate(feats):
                out[i] += ww * f.get(name, 0.0)
        return out

    def score(self, feats: Sequence[Dict[str, float]]) -> np.ndarray:
        z = self.logit(feats)
        return 1.0 / (1.0 + np.exp(-z))

    # -- 解码 ----------------------------------------------------------
    def decode(self, cut_logit: np.ndarray, L: int,
               max_width: int = 256) -> List[int]:
        """最大后验切分。返回切分点（不含 0，含 L 由调用方补）。"""
        if L <= 1:
            return []
        NEG = -1e18
        best = np.full(L + 1, NEG)
        back = np.zeros(L + 1, dtype=int)
        best[0] = 0.0
        for j in range(1, L + 1):
            for w in range(1, min(max_width, j) + 1):
                i = j - w
                gain = best[i] + self.width_logprob.get(w, -8.0)
                if i > 0:
                    gain += cut_logit[i] - self.theta
                if gain > best[j]:
                    best[j] = gain
                    back[j] = i
        cuts: List[int] = []
        j = L
        while j > 0:
            i = back[j]
            if i > 0:
                cuts.append(i)
            j = i
        return sorted(cuts)


def gap_features(M: np.ndarray, V: np.ndarray, prof: dict,
                 str_run: np.ndarray, payload_start: int,
                 anchors: Sequence[Tuple[int, int]],
                 lo: int = 0) -> List[Dict[str, float]]:
    """为位置 p=0..L 计算切分证据特征（索引即 p，0 与 L 处为零）。"""
    N, L = M.shape
    feats: List[Dict[str, float]] = []

    def anchor_state(p: int) -> Tuple[float, float]:
        start = 0.0
        inside = 0.0
        for (s, e) in anchors:
            s -= lo
            e -= lo
            if p == s:
                start = 1.0
            if s < p < e:
                inside = 1.0
        return start, inside

    for p in range(L + 1):
        if p == 0 or p >= L:
            feats.append({k: 0.0 for k in FEATURE_NAMES})
            continue
        both = V[:, p - 1] & V[:, p]
        a = M[both, p - 1]
        b = M[both, p]
        ha = F.entropy(a)
        hb = F.entropy(b)
        det_prev = prof['determinism'][p - 1]
        det_cur = prof['determinism'][p]
        if a.size > 3 and min(ha, hb) > 1e-6:
            mi = F.mutual_information(a, b)
            coh = min(1.0, mi / min(ha, hb))
        else:
            # 有一侧为常量时互信息恒为 0，改用“双常量”判据
            coh = 1.0 if (det_prev > 0.98 and det_cur > 0.98) else 0.0
        run = 0
        k = p - 1
        while k >= 0 and prof['determinism'][k] > 0.98:
            run += 1
            k -= 1
        a_start, a_inside = anchor_state(p)
        left = [prof['nentropy'][j] for j in range(max(0, p - 4), p)]
        right = [prof['nentropy'][j] for j in range(p, min(L, p + 4))]
        feats.append({
            'mi_indep': float(1.0 - coh),
            'pair_coh': float(coh),
            'det_jump': float(abs(det_prev - det_cur)),
            'det_prev': float(det_prev),
            'det_cur': float(det_cur),
            'ent_jump': float(prof['nentropy'][p] - prof['nentropy'][p - 1]),
            'ent_cur': float(prof['nentropy'][p]),
            'const_break': float((det_prev > 0.98) != (det_cur > 0.98)),
            'run_len': float(min(4, run)),
            'is_payload': float(p == payload_start),
            'in_str': float(str_run[p - 1] > 0 and str_run[p] > 0),
            'anchor_start': a_start,
            'anchor_inside': a_inside,
            'pos_ratio': p / max(1, L),
            'ent_left4': float(np.mean(left)) if left else 0.0,
            'ent_right4': float(np.mean(right)) if right else 0.0,
            'mi_raw': float(F.mutual_information(a, b)) if a.size > 3 else 0.0,
            'is_edge': float(p <= 2 or (L - p) <= 2),
        })
    return feats


def region_matrix(msgs: Sequence[bytes], lo: int, hi: Optional[int]):
    """截取若干报文的 [lo, hi) 区间并构成左对齐矩阵。"""
    if hi is None:
        sub = [m[lo:] for m in msgs]
    else:
        sub = [m[lo:hi] for m in msgs]
    sub = [s for s in sub if len(s) >= 1]
    if not sub:
        return None, None, []
    M, V = F.to_matrix(sub)
    return M, V, sub
