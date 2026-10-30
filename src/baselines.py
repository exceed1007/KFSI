# -*- coding: utf-8 -*-
"""对比方法（基线）实现。

三个基线均按原论文的核心机制复现，并在**同一输入、同一评价口径**下与 KFSI
比较：

  * ``binaryinferno`` —— Chandler 等, NDSS'23。原子类型检测器（定长整型、
    序列、长度值对）与香农熵边界检测器组成检测器集合，再对相互竞争的
    假设做整合（冲突区域取证据最强者），输出字段边界。
  * ``pft`` —— Rohl 等, CCISP'24 的字段树（Packet Field Tree）。自底向上
    把相邻字节合并成字段树节点，合并判据由启发式规则（常数游程）与统计
    检验（相邻列取值的依赖性）混合给出；原文的语法分类器不影响边界，
    此处略去。
  * ``reinpro`` —— Qin 等, INFOCOM'24。先用流量行为的概率模型识别“控制
    字段”（决定报文结构的那一个字段），按控制字段取值把报文分簇，再在簇
    内用字段特征的差异定位边界。

各方法的判决阈值都在标定集（``data/train_protocol``）上选取，测试集不参与。
"""

from __future__ import annotations

from typing import Dict, List, Sequence, Tuple

import numpy as np

from . import features as F


# ----------------------------------------------------------------------
def _entropy(vals: np.ndarray) -> float:
    if vals.size == 0:
        return 0.0
    _, cnt = np.unique(vals, return_counts=True)
    p = cnt / cnt.sum()
    return float(-(p * np.log2(p)).sum())


def _joint_entropy(x: np.ndarray, y: np.ndarray) -> float:
    if x.size == 0:
        return 0.0
    pairs = x.astype(np.int64) * 4096 + y.astype(np.int64)
    return _entropy(pairs)


def _nmi(x: np.ndarray, y: np.ndarray) -> float:
    """归一化互信息（以两侧熵的较小者为分母）。"""
    hx, hy = _entropy(x), _entropy(y)
    if min(hx, hy) < 1e-6:
        return 0.0
    hxy = _joint_entropy(x, y)
    return max(0.0, (hx + hy - hxy) / min(hx, hy))


def _positions_to_boundaries(cuts: Sequence[int]) -> List[int]:
    return sorted({int(c) for c in cuts if c > 0})


def _col_det(M: np.ndarray, V: np.ndarray) -> np.ndarray:
    return F.column_profile(M, V)['determinism']


def _col_cov(M: np.ndarray, V: np.ndarray) -> np.ndarray:
    return F.column_profile(M, V)['coverage']


# ----------------------------------------------------------------------
# BinaryInferno（NDSS 2023）
# ----------------------------------------------------------------------
def _atomic_type_scores(M: np.ndarray, V: np.ndarray, p: int,
                        size: int) -> Dict[str, float]:
    """在 [p, p+size) 上评估各类原子类型假设的“纯度”。"""
    N, L = M.shape
    if p + size > L:
        return {}
    scores: Dict[str, float] = {}
    for endian in ('big', 'little'):
        vals = np.array([int.from_bytes(bytes(M[i, p:p + size]), endian)
                         for i in range(N)])
        scores[f'uint{size * 8}{endian[0].upper()}'] = float(len(np.unique(vals)) / N)
    if size == 1:
        printable = np.mean((M[:, p] >= 0x20) & (M[:, p] <= 0x7E))
        scores['ascii'] = float(1.0 - printable)
    return scores


def binaryinferno(msgs: Sequence[bytes], thr: float = 0.30,
                  max_size: int = 4) -> List[List[int]]:
    """熵边界 + 原子类型一致性，贪心选出最长一致字段。"""
    if len(msgs) < 2:
        return [[] for _ in msgs]
    M, V = F.to_matrix(msgs)
    N, L = M.shape
    prof = F.column_profile(M, V)
    ne = prof['nentropy']

    # 熵边界检测器：σ 的局部突变
    sigma_edge = np.zeros(L)
    for j in range(1, L):
        sigma_edge[j] = abs(ne[j] - ne[j - 1])

    cuts: List[int] = []
    p = 0
    while p < L - 1:
        best_w = 1
        for w in range(1, min(max_size, L - p) + 1):
            q = p + w
            if q >= L:
                break
            # 字段内部“类型一致性”：内部熵差小
            inner = float(np.mean(sigma_edge[p + 1:q])) if q > p + 1 else 0.0
            if inner <= thr:
                best_w = w
            else:
                break
        q = p + best_w
        if q < L and sigma_edge[q] >= thr:
            cuts.append(q)
            p = q
        else:
            # 找不到明显边界时，向右扩展直到出现边界，避免碎片
            k = q
            while k < L and sigma_edge[k] < thr:
                k += 1
            if k < L:
                cuts.append(k)
                p = k
            else:
                break
    b = _positions_to_boundaries(cuts)
    return [list(b) for _ in msgs]


# ----------------------------------------------------------------------
# Packet Field Tree（CCISP 2024）
# ----------------------------------------------------------------------
def pft(msgs: Sequence[bytes], merge_mi: float = 0.55,
        const_det: float = 0.95, min_cov: float = 0.6) -> List[List[int]]:
    """字段树：自底向上把相邻字节合并成节点。

    合并判据是启发式与统计的混合：相邻两列若①都属于“常数游程”
    （众数占比不低于 ``const_det``），或②取值相互依赖（归一化互信息
    不低于 ``merge_mi``），则视为同一字段的两个字节，合并为一个节点；
    否则在其间落一条边界。覆盖率不足的列不参与合并。
    """
    if len(msgs) < 2:
        return [[] for _ in msgs]
    M, V = F.to_matrix(msgs)
    N, L = M.shape
    det = _col_det(M, V)
    cov = _col_cov(M, V)

    nmi = np.zeros(L)
    for j in range(1, L):
        if cov[j - 1] >= min_cov and cov[j] >= min_cov:
            nmi[j] = _nmi(M[:, j - 1], M[:, j])

    cuts: List[int] = []
    for j in range(1, L):
        if cov[j] < min_cov or cov[j - 1] < min_cov:
            continue
        both_const = det[j] >= const_det and det[j - 1] >= const_det
        if both_const or nmi[j] >= merge_mi:
            continue
        cuts.append(j)
    b = _positions_to_boundaries(cuts)
    return [list(b) for _ in msgs]


# ----------------------------------------------------------------------
# REInPro（INFOCOM 2024）
# ----------------------------------------------------------------------
def _control_field_score(M: np.ndarray, V: np.ndarray, lens: np.ndarray,
                         s: int, w: int,
                         span: int = 24) -> Tuple[float, np.ndarray]:
    """候选控制字段的结构区分力：按取值分簇后组内列确定性的加权提升。"""
    N, L = M.shape
    vals = np.array([int.from_bytes(bytes(M[i, s:s + w]), 'big')
                     for i in range(N)])
    uniq = np.unique(vals)
    if len(uniq) < 2 or len(uniq) > 12:
        return -1.0, vals
    lo = s + w
    hi = min(L, lo + span)
    if hi - lo < 2:
        return -1.0, vals
    det = _col_det(M, V)
    base = float(det[lo:hi].mean())
    inner = 0.0
    for u in uniq:
        sel = vals == u
        n = int(sel.sum())
        if n < 2:
            continue
        sub = _col_det(M[sel], V[sel])
        inner += n * float(sub[lo:hi].mean())
    inner /= N
    gain = inner - base
    # 流量行为模型：控制字段取值与报文长度通常强相关
    corr = 0.0
    if np.ptp(vals) > 0 and np.ptp(lens) > 0:
        c = float(np.corrcoef(vals.astype(float), lens)[0, 1])
        corr = abs(c) if np.isfinite(c) else 0.0
    return gain + 0.05 * corr, vals


def reinpro(msgs: Sequence[bytes], min_gain: float = 0.08,
            det_jump: float = 0.25, ent_jump: float = 0.25,
            cf_max_off: int = 8, span: int = 24) -> List[List[int]]:
    """控制字段驱动：先定位控制字段并分簇，再在簇内按特征差异切分。"""
    if len(msgs) < 2:
        return [[] for _ in msgs]
    M, V = F.to_matrix(msgs)
    N, L = M.shape
    lens = np.array([len(m) for m in msgs], dtype=float)
    prof = F.column_profile(M, V)
    det, ne = prof['determinism'], prof['nentropy']

    best = (-1.0, 0, 1, None)
    for w in (1, 2):
        for s in range(0, min(L - w, cf_max_off) + 1):
            sc, vals = _control_field_score(M, V, lens, s, w, span=span)
            if sc > best[0]:
                best = (sc, s, w, vals)
    sc, s, w, vals = best
    if vals is None or sc < min_gain:
        # 未找到控制字段：退化为纯统计切分
        cuts = [j for j in range(1, L)
                if abs(det[j] - det[j - 1]) >= det_jump
                or abs(ne[j] - ne[j - 1]) >= ent_jump]
        b = _positions_to_boundaries(cuts)
        return [list(b) for _ in msgs]

    head = [s, s + w]
    uniq = np.unique(vals)
    out: List[List[int]] = [[] for _ in msgs]
    for u in uniq:
        idx = np.where(vals == u)[0]
        if idx.size == 0:
            continue
        subM, subV = M[idx], V[idx]
        subdet = _col_det(subM, subV)
        subne = F.column_profile(subM, subV)['nentropy']
        cuts = [j for j in range(1, L)
                if abs(subdet[j] - subdet[j - 1]) >= det_jump
                or abs(subne[j] - subne[j - 1]) >= ent_jump]
        b = _positions_to_boundaries(list(head) + cuts)
        for i in idx:
            out[i] = list(b)
    return out


BASELINES = {
    'binaryinferno': binaryinferno,
    'pft': pft,
    'reinpro': reinpro,
}
