# -*- coding: utf-8 -*-
"""矩阵与列统计工具。

约定：
  * 消息用 ``bytes`` 表示；
  * 一批消息构成矩阵 ``M``（N x L，uint8），不足长度处补 0，并用
    ``valid``（N x L，bool）标记哪些格子是真实字节。所有列统计都只在
    ``valid`` 为真的格子上计算，避免零填充污染。
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

import numpy as np


# ----------------------------------------------------------------------
# 矩阵构造
# ----------------------------------------------------------------------
def to_matrix(msgs: Sequence[bytes], width: int | None = None) -> Tuple[np.ndarray, np.ndarray]:
    """把消息序列转成 (M, valid)。

    width 为 None 时取最长消息长度。
    """
    if not msgs:
        return np.zeros((0, 0), dtype=np.uint8), np.zeros((0, 0), dtype=bool)
    if width is None:
        width = max(len(m) for m in msgs)
    width = max(1, int(width))
    M = np.zeros((len(msgs), width), dtype=np.uint8)
    V = np.zeros((len(msgs), width), dtype=bool)
    for i, m in enumerate(msgs):
        n = min(len(m), width)
        if n:
            M[i, :n] = np.frombuffer(m[:n], dtype=np.uint8)
            V[i, :n] = True
    return M, V


# ----------------------------------------------------------------------
# 基本统计
# ----------------------------------------------------------------------
def entropy(values: np.ndarray) -> float:
    """香农熵（bit）。"""
    if values.size == 0:
        return 0.0
    _, counts = np.unique(values, return_counts=True)
    p = counts.astype(np.float64) / values.size
    return float(-(p * np.log2(p)).sum())


def norm_entropy(values: np.ndarray) -> float:
    """以 8 bit 为上限归一化的熵（0..1）。"""
    return entropy(values) / 8.0


def determinism(values: np.ndarray) -> float:
    """列内众数占比（0..1），值越大说明该列越“固定”。"""
    if values.size == 0:
        return 0.0
    _, counts = np.unique(values, return_counts=True)
    return float(counts.max() / values.size)


def conditional_determinism(keys: np.ndarray, values: np.ndarray) -> float:
    """按 keys 分组后 values 的加权平均众数占比。

    用来衡量“按某字段分组后，后续列是否变得更确定”，是结构标识字段
    （SIF）判别力的直接度量。
    """
    if values.size == 0:
        return 0.0
    total = 0.0
    for k in np.unique(keys):
        mask = keys == k
        sub = values[mask]
        if sub.size:
            total += sub.size * determinism(sub)
    return float(total / values.size)


def mutual_information(a: np.ndarray, b: np.ndarray) -> float:
    """两个离散列的经验互信息（bit）。"""
    if a.size == 0 or b.size == 0 or a.size != b.size:
        return 0.0
    pairs, counts = np.unique(np.stack([a, b], axis=1), axis=0,
                              return_counts=True)
    pxy = counts.astype(np.float64) / a.size
    pa = np.zeros(len(pxy)); pb = np.zeros(len(pxy))
    ua, ia = np.unique(pairs[:, 0], return_inverse=True)
    ub, ib = np.unique(pairs[:, 1], return_inverse=True)
    for i, v in enumerate(pxy):
        pa[ia[i]] += v
        pb[ib[i]] += v
    mi = 0.0
    for i, v in enumerate(pxy):
        mi += v * np.log2(v / (pa[ia[i]] * pb[ib[i]]))
    return float(max(0.0, mi))


def column_profile(M: np.ndarray, V: np.ndarray) -> dict:
    """逐列统计：熵、归一化熵、众数占比、可打印率、零值率、取值数。"""
    N, L = M.shape
    out = {k: np.zeros(L) for k in
           ('entropy', 'nentropy', 'determinism', 'printable', 'zero',
            'nunique', 'coverage')}
    for j in range(L):
        col = M[V[:, j], j]
        out['coverage'][j] = col.size / N if N else 0.0
        if col.size == 0:
            continue
        out['entropy'][j] = entropy(col)
        out['nentropy'][j] = out['entropy'][j] / 8.0
        out['determinism'][j] = determinism(col)
        out['printable'][j] = float(np.mean((col >= 0x20) & (col <= 0x7E)))
        out['zero'][j] = float(np.mean(col == 0))
        out['nunique'][j] = len(np.unique(col))
    return out


def structural_consistency(M: np.ndarray, V: np.ndarray,
                           cols: Sequence[int] | None = None) -> float:
    """矩阵的“结构一致性”：头部各列众数占比的均值（1 = 完全模板化）。"""
    if M.size == 0:
        return 0.0
    if cols is None:
        cols = range(M.shape[1])
    vals = []
    for j in cols:
        col = M[V[:, j], j]
        if col.size >= 2:
            vals.append(determinism(col))
    return float(np.mean(vals)) if vals else 0.0


def printable_runs(M: np.ndarray, V: np.ndarray) -> np.ndarray:
    """逐列标记“该列属于长度 >= 4 的可打印字符串游程”。"""
    N, L = M.shape
    flag = np.zeros(L, dtype=float)
    if N == 0:
        return flag
    for j in range(L):
        col = M[V[:, j], j]
        if col.size == 0:
            continue
        flag[j] = float(np.mean((col >= 0x20) & (col <= 0x7E)))
    # 只在连续 4 列以上高可打印的区域标记
    out = np.zeros(L, dtype=float)
    j = 0
    while j < L:
        if flag[j] >= 0.85:
            k = j
            while k < L and flag[k] >= 0.85:
                k += 1
            if k - j >= 4:
                out[j:k] = 1.0
            j = k
        else:
            j += 1
    return out


def estimate_payload_start(prof: dict, L: int, min_run: int = 4) -> int:
    """估计“结构区/载荷区”分界：返回第一个进入高熵段的列号。

    载荷（随机数据、加密内容、压缩内容）的列熵接近 8 bit，且会连续多列
    维持高熵；结构区（头部）的列通常是低熵或模板化的。找到第一个
    “连续 min_run 列归一化熵都 >= 0.75”的位置即为载荷起点。
    """
    ne = prof['nentropy']
    j = 0
    while j < L:
        if ne[j] >= 0.75:
            k = j
            while k < L and ne[k] >= 0.75:
                k += 1
            if k - j >= min_run:
                return j
            j = k
        else:
            j += 1
    return L
