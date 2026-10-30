# -*- coding: utf-8 -*-
"""关键字段识别：结构标识字段（SIF）与长度字段（LF）。

本模块是全文的“第一步”：把协议设计原则落到可计算的判据上。

结构标识字段
------------
三条设计特征 → 三个可计算判据：
  1) 位置在前（位于任何依赖它的字段之前）→ 位置先验；
  2) 值域有限（对应有限的报文类型）→ 取值基数约束；
  3) **决定后续结构** → “分组结构增益”：按该字段取值分组后，各组内部
     的列确定性显著提升（组内模板化）。
判据 3 是本方法的核心，它把“该字段是否决定结构”变成一个可检验的量。
在比特粒度上，用掩码（mask/shift）枚举 1~4 bit 的组合，覆盖 IEC104 的
U/S/I 帧标志这类“用几个比特表示结构”的情形。

长度字段
--------
四类检验统计量（语义一致性 SC、结构边界强度 SBS、取值分布合理性 VDP、
指针有效性 PV）之外，本模块增加了两个更强的判据：
  * 闭合性检验（closure）：报文长度与字段值之差是否为常数（对多长度
    字段、多层封装同时成立）；
  * 对齐增益（alignment gain）：把字段之后的内容按 v 平移对齐后，后续
    首列的确定性是否显著提升——这是“该字段确实指向一个块边界”的直接证据。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

from . import features as F

DEFAULT_CFG = {
    # 结构标识字段
    'sif_max_types': 20,
    'sif_min_gain': 0.06,
    'sif_max_size': 3,
    'sif_head_limit': 16,
    'sif_min_bit_gain': 0.06,
    'sif_bit_masks': [1, 2, 4, 8, 16, 32, 64, 128, 3, 12, 15, 240],
    # 长度字段
    'lf_max_size': 4,
    'lf_head_limit': 24,
    'lf_min_corr': 0.6,
    'lf_align_gain': 0.25,
    'lf_closure_std': 1.2,
    'lf_closure_inlier': 0.88,
    'lf_min_values': 3,
    'sif_local_gain': False,
    'use_bit_sif': True,
}


@dataclass
class KeyField:
    start: int                      # 全局偏移
    size: int                       # 字节长度（比特级字段仍占 1 字节）
    label: str                      # 'type' | 'length'
    score: float
    endian: str = 'big'
    mask: Optional[int] = None      # 比特级结构标识字段的掩码
    shift: int = 0
    meta: Dict[str, float] = field(default_factory=dict)

    @property
    def end(self) -> int:
        return self.start + self.size


# ----------------------------------------------------------------------
# 结构标识字段
# ----------------------------------------------------------------------
def _norm_entropy(vals: np.ndarray) -> float:
    return F.norm_entropy(vals)


def _group_gain(M: np.ndarray, V: np.ndarray, keys: np.ndarray,
                cols: Sequence[int]) -> Tuple[float, float, int]:
    """分组结构增益。

    返回 (gain, 组间结构散度, 唯一取值数)。
    gain > 0 表示“按该字段分组后结构更模板化”。
    """
    if not cols:
        return 0.0, 0.0, 0
    uniq = np.unique(keys)
    if uniq.size < 2:
        return 0.0, 0.0, int(uniq.size)

    base = F.structural_consistency(M, V, cols)

    # 组内一致性（按报文数加权）
    within = 0.0
    profiles = []
    for k in uniq:
        idx = np.where(keys == k)[0]
        if idx.size == 0:
            continue
        subM, subV = M[idx], V[idx]
        within += idx.size * F.structural_consistency(subM, subV, cols)
        profiles.append(np.array([F.determinism(subM[subV[:, j], j])
                                  for j in cols]))
    within /= keys.size
    gain = within - base

    # 组间结构散度：各组“列确定性指纹”的平均 L1 距离
    div = 0.0
    cnt = 0
    for i in range(len(profiles)):
        for j in range(i + 1, len(profiles)):
            div += float(np.abs(profiles[i] - profiles[j]).mean())
            cnt += 1
    div = div / cnt if cnt else 0.0
    return float(gain), div, int(uniq.size)


def _local_gain(M: np.ndarray, V: np.ndarray, keys: np.ndarray,
                after: int, span: int = 10) -> Tuple[float, float]:
    """候选字段**紧随其后**若干列上的分组结构增益。

    整体头部列集往往被长载荷/变长字段稀释，使得真实的结构标识字段
    也拿不到正增益（实测 MQTT 的 ``hdrflags`` 在全列上增益为负）。而
    结构标识字段的作用本来就是局部的——“它决定了紧接其后的字段如何
    排布”。因此额外在 ``[after, after+span)`` 的局部窗口上度量增益，
    作为与全局增益并列的证据。
    """
    L = M.shape[1]
    cols = [j for j in range(after, min(L, after + span))
            if V[:, j].mean() >= 0.9]
    if len(cols) < 2:
        return 0.0, 0.0
    gain, div, _ = _group_gain(M, V, keys, cols)
    return gain, div


def detect_structure_fields(msgs: Sequence[bytes],
                            window: Tuple[int, int] | None = None,
                            cfg: Optional[dict] = None,
                            exclude: Sequence[Tuple[int, int]] = ()
                            ) -> List[KeyField]:
    """检测结构标识字段（字节级 + 比特级）。"""
    cfg = {**DEFAULT_CFG, **(cfg or {})}
    if len(msgs) < 4:
        return []
    lo, hi = window if window else (0, max(len(m) for m in msgs))
    sub = [m[lo:hi] for m in msgs]
    M, V = F.to_matrix(sub)
    N, L = M.shape
    if L < 2:
        return []

    head = min(L, int(cfg['sif_head_limit']))
    prof = F.column_profile(M, V)
    payload_start = F.estimate_payload_start(prof, L)
    # 可打印字符串游程内的列不作为结构标识字段候选（如 MQTT 的 topic 名）
    str_run = F.printable_runs(M, V)
    # 参与“分组一致性”统计的列：头部且非载荷、非候选字段自身
    all_cols = [j for j in range(min(head + 8, max(L, 1))) if j < L]

    def excluded(j: int) -> bool:
        for (s, e) in exclude:
            if s - lo <= j < e - lo:
                return True
        return False

    candidates: List[KeyField] = []

    def _score(gain: float, div: float, nent: float, s: int,
               n_vals: int) -> Tuple[float, float]:
        """把两类证据（结构决定性 / 类型标志性）归一化后做“或”融合。"""
        struct_ev = min(1.0, max(0.0, gain) / 0.20)
        pos = 1.0 if s <= 8 else math_exp(-(s - 8) / 8.0)
        type_ev = min(1.0, max(0.0, 1.0 - nent)) * pos
        if not (2 <= n_vals <= int(cfg['sif_max_types'])):
            type_ev = 0.0
        score = 1.0 - (1.0 - struct_ev) * (1.0 - 0.9 * type_ev)
        score *= (0.75 + 0.25 * min(1.0, div / 0.3))
        return float(score), float(struct_ev)

    # ---- 字节级 ----
    for s in range(0, min(head, L)):
        for size in range(1, min(int(cfg['sif_max_size']), L - s) + 1):
            if any(excluded(lo + s + k) for k in range(size)):
                continue
            if any(str_run[s + k] > 0 for k in range(size)):
                continue
            if any(prof['coverage'][s + k] < 0.95 for k in range(size)):
                continue
            vals = np.array([int.from_bytes(bytes(M[i, s:s + size]), 'big')
                             for i in range(N)])
            uniq = np.unique(vals)
            if uniq.size < 2 or uniq.size > int(cfg['sif_max_types']):
                continue
            cols = [j for j in all_cols
                    if not (s <= j < s + size) and j <= max(payload_start, s + 8)]
            gain_g, div, _ = _group_gain(M, V, vals, cols)
            if cfg.get('sif_local_gain', True):
                gain_l, div_l = _local_gain(M, V, vals, s + size)
            else:
                gain_l, div_l = gain_g, div
            gain = max(gain_g, gain_l)
            if gain_l > gain_g:
                div = div_l
            nent = F.norm_entropy(vals)
            score, struct_ev = _score(gain, div, nent, s, int(uniq.size))
            score *= (1.0 - 0.10 * (size - 1))     # 宽度惩罚：类型字段多为 1~2 字节
            if score < float(cfg['sif_min_gain']) and struct_ev < 0.3:
                continue
            candidates.append(KeyField(
                start=lo + s, size=size, label='type', score=score,
                meta={'gain': gain, 'gain_local': gain_l, 'gain_global': gain_g,
                      'divergence': div, 'nentropy': nent,
                      'n_values': int(uniq.size), 'struct_ev': struct_ev}))

    # ---- 比特级 ----
    for s in (range(0, min(head, L)) if cfg.get('use_bit_sif', True) else []):
        if excluded(lo + s) or str_run[s] > 0 or prof['coverage'][s] < 0.95:
            continue
        col = M[:, s]
        for mask in cfg['sif_bit_masks']:
            masked = col & mask
            uniq = np.unique(masked)
            if uniq.size < 2 or uniq.size > 8:
                continue
            cols = [j for j in all_cols if j != s and j <= max(payload_start, s + 8)]
            gain_g, div, _ = _group_gain(M, V, masked, cols)
            if cfg.get('sif_local_gain', True):
                gain_l, div_l = _local_gain(M, V, masked, s + 1)
            else:
                gain_l, div_l = gain_g, div
            gain = max(gain_g, gain_l)
            if gain_l > gain_g:
                div = div_l
            nent = F.norm_entropy(masked)
            score, struct_ev = _score(gain, div, nent, s, int(uniq.size))
            # 掩码越“简”越可信（bit 数少、连续）
            nbits = bin(int(mask)).count('1')
            score = score / (1.0 + 0.10 * (nbits - 1))
            if struct_ev < 0.45:
                continue
            candidates.append(KeyField(
                start=lo + s, size=1, label='type', score=float(score),
                mask=int(mask), shift=_mask_shift(int(mask)),
                meta={'gain': gain, 'gain_local': gain_l, 'gain_global': gain_g,
                      'divergence': div, 'nentropy': nent,
                      'n_values': int(uniq.size), 'struct_ev': struct_ev,
                      'bit_level': 1.0}))

    # ---- 去重与排序 ----
    candidates.sort(key=lambda c: -c.score)
    kept: List[KeyField] = []
    for c in candidates:
        if any(c.start < k.end and k.start < c.end for k in kept):
            continue
        kept.append(c)
        if len(kept) >= 3:
            break
    return kept


def math_exp(x: float) -> float:
    return float(np.exp(x))


def _mask_shift(mask: int) -> int:
    s = 0
    while mask and not (mask & 1):
        mask >>= 1
        s += 1
    return s


# ----------------------------------------------------------------------
# 长度字段
# ----------------------------------------------------------------------
def _js_divergence(a: np.ndarray, b: np.ndarray) -> float:
    if a.size == 0 or b.size == 0:
        return 0.0
    pa = np.bincount(a, minlength=256).astype(np.float64)
    pb = np.bincount(b, minlength=256).astype(np.float64)
    pa /= pa.sum()
    pb /= pb.sum()
    m = 0.5 * (pa + pb)
    def kl(x, y):
        mask = x > 0
        return float((x[mask] * np.log2(x[mask] / np.maximum(y[mask], 1e-12))).sum())
    return float(min(1.0, 0.5 * (kl(pa, m) + kl(pb, m)) / 1.0))


def detect_length_fields(msgs: Sequence[bytes],
                         window: Tuple[int, int] | None = None,
                         cfg: Optional[dict] = None,
                         exclude: Sequence[Tuple[int, int]] = ()
                         ) -> List[KeyField]:
    """检测长度字段（含多层/多个长度字段）。

    “窗口”可以是一条完整报文，也可以是垂直分裂后的子区间；后者使嵌套
    长度字段（TPKT/COTP/S7 多层首部）能够被逐层识别。
    """
    cfg = {**DEFAULT_CFG, **(cfg or {})}
    if len(msgs) < 4:
        return []
    lo, hi = window if window else (0, max(len(m) for m in msgs))
    lens = np.array([min(len(m), hi) - lo for m in msgs], dtype=np.float64)
    if (lens <= 2).sum() > len(lens) // 2:
        return []
    sub = [m[lo:hi] for m in msgs]
    M, V = F.to_matrix(sub)
    N, L = M.shape
    if L < 4:
        return []

    head = min(L, int(cfg['lf_head_limit']))
    out: List[KeyField] = []
    # 可打印字符串游程内的列不可能是长度字段：MQTT 的 topic 里恰好出现
    # 0x2f('/')、0x20(' ') 这类字节，在整段报文上会呈现“取值集中、与报文
    # 长度近似闭合”的假象，一旦被当作长度字段就会触发连锁伪垂直分裂。
    prof = F.column_profile(M, V)
    str_run = F.printable_runs(M, V)

    for s in range(0, head):
        if any(s0 - lo <= s < e0 - lo for (s0, e0) in exclude):
            continue
        if str_run[s] > 0:
            continue
        for size in (1, 2, 4):
            if s + size + 1 >= L:
                continue
            if any(str_run[s + k] > 0 for k in range(size)):
                continue
            # 自然对齐：字段起始偏移应是其宽度的整数倍（避免把上一字段的
            # 尾部并入长度字段，例如把 Modbus 的 0x0000 协议标识 + 长度
            # 拆成 4 字节“长度”）
            if s % size != 0:
                continue
            for endian in ('big', 'little'):
                vals = np.array([int.from_bytes(bytes(M[i, s:s + size]), endian)
                                 for i in range(N)], dtype=np.float64)
                if np.all(vals == 0) or vals.max() > lens.max() + 8:
                    continue
                # 单字节候选额外要求“真的承载变化”：取值过少说明它是常
                # 量标志或字符串里的某个字符，与报文长度同起同落只是巧合。
                # 多字节候选不受此限——固定长度报文的长度字段取值本来就
                # 单一（如 S7comm 的 TPKT 长度），其可信度来自闭合性。
                if size == 1:
                    if np.unique(vals).size < int(cfg['lf_min_values']):
                        continue
                    if np.ptp(vals) < 2:
                        continue
                # 闭合性：长度字段值与报文(窗口)长度之差为常数。
                # 用“中位数附近 ±1 的内点占比”而不是标准差：真实协议里
                # 常有个别报文带填充、扩展选项或多出一个尾部字段，标准差
                # 会被这些离群样本抬高，从而把真实长度字段判掉（HART-IP
                # 的 msg_length 即属此类）。内点占比对离群样本稳健。
                res = lens - vals
                res_med = float(np.median(res))
                dev = np.abs(res - res_med)
                inlier = float(np.mean(dev <= 1.0))
                res_std = float(res.std())
                sane = (res.min() >= -8) and (res.max() <= lens.max())
                if not sane:
                    continue
                closure = inlier / (1.0 + 0.25 * min(res_std, 8.0))
                if np.ptp(vals) == 0 or np.ptp(lens) == 0:
                    corr = 0.0
                else:
                    corr = float(np.corrcoef(vals, lens)[0, 1])
                    if not np.isfinite(corr):
                        corr = 0.0
                align = _alignment_gain(sub, vals, s + size)
                vdp = 1.0 - F.norm_entropy(vals)
                sbs = _block_boundary_strength(sub, vals, s + size)
                pv = float(np.mean((vals >= 0) & (vals <= lens)))
                if pv < 0.98:
                    continue

                score = (0.32 * closure + 0.28 * max(0.0, align)
                         + 0.20 * max(0.0, corr) + 0.12 * vdp + 0.08 * sbs)
                accepts = (
                    (inlier >= float(cfg['lf_closure_inlier'])
                     and np.ptp(vals) > 0)
                    or (align >= float(cfg['lf_align_gain'])
                        and corr >= float(cfg['lf_min_corr']))
                    or (align >= 0.5 and inlier >= 0.9)
                )
                if not accepts:
                    continue
                out.append(KeyField(
                    start=lo + s, size=size, label='length',
                    score=float(score), endian=endian,
                    meta={'closure': closure, 'align_gain': align,
                          'corr': corr, 'vdp': vdp, 'sbs': sbs,
                          'res_std': res_std, 'res_mean': float(res.mean()),
                          'res_med': res_med, 'inlier': inlier,
                          'pv': pv, 'values': vals.tolist()}))

    # 同一“取值序列”只保留一个候选：优先自然对齐下宽度更大的解释
    # （如 Modbus 长度字段 2 字节，其高字节恒为 0，与 1 字节解释的取值
    # 序列完全相同，此时应取 2 字节版本）。
    out.sort(key=lambda c: (-c.size, -c.score))
    kept: List[KeyField] = []
    for c in out:
        sig = tuple(int(x) for x in c.meta['values'])
        if any(tuple(int(x) for x in k.meta['values']) == sig for k in kept):
            continue
        if any(c.start < k.end and k.start < c.end for k in kept):
            continue
        kept.append(c)
    kept.sort(key=lambda c: c.start)
    return kept[:3]


def _alignment_gain(msgs: Sequence[bytes], vals: np.ndarray,
                    block_start: int) -> float:
    """按字段值平移后，后续首列的确定性提升量。

    对真实长度字段，``msg[block_start + v]`` 之后是同一个字段（如 S7 的
    Data Length），因此对齐后首列取值高度集中；对伪长度字段则无此效果。
    """
    def first_col(offset_fn) -> np.ndarray:
        col = []
        for i, m in enumerate(msgs):
            p = offset_fn(i)
            if 0 <= p < len(m):
                col.append(m[p])
        return np.array(col, dtype=np.uint8)

    before = first_col(lambda i: block_start)
    after = first_col(lambda i: block_start + int(vals[i]))
    if before.size < 4 or after.size < 4:
        return 0.0
    return float(F.determinism(after) - F.determinism(before))


def _block_boundary_strength(msgs: Sequence[bytes], vals: np.ndarray,
                             block_start: int) -> float:
    """指称区间内外字节分布的 JS 散度均值。"""
    inside, outside = [], []
    for i, m in enumerate(msgs):
        v = int(vals[i])
        s0 = block_start
        s1 = min(len(m), s0 + v)
        if s1 - s0 >= 2:
            inside.append(np.frombuffer(m[s0:s1], dtype=np.uint8))
            o1 = min(len(m), s1 + (s1 - s0))
            if o1 > s1:
                outside.append(np.frombuffer(m[s1:o1], dtype=np.uint8))
    if not inside or not outside:
        return 0.0
    return _js_divergence(np.concatenate(inside), np.concatenate(outside))


# ----------------------------------------------------------------------
# 比特级取值提取
# ----------------------------------------------------------------------
def field_values(msgs: Sequence[bytes], kf: KeyField) -> np.ndarray:
    if kf.mask is not None:
        return np.array([(m[kf.start] & kf.mask) >> kf.shift
                         if kf.start < len(m) else -1 for m in msgs])
    return np.array([int.from_bytes(m[kf.start:kf.end], kf.endian)
                     if kf.end < len(m) + 1 else -1 for m in msgs])
