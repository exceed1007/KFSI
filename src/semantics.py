# -*- coding: utf-8 -*-
"""典型语义字段检测（借鉴 MSERA 归纳的工控协议典型字段特征，并做了扩展）。

每个检测器只依赖报文本身的数据特征，输出“字段区间 + 语义标签 + 置信度”，
供上层作为**硬约束（锚点）**使用：锚点内部不得再切分，锚点边界必须切分。

支持的语义：
  protocol_id   协议标识（报文起始处全同的定长字节串）
  length        长度字段（由 keyfields 检测，见 :mod:`keyfields`）
  seq           序列号（同方向相邻报文递增 1）
  timestamp     时间戳（与抓包时间线性相关）
  crc           校验和（报文尾部 CRC16/CRC32）
  type          功能码/结构标识（由 keyfields 检测）
  constant      常量字段（在样本内取值恒定）
  payload       载荷区（高熵变长区域）
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

from . import features as F


@dataclass
class SemanticField:
    start: int                      # 全局起始偏移
    end: int                        # 全局结束偏移（左闭右开）
    label: str
    confidence: float
    evidence: Dict[str, float] = field(default_factory=dict)

    @property
    def length(self) -> int:
        return self.end - self.start


# ----------------------------------------------------------------------
# 校验和
# ----------------------------------------------------------------------
def _crc16(data: bytes, poly: int, init: int, refin: bool, refout: bool,
           xorout: int) -> int:
    crc = init
    if refin:
        for b in data:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
    else:
        for b in data:
            crc ^= b << 8
            for _ in range(8):
                crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc ^ xorout


_CRC16_VARIANTS = {
    'ccitt_false': lambda d: _crc16(d, 0x1021, 0xFFFF, False, False, 0),
    'xmodem': lambda d: _crc16(d, 0x1021, 0x0000, False, False, 0),
    'modbus': lambda d: _crc16(d, 0xA001, 0xFFFF, True, True, 0),
    'ibm': lambda d: _crc16(d, 0xA001, 0x0000, True, True, 0),
}

# 参数化的 CRC16 变体，供前缀增量扫描使用：(poly, init, refin, xorout)
_CRC16_PARAMS = {
    'ccitt_false': (0x1021, 0xFFFF, False, 0),
    'xmodem': (0x1021, 0x0000, False, 0),
    'modbus': (0xA001, 0xFFFF, True, 0),
    'ibm': (0xA001, 0x0000, True, 0),
    'ccitt_tcp': (0x8408, 0xFFFF, True, 0xFFFF),
    # DNP3 链路层块校验：CRC-16/DNP，多项式 0x3D65 的**反射形式**为 0xA6BC
    'dnp': (0xA6BC, 0x0000, True, 0xFFFF),
    'dnp_noxor': (0xA6BC, 0x0000, True, 0x0000),
}


def _crc32(data: bytes, prev: int = 0) -> int:
    import zlib
    return zlib.crc32(data, prev) & 0xFFFFFFFF


# ----------------------------------------------------------------------
# 检测器
# ----------------------------------------------------------------------
class SemanticAnalyzer:
    """在一批（已按时间排序、可能双向的）报文上检测典型语义字段。"""

    def __init__(self, cfg: Optional[dict] = None):
        cfg = cfg or {}
        self.min_support = int(cfg.get('min_support', 6))
        self.seq_ratio = float(cfg.get('seq_ratio', 0.85))
        self.crc_ratio = float(cfg.get('crc_ratio', 0.8))
        self.ts_corr = float(cfg.get('ts_corr', 0.95))
        self.max_header = int(cfg.get('max_header', 64))

    # -- 对外接口 ------------------------------------------------------
    def analyze(self, msgs: Sequence[bytes],
                timestamps: Optional[Sequence[float]] = None,
                directions: Optional[Sequence[int]] = None,
                window: Tuple[int, int] | None = None,
                whole_message: bool = True) -> List[SemanticField]:
        """返回窗口内的典型语义字段（全局偏移）。"""
        if not msgs:
            return []
        lo, hi = window if window else (0, max(len(m) for m in msgs))
        sub = [m[lo:hi] for m in msgs]
        n = len(sub)
        if n < 2:
            return []

        M, V = F.to_matrix(sub)
        prof = F.column_profile(M, V)
        L = M.shape[1]

        found: List[SemanticField] = []
        found += self._protocol_id(M, V, prof, lo, L, n)
        found += self._sequence(M, V, lo, L, directions, n)
        if timestamps is not None and whole_message:
            found += self._timestamp(M, V, lo, L, timestamps, n)
        if whole_message:
            found += self._crc(sub, lo, n)
        found += self._constant(M, V, prof, lo, L, n)
        found += self._payload(prof, M, V, lo, L)
        return self._resolve_overlaps(found)

    # -- 协议标识 ------------------------------------------------------
    def _protocol_id(self, M, V, prof, lo, L, n) -> List[SemanticField]:
        if n < 2 or L == 0:
            return []
        # 协议标识取报文起始的**短常量签名**（1~2 字节）。若一味向后延伸，
        # 会把紧随其后的、恰好高字节为常量的长度字段也吞进来
        # （如 TPKT 的 version|reserved|长度高字节 = 03 00 00），其“结束
        # 位置”也就不再是真实字段边界。
        k = 0
        while k < min(L, 2):
            col = M[:, k]
            if len(np.unique(col)) == 1:
                k += 1
            else:
                break
        if k == 0:
            return []
        # 全部报文起始处完全相同的字节串
        ref = M[0, :k]
        if not all(np.array_equal(M[i, :k], ref) for i in range(n)):
            return []
        return [SemanticField(lo, lo + k, 'protocol_id', 0.99,
                              {'const_len': k})]

    # -- 序列号 --------------------------------------------------------
    def _sequence(self, M, V, lo, L, directions, n) -> List[SemanticField]:
        if n < self.min_support:
            return []
        if directions is None:
            groups = [list(range(n))]
        else:
            groups = {}
            for i, d in enumerate(directions):
                groups.setdefault(d, []).append(i)
            groups = list(groups.values())

        best = None
        for size in (1, 2, 4):
            if size > L:
                continue
            for s in range(0, min(L - size + 1, 32)):
                for endian in ('big', 'little'):
                    vals = np.array([int.from_bytes(bytes(M[i, s:s + size]), endian)
                                     for i in range(n)], dtype=np.float64)
                    hit = tot = 0
                    for g in groups:
                        for a, b in zip(g, g[1:]):
                            if V[a, s] and V[b, s]:
                                tot += 1
                                d = vals[b] - vals[a]
                                # 序列号的判据是**严格递增 1**。若允许
                                # “不变”，任何变化缓慢的列（类型码、参数
                                # 码）都会被判成序列号。
                                if d == 1:
                                    hit += 1
                    if tot < self.min_support:
                        continue
                    # 序列号必须在样本内真的“走动”：取值过少时，“相邻差
                    # 为 0 或 1”会被常量列平凡满足（如 MQTT 的 topic 长度）。
                    if len(np.unique(vals)) < 4 or np.ptp(vals) < 4:
                        continue
                    ratio = hit / tot
                    if ratio >= self.seq_ratio and (best is None or ratio > best[0]):
                        best = (ratio, s, size, endian)
        if best is None:
            return []
        ratio, s, size, endian = best
        return [SemanticField(lo + s, lo + s + size, 'seq', float(ratio),
                              {'inc_ratio': ratio})]

    # -- 时间戳 --------------------------------------------------------
    def _timestamp(self, M, V, lo, L, timestamps, n) -> List[SemanticField]:
        if n < self.min_support or len(timestamps) != n:
            return []
        t = np.asarray(timestamps, dtype=np.float64)
        if np.ptp(t) <= 0:
            return []
        best = None
        for size in (4, 8):
            if size > L:
                continue
            for s in range(0, min(L - size + 1, 32)):
                for endian in ('big', 'little'):
                    vals = np.array([int.from_bytes(bytes(M[i, s:s + size]), endian)
                                     for i in range(n)], dtype=np.float64)
                    if np.ptp(vals) <= 0:
                        continue
                    c = np.corrcoef(vals, t)[0, 1]
                    if not np.isfinite(c):
                        continue
                    if abs(c) >= self.ts_corr and (best is None or abs(c) > best[0]):
                        best = (abs(c), s, size)
        if best is None:
            return []
        c, s, size = best
        return [SemanticField(lo + s, lo + s + size, 'timestamp', float(c),
                              {'corr': c})]

    # -- CRC -----------------------------------------------------------
    def _crc(self, sub, lo, n, max_pos: int = 56) -> List[SemanticField]:
        """前缀扫描式校验和识别。

        传统做法只在报文末尾比对 CRC，只能覆盖“整报文一个校验尾”的情形。
        DNP3 这类协议在每个数据块之后都插一个 CRC16，校验值出现在报文
        中部且位置随报文长度变化；为此对每个候选位置 p 检验
        ``msg[p:p+size] == CRC(msg[:p])``，用**前缀增量计算**避免重复扫描，
        复杂度为 O(L) 而非 O(L²)。
        """
        out: List[SemanticField] = []
        if not sub:
            return out
        Lmax = min(max_pos, min(len(m) for m in sub) - 2)
        if Lmax <= 4:
            return out

        def _accept(tbl: Dict[int, set], tot: Dict[int, int],
                    size: int) -> None:
            """判定某个位置的校验匹配是否可信。

            必须排除“退化匹配”：若前缀在各报文间几乎不变，则其校验值也
            几乎不变，此时它与该位置上任何近乎恒定的字节都会自动吻合。
            因此要求校验值本身至少有 3 个不同取值。
            """
            for p_end, vals in tbl.items():
                t = tot.get(p_end, 0)
                if t < self.min_support or len(vals) < 3:
                    continue
                # vals 里存放的是“匹配次数”对应的集合长度无意义，
                # 真正的匹配率由 callers 传入的 hit/tot 计算
                c = len(vals)
                if c / t >= self.crc_ratio:
                    out.append(SemanticField(lo + p_end, lo + p_end + size,
                                             'crc', c / t, {'match': c / t}))

        # ---- CRC16：逐报文增量求前缀 CRC ----
        for name, (poly, init, refin, xorout) in _CRC16_PARAMS.items():
            hitcnt: Dict[int, int] = {}
            tot: Dict[int, int] = {}
            crcvar: Dict[int, set] = {}
            for m in sub:
                crc = init
                for p, b in enumerate(m[:Lmax]):
                    if refin:
                        crc ^= b
                        for _ in range(8):
                            crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
                    else:
                        crc ^= b << 8
                        for _ in range(8):
                            crc = (((crc << 1) ^ poly) & 0xFFFF) if crc & 0x8000 \
                                else ((crc << 1) & 0xFFFF)
                    p_end = p + 1
                    if p_end + 2 > len(m) or p_end < 4:
                        continue
                    v = crc ^ xorout
                    crcvar.setdefault(p_end, set()).add(v)
                    tot[p_end] = tot.get(p_end, 0) + 1
                    if v in ((m[p_end] << 8) | m[p_end + 1],
                             (m[p_end + 1] << 8) | m[p_end]):
                        hitcnt[p_end] = hitcnt.get(p_end, 0) + 1
            for p_end, c in hitcnt.items():
                t = tot.get(p_end, 0)
                if (t >= self.min_support and c / t >= self.crc_ratio
                        and len(crcvar.get(p_end, ())) >= 3):
                    out.append(SemanticField(lo + p_end, lo + p_end + 2, 'crc',
                                             c / t, {'match': c / t,
                                                     'crc16': 1.0}))

        # ---- CRC32（zlib 支持增量）----
        hit32: Dict[int, int] = {}
        tot32: Dict[int, int] = {}
        var32: Dict[int, set] = {}
        for m in sub:
            crc = 0
            for p, b in enumerate(m[:Lmax]):
                crc = _crc32(bytes([b]), crc)
                p_end = p + 1
                if p_end + 4 > len(m) or p_end < 4:
                    continue
                var32.setdefault(p_end, set()).add(crc)
                tot32[p_end] = tot32.get(p_end, 0) + 1
                if crc == int.from_bytes(m[p_end:p_end + 4], 'big'):
                    hit32[p_end] = hit32.get(p_end, 0) + 1
        for p_end, c in hit32.items():
            t = tot32.get(p_end, 0)
            if (t >= self.min_support and c / t >= self.crc_ratio
                    and len(var32.get(p_end, ())) >= 3):
                out.append(SemanticField(lo + p_end, lo + p_end + 4, 'crc',
                                         c / t, {'match': c / t, 'crc32': 1.0}))

        # ---- 单字节校验（累加和取补 / 反码和 / 异或和）----
        hit1: Dict[int, int] = {}
        tot1: Dict[int, int] = {}
        var1: Dict[int, set] = {}
        for m in sub:
            s = 0
            x = 0
            for p, b in enumerate(m[:Lmax]):
                s = (s + b) & 0xFF
                x ^= b
                p_end = p + 1
                if p_end >= len(m) or p_end < 5:
                    continue
                var1.setdefault(p_end, set()).add((s, x))
                tot1[p_end] = tot1.get(p_end, 0) + 1
                obs = m[p_end]
                if obs in ((-s) & 0xFF, (~s) & 0xFF, x):
                    hit1[p_end] = hit1.get(p_end, 0) + 1
        for p_end, c in hit1.items():
            t = tot1.get(p_end, 0)
            if (t >= self.min_support and c / t >= max(self.crc_ratio, 0.9)
                    and len(var1.get(p_end, ())) >= 4):
                out.append(SemanticField(lo + p_end, lo + p_end + 1, 'crc',
                                         c / t, {'match': c / t, 'byte': 1}))
        return out

    # -- 常量字段 ------------------------------------------------------
    def _constant(self, M, V, prof, lo, L, n) -> List[SemanticField]:
        out: List[SemanticField] = []
        j = 0
        while j < L:
            if prof['coverage'][j] < 0.95 or prof['nunique'][j] != 1:
                j += 1
                continue
            k = j
            while (k < L and prof['coverage'][k] >= 0.95
                   and prof['nunique'][k] == 1):
                k += 1
            if 1 <= k - j <= 8:
                out.append(SemanticField(lo + j, lo + k, 'constant', 0.8))
            j = k
        return out

    # -- 载荷 ----------------------------------------------------------
    def _payload(self, prof, M, V, lo, L) -> List[SemanticField]:
        start = F.estimate_payload_start(prof, L)
        if start >= L:
            return []
        # 载荷区必须足够长，避免把头部个别高熵列误判为载荷
        if L - start < 3:
            return []
        return [SemanticField(lo + start, lo + L, 'payload', 0.7,
                              {'entropy': float(prof['nentropy'][start:].mean())})]

    # -- 冲突消解 ------------------------------------------------------
    @staticmethod
    def _resolve_overlaps(fields: List[SemanticField]) -> List[SemanticField]:
        """按语义优先级消解重叠：越“硬”的语义保留在外层。"""
        priority = {'protocol_id': 100, 'crc': 95, 'timestamp': 90, 'seq': 85,
                    'length': 80, 'type': 70, 'constant': 40, 'payload': 30}
        fields = sorted(fields, key=lambda f: (-priority.get(f.label, 0), f.start))
        kept: List[SemanticField] = []
        for f in fields:
            if any(not (f.end <= k.start or f.start >= k.end) for k in kept):
                continue
            kept.append(f)
        return sorted(kept, key=lambda f: f.start)


# ----------------------------------------------------------------------
# 在若干已标注报文上标定“语义 → 是否边界”的统计（供论文表格使用）
# ----------------------------------------------------------------------
def label_stats(fields: Sequence[SemanticField]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in fields:
        out[f.label] = out.get(f.label, 0) + 1
    return out
