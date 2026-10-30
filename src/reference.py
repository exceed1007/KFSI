# -*- coding: utf-8 -*-
"""参考解析（ground truth）与评价指标。

参考字段来自 tshark 的 PDML 输出：解析每个报文的应用层字段及其在
“报文内”的字节区间（左闭右开），并按需给出字段名、位宽与嵌套层级。

口径说明（沿用既有工作的定义，便于横向比较）：
  V1_全部字段    tshark 报出的全部应用层字段（含嵌套/位域）
  V2_字节级      排除位域（bit_width < 8）
  V3_一级字段    只取非嵌套字段（parent 为 None）——**主口径**
  V4_一级字节级  以上两者交集
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from .reference_base import TsharkGroundTruth

GT_SCOPES = ('V1_全部字段', 'V2_字节级', 'V3_一级字段', 'V4_一级字节级')

DEFAULT_LENGTH_PATTERN = r'(^|[._])[A-Za-z0-9_]*len[A-Za-z0-9_]*([._]|$)|length'
DEFAULT_STRUCTURE_PATTERN = (
    r'(^|[._])(type|typeid|types|func|func_code|function|code|cmd|command|'
    r'opcode|opnum|pkt_type|packet_type|msgtype|mesgtyp|message_type|rosctr|'
    r'subfunc|service|serviceid|blocktype)([._]|$)'
)


class ReferenceIndex:
    """tshark 参考字段索引：帧号 -> 字段区间，并换算到“消息内偏移”。"""

    def __init__(self, tshark_path: str = 'tshark', timeout: int = 300):
        self.tshark = TsharkGroundTruth(tshark_path=tshark_path, timeout=timeout)
        self._cache: Dict[str, Tuple[Dict[int, List[dict]], Dict[int, dict]]] = {}

    def load(self, pcap_file: str):
        key = str(pcap_file)
        if key not in self._cache:
            self._cache[key] = self.tshark.load(pcap_file)
        return self._cache[key]

    @staticmethod
    def fields_for_frames(frames: List[int], frame_fields: Dict[int, List[dict]],
                          payload_info: Dict[int, dict], msg_len: int) -> List[dict]:
        """把帧内绝对区间换算为消息内区间，返回 [{name,start,end,bit_width,parent}]。"""
        fields: List[dict] = []
        offset = 0
        for fnum in frames or []:
            if fnum is None:
                continue
            info = payload_info.get(fnum) or {}
            base = int(info.get('payload_pos') or 0)
            flen = int(info.get('payload_len') or 0)
            for f in frame_fields.get(fnum) or []:
                s = int(f['start']) - base
                e = int(f['end']) - base + 1          # 转为左闭右开
                if e <= 0:
                    continue
                s = max(0, s)
                if flen > 0:
                    e = min(e, flen)
                if e <= s:
                    continue
                parent = f.get('parent')
                fields.append({
                    'name': f.get('name') or '',
                    'start': offset + s,
                    'end': offset + e,
                    'bit_width': f.get('bit_width'),
                    'parent': ({'name': parent.get('name'),
                                'start': parent.get('start') - base + offset,
                                'end': parent.get('end') - base + offset + 1}
                               if parent else None),
                })
            offset += flen
        return [f for f in fields if f['start'] < msg_len]

    @staticmethod
    def scope_fields(fields: List[dict], scope: str) -> List[dict]:
        def byte_level(f):
            bw = f.get('bit_width')
            return bw is None or bw >= 8

        if scope == 'V2_字节级':
            return [f for f in fields if byte_level(f)]
        if scope == 'V3_一级字段':
            return [f for f in fields if f.get('parent') is None]
        if scope == 'V4_一级字节级':
            return [f for f in fields
                    if f.get('parent') is None and byte_level(f)]
        return list(fields)

    @staticmethod
    def positions(fields: List[dict], msg_len: int,
                  include_zero: bool = False) -> List[int]:
        out = {int(f['start']) for f in fields if 0 < int(f['start']) < msg_len}
        if include_zero:
            out.add(0)
        return sorted(out)

    @staticmethod
    def length_fields(fields: List[dict],
                      pattern: str = DEFAULT_LENGTH_PATTERN) -> List[dict]:
        rx = re.compile(pattern or DEFAULT_LENGTH_PATTERN, re.I)
        return [f for f in fields if rx.search(f.get('name') or '')]

    @staticmethod
    def structure_fields(fields: List[dict],
                         pattern: str = DEFAULT_STRUCTURE_PATTERN) -> List[dict]:
        rx = re.compile(pattern or DEFAULT_STRUCTURE_PATTERN, re.I)
        return [f for f in fields if rx.search(f.get('name') or '')]


class Metrics:
    """边界位置与字段区间的 P/R/F1。"""

    @staticmethod
    def match_positions(pred: List[int], gt: List[int],
                        tol: int = 1) -> Tuple[int, int, int]:
        """位置口径容差匹配，返回 TP/FP/FN。

        采用一维区间二分匹配（按参考点升序，为其分配窗口内最早的未占用
        预测点），该策略可证达到最大匹配数。旧实现按预测点左到右贪心，
        预测点成簇时靠左的预测会抢走参考点，把本应命中的预测记为 FP，
        系统性低估精度；所有对比方法共用本规则以保证口径一致。
        """
        if not pred or not gt:
            return 0, len(pred), len(gt)
        preds = sorted(pred)
        gts = sorted(gt)
        n = len(preds)
        used = [False] * n
        tp = 0
        k = 0
        for g in gts:
            while k < n and preds[k] < g - tol:
                k += 1
            j = k
            while j < n and preds[j] <= g + tol:
                if not used[j]:
                    used[j] = True
                    tp += 1
                    break
                j += 1
        return tp, len(pred) - tp, len(gt) - tp

    @staticmethod
    def match_intervals_iou(pred: List[Tuple[int, int]],
                            gt: List[Tuple[int, int]],
                            iou_thr: float = 0.5) -> Tuple[int, int, int]:
        """区间口径匹配：IoU≥阈值的区间按 IoU 从大到小一一配对。"""
        if not pred and not gt:
            return 0, 0, 0
        if not pred:
            return 0, 0, len(gt)
        if not gt:
            return 0, len(pred), 0
        cand = []
        for pi, (ps, pe) in enumerate(pred):
            for gi, (gs, ge) in enumerate(gt):
                inter = min(pe, ge) - max(ps, gs)
                if inter <= 0:
                    continue
                union = (pe - ps) + (ge - gs) - inter
                if union > 0 and inter / union >= iou_thr:
                    cand.append((inter / union, pi, gi))
        cand.sort(reverse=True)
        used_p, used_g = set(), set()
        for _, pi, gi in cand:
            if pi in used_p or gi in used_g:
                continue
            used_p.add(pi)
            used_g.add(gi)
        tp = len(used_p)
        return tp, len(pred) - tp, len(gt) - tp

    @staticmethod
    def prf(tp: int, fp: int, fn: int) -> Dict[str, float]:
        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        return {'tp': int(tp), 'fp': int(fp), 'fn': int(fn),
                'precision': p, 'recall': r, 'f1': f1}
