# -*- coding: utf-8 -*-
"""KFSI 主流程：关键字段引导的递归分裂与字段边界推断。

整体流程
--------
1. **关键字段识别**（:mod:`keyfields`）：在当前区域上检测结构标识字段
   （SIF）与长度字段（LF）；典型语义字段（:mod:`semantics`）给出额外锚点。
2. **水平分裂**：按 SIF 取值（含比特掩码）把报文分组，使组内结构同质。
3. **垂直分裂**：按 LF 指称的区间把每条报文切成“块 + 余部”，使变长字段
   不再妨碍后续字段的定偏移比对；分裂可递归，从而逐层剥离多层封装。
4. **字段边界推断**：在不能再分裂的区域上，用证据融合 + 最大后验解码
   给出切分（:mod:`inference`）。
5. **跨结构语义迁移**：结构间共享字段的语义在多个结构上互证；小样本
   结构的语义假设从兄弟结构迁移而来并做本地验证。

实现约定：递归的每一层都以 ``entries = [(msg_index, base, seq_bytes)]``
描述“当前区域”，``seq_bytes`` 是该报文在此区域的字节切片，
``base`` 是切片在报文中的起始偏移。这样同一套代码既能处理“所有报文
起点相同”的区域（水平分裂后、块内），也能处理“起点随变长字段浮动”的
区域（垂直分裂后的余部）。
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

import numpy as np

from . import features as F
from . import inference as I
from . import keyfields as KF
from .semantics import SemanticAnalyzer, SemanticField

DEFAULT_CFG = {
    'max_depth': 3,
    'min_group': 4,
    'min_region': 3,
    'min_cut_coverage': 0.6,
    'sif_split_gain': 0.06,
    'sif_split_score': 0.55,
    'sif_split_div': 0.0,     # 组间结构散度下限（0 = 关闭，见论文局限分析）
    'lf_split_score': 0.35,
    'max_groups': 12,
    'max_width': 256,
    # ---- 消融开关（默认全部启用）----
    'use_semantic': True,     # 典型语义字段锚点
    'use_keymark': 'all',     # 'all' 广度标记关键字段端点
    'shrink_k': 0.0,          # 小样本证据收缩（0 = 关闭）
    'use_horizontal': True,   # 水平分裂
    'use_vertical': True,     # 垂直分裂
    'use_transfer': True,     # 跨结构语义迁移
    'use_width_prior': True,  # 字段宽度先验
    'transfer_max_group': 16,  # 小样本结构的判定上限
    'transfer_min_score': 0.6,  # 参与跨结构迁移的关键字段置信度门槛
    'transfer_max_types': 20,
    'block_mark': 'lf',        # 长度字段指称块内的标记范围
    'decoder': 'map',         # 'map' 最大后验解码 / 'thr' 逐位置阈值
}


@dataclass
class AnalysisResult:
    n_messages: int
    boundaries: List[List[int]]
    key_fields: List[KF.KeyField] = field(default_factory=list)
    anchors: List[SemanticField] = field(default_factory=list)
    structures: List[List[int]] = field(default_factory=list)
    stats: Dict[str, float] = field(default_factory=dict)

    def fields_of(self, i: int, msg_len: int) -> List[Tuple[int, int]]:
        cuts = [0] + [p for p in sorted(set(self.boundaries[i]))
                      if 0 < p < msg_len] + [msg_len]
        return [(cuts[k], cuts[k + 1]) for k in range(len(cuts) - 1)]


class KFSIEngine:
    """关键字段引导的递归分裂引擎。"""

    def __init__(self, cfg: Optional[dict] = None,
                 model: Optional[I.GapModel] = None):
        self.cfg = {**DEFAULT_CFG, **(cfg or {})}
        self.model = model or I.GapModel()
        if 'shrink_k' in self.cfg:
            self.model.shrink_k = float(self.cfg['shrink_k'])
        if 'theta' in self.cfg:
            self.model.theta = float(self.cfg['theta'])
        self.semantic = SemanticAnalyzer(self.cfg.get('semantic') or {})
        self.kf_cfg = self.cfg.get('keyfield') or {}
        self._shared_anchors: List[SemanticField] = []
        self._h_memo: Set[Tuple[int, int, int]] = set()
        self._depth_groups: List[List[int]] = []
        self._top_groups: List[List[int]] = []

    # ------------------------------------------------------------------
    def analyze(self, msgs: Sequence[bytes],
                timestamps: Optional[Sequence[float]] = None,
                directions: Optional[Sequence[int]] = None,
                gt: Optional[Sequence[Set[int]]] = None,
                collector: Optional[list] = None) -> AnalysisResult:
        self._shared_anchors = []
        self._h_memo = set()
        self._depth_groups = []
        self._top_groups = []
        self._gt = gt
        self._collector = collector
        n = len(msgs)
        if n == 0:
            return AnalysisResult(0, [])
        boundaries: List[Set[int]] = [set() for _ in range(n)]

        top_all = self.semantic.analyze(msgs, timestamps=timestamps,
                                        directions=directions,
                                        whole_message=True)
        if not self.cfg.get('use_semantic', True):
            top_all = []
        # 只把“强语义”字段当作硬锚点；protocol_id/constant/payload 只作为
        # 语义解释与软证据，避免把 1 字节常量前缀误当作独立字段边界。
        # 语义证据分两级：CRC 与长度字段的区间可以**直接验证**（校验和
        # 能算出来、长度能闭合），因此作为硬约束直接标记为字段边界；
        # 序列号、时间戳、协议标识等只能说明“这里存在一个语义字段”，
        # 其精确区间仍需数据特征支撑，故仅进入特征层（软约束）与跨结构
        # 迁移的候选来源，不直接产生边界。
        top = [a for a in top_all
               if a.label in ('crc', 'seq', 'timestamp', 'length')]
        # 可直接计算的语义（校验和、长度、严格递增序列号、与抓包时间
        # 线性相关的时间戳）区间是可信的，作为硬约束；协议标识、常量
        # 游程只作软证据。
        hard_labels = tuple(self.cfg.get('hard_anchor_labels',
                                         ('crc', 'length', 'seq',
                                          'timestamp')))
        hard = [a for a in top
                if a.label in hard_labels and a.confidence >= 0.9]
        for a in hard:
            for i, m in enumerate(msgs):
                if 0 < a.start < len(m):
                    boundaries[i].add(a.start)
                if 0 < a.end < len(m):
                    boundaries[i].add(a.end)
        self._shared_anchors.extend([a for a in top_all
                                     if a.label in ('protocol_id', 'length',
                                                    'constant')])

        key_fields: List[KF.KeyField] = []
        entries = [(i, 0, msgs[i]) for i in range(n)]
        self._rec(entries, 0, boundaries, key_fields, top)

        # ---- 第二遍：跨结构语义迁移 ----
        # 水平分裂后，每个结构各自推断关键字段，容易出现“某结构样本多、
        # 检出稳定，某结构样本少、漏检”的不均衡。这里把兄弟结构上已确认
        # 的关键字段拿到本结构上做**本地验证**（长度字段仍然闭合、结构
        # 标识字段取值仍然有限），验证通过才补成边界，实现结构间的语义
        # 互证，而不是无条件的硬迁移。
        if self.cfg.get('use_transfer', True):
            self._cross_structure_transfer(msgs, boundaries, key_fields)

        out_b = [sorted(p for p in b if 0 < p < len(msgs[i]))
                 for i, b in enumerate(boundaries)]
        stats = {
            'n_messages': n,
            'n_key_fields': len(key_fields),
            'n_anchors': len(top),
            'n_structures': len(self._depth_groups),
            'avg_boundaries': float(np.mean([len(b) for b in out_b])),
        }
        return AnalysisResult(n_messages=n, boundaries=out_b,
                              key_fields=key_fields[:64], anchors=top,
                              structures=self._depth_groups or [list(range(n))],
                              stats=stats)

    # ------------------------------------------------------------------
    # 递归主体
    # ------------------------------------------------------------------
    def _rec(self, entries: List[Tuple[int, int, bytes]], depth: int,
             boundaries: List[Set[int]], key_fields: List[KF.KeyField],
             anchors: List[SemanticField], context: str = 'root') -> None:
        min_region = int(self.cfg['min_region'])
        entries = [(i, b, s) for (i, b, s) in entries if len(s) >= min_region]
        if len(entries) < 3:
            return

        seqs = [e[2] for e in entries]
        # 无法再分裂的区域（到达深度上限 / 样本太少 / 全部相同）仍需收尾，
        # 否则父层“只为分裂键打点”的策略会让这些区域一个边界都拿不到。
        if depth > int(self.cfg['max_depth']) or len(entries) < 4 \
                or len(set(seqs)) == 1:
            self._finalize(entries, boundaries, key_fields)
            return

        M, V = F.to_matrix(seqs)
        L = M.shape[1]

        common_base = len({e[1] for e in entries}) == 1
        base0 = entries[0][1]

        # ---- 小样本结构：迁移 + 本地验证 ----
        if (len(entries) < int(self.cfg['transfer_max_group']) and common_base
                and self.cfg.get('use_transfer', True)):
            # 迁移得到的语义只用于“给边界”，不作为软锚点参与“区间内部
            # 禁止切分”——报文起始处的常量前缀经常横跨多个真实字段
            # （如 TPKT 的 version/reserved/长度高字节），若据此封闭区间
            # 反而会把真实边界压掉。
            adopted = self._transfer_anchors(entries, M, V, base0, depth)
            for a in adopted:
                self._mark(boundaries, entries, a.start, a.end)

        # ---- 关键字段识别（区域局部坐标）----
        lf = KF.detect_length_fields(seqs, window=(0, L), cfg=self.kf_cfg)
        exclude = [(f.start, f.end) for f in lf]
        sif = KF.detect_structure_fields(seqs, window=(0, L),
                                         cfg=self.kf_cfg, exclude=exclude)

        for f in lf + sif:
            gf = self._globalize(f, base0)
            if not any(abs(gf.start - g.start) < 1 and gf.label == g.label
                       for g in key_fields):
                key_fields.append(gf)

        # ---- 决策：水平分裂 > 垂直分裂 > 叶子推断 ----
        # 端点标记的时机很关键：只有“结构同质”的区域上检出的关键字段，
        # 其端点才对全部报文成立。若本区域还要继续分裂，则只标记被用作
        # 分裂键的那个字段（它在所有结构里位于同一偏移），其余候选留给
        # 各子结构重新识别；否则会把 A 结构的字段端点错标到 B 结构报文
        # 的大字段内部（S7comm 中 COTP 参数区与 S7 头部重叠即属此类）。
        mark = self.cfg.get('use_keymark', True)
        # 长度字段所指称的块（block）内部通常是同一个变长字段的内容，
        # 在其中检出“结构标识字段”多半是内容字节的巧合；因此块内只把
        # 长度字段当作边界锚点，结构标识字段仅在根/余部区域生效。
        if mark is True or mark == 'all':
            picked = lf if (context == 'block' and
                            self.cfg.get('block_mark', 'lf') == 'lf') else lf + sif
            for f in picked:
                self._mark_field(boundaries, entries, base0, f)
        elif mark in ('both', 'lf', 'sif'):
            for f in lf + sif:
                if self._markable(f, mark):
                    self._mark_field(boundaries, entries, base0, f)
        best_sif = self._pick_sif(sif) if self.cfg.get('use_horizontal', True) else None
        if best_sif is not None and len(entries) >= 2 * int(self.cfg['min_group']):
            if mark == 'split':
                self._mark_field(boundaries, entries, base0, best_sif)
            if self._horizontal_split(entries, best_sif, depth, boundaries,
                                      key_fields, anchors, base0):
                return
        best_lf = self._pick_lf(lf) if self.cfg.get('use_vertical', True) else None
        if best_lf is not None:
            if mark == 'split':
                self._mark_field(boundaries, entries, base0, best_lf)
            if self._vertical_split(entries, best_lf, depth, boundaries,
                                    key_fields, anchors):
                return
        if mark == 'split':
            for f in lf + sif:
                self._mark_field(boundaries, entries, base0, f)
        region_anchors = list(anchors) + [
            SemanticField(base0 + f.start, base0 + f.end, f.label, f.score)
            for f in lf + sif]
        self._leaf(entries, M, V, boundaries, region_anchors, base0)

    # ------------------------------------------------------------------
    def _mark(self, boundaries, entries, g_start: int, g_end: int) -> None:
        for (i, base, seq) in entries:
            for pos in (g_start, g_end):
                local = pos - base
                if 0 < local < len(seq):
                    boundaries[i].add(pos)

    def _cross_structure_transfer(self, msgs, boundaries, key_fields) -> None:
        groups = [g for g in self._top_groups if len(g) >= int(self.cfg['min_group'])]
        if len(groups) < 2:
            return
        cand = [f for f in key_fields
                if f.score >= float(self.cfg.get('transfer_min_score', 0.6))]
        if not cand:
            return
        for g in groups:
            idx = [i for i in g if i < len(msgs)]
            if len(idx) < int(self.cfg['min_group']):
                continue
            for f in cand:
                if not self._validate_locally(msgs, idx, f):
                    continue
                for i in idx:
                    m = msgs[i]
                    for pos in (f.start, f.end):
                        if 0 < pos < len(m):
                            boundaries[i].add(pos)

    def _validate_locally(self, msgs, idx, f: KF.KeyField) -> bool:
        """在给定报文子集上验证一个关键字段假设是否仍然成立。"""
        if f.end <= f.start:
            return False
        n = len(idx)
        ok = 0
        res = []
        vals = []
        for i in idx:
            m = msgs[i]
            if f.end > len(m):
                continue
            ok += 1
            v = int.from_bytes(m[f.start:f.end], 'big')
            vals.append(v)
            res.append(len(m) - v)
        if ok < max(4, int(0.6 * n)):
            return False
        if f.label == 'length':
            if not vals or np.ptp(vals) == 0:
                return False
            dev = np.abs(np.array(res) - float(np.median(res)))
            return float(np.mean(dev <= 1.0)) >= 0.9
        # 结构标识字段：取值必须有限且覆盖充分
        u = len(set(vals))
        return 2 <= u <= int(self.cfg.get('transfer_max_types', 20))

    def _mark_field(self, boundaries, entries, base0: int,
                    f: KF.KeyField) -> None:
        """把一个关键字段的端点记为该区域的边界。"""
        if f.mask is not None:
            # 比特级结构标识字段只标记其起始字节：它通常只是所在字节
            # 内部的一个标志位，不该在字节之后再造一个边界。
            self._mark(boundaries, entries, base0 + f.start, base0 + f.start)
        else:
            self._mark(boundaries, entries, base0 + f.start, base0 + f.end)

    def _markable(self, f: KF.KeyField, mode) -> bool:
        """关键字段的端点是否足够可信、可以直接当成字段边界。

        结构标识字段有两种成立方式：真的解释了结构（``struct_ev`` 高），
        或者只是一个低熵的“类型码”列（仅凭取值集中）。后者在小样本子
        区域里极易蒙对（载荷里某个字节恰好在 20 条报文里相同），若一律
        标记就会在载荷区造出成片的伪边界，因此对纯类型码证据要求更高
        的分数门槛。
        """
        if f.label == 'length':
            return mode in ('all', 'both', 'lf') and f.score >= float(
                self.cfg.get('mark_lf_score', 0.45))
        if mode not in ('all', 'both', 'sif'):
            return False
        if f.score < float(self.cfg.get('mark_sif_score', 0.60)):
            return False
        if float(f.meta.get('struct_ev', 1.0)) < 0.2:
            return f.score >= float(self.cfg.get('mark_sif_weak_score', 0.86))
        return True

    def _finalize(self, entries, boundaries, key_fields) -> None:
        """不可再分裂区域的收尾：识别并标记关键字段，必要时再做叶子解码。"""
        seqs = [e[2] for e in entries]
        M, V = F.to_matrix(seqs)
        L = M.shape[1]
        base0 = entries[0][1]
        lf = KF.detect_length_fields(seqs, window=(0, L), cfg=self.kf_cfg)
        exclude = [(f.start, f.end) for f in lf]
        sif = KF.detect_structure_fields(seqs, window=(0, L),
                                         cfg=self.kf_cfg, exclude=exclude)
        for f in lf + sif:
            gf = self._globalize(f, base0)
            if not any(abs(gf.start - g.start) < 1 and gf.label == g.label
                       for g in key_fields):
                key_fields.append(gf)
        if self.cfg.get('use_keymark', True):
            for f in lf + sif:
                self._mark_field(boundaries, entries, base0, f)
        if len(entries) >= 4 and len(set(seqs)) > 1 and L >= 3:
            region_anchors = [
                SemanticField(base0 + f.start, base0 + f.end, f.label, f.score)
                for f in lf + sif]
            self._leaf(entries, M, V, boundaries, region_anchors, base0)

    def _leaf(self, entries, M, V, boundaries, anchors, base0: int) -> None:
        N, L = M.shape
        if L < 3:
            return
        prof = F.column_profile(M, V)
        str_run = F.printable_runs(M, V)
        payload_start = F.estimate_payload_start(prof, L)
        local_anchors = [(a.start, a.end) for a in anchors
                         if base0 <= a.start < base0 + L]
        feats = I.gap_features(M, V, prof, str_run, payload_start,
                               local_anchors, lo=base0)
        if self._collector is not None and self._gt is not None:
            for p in range(1, L):
                hit = [1.0 if (base + p) in self._gt[i] else 0.0
                       for (i, base, seq) in entries if base + p < base + len(seq)]
                if hit:
                    self._collector.append((dict(feats[p]), float(np.mean(hit))))
        # 只有“足够多报文都覆盖到”的列才允许切分：变长尾部的低覆盖列
        # 属于个别长报文的内容，不应产生边界。
        min_cov = float(self.cfg.get('min_cut_coverage', 0.6))
        ok = np.where(prof['coverage'] >= min_cov)[0]
        Lc = int(ok.max()) + 1 if ok.size else 0
        z = self.model.logit(feats, n_samples=N)
        if self.cfg.get('decoder') == 'thr':
            cuts = [p for p in range(1, Lc) if z[p] - self.model.theta > 0.0]
            for p in cuts:
                for (i, base, seq) in entries:
                    pos = base + p
                    if 0 < pos < len(seq) + base:
                        boundaries[i].add(pos)
            return
        if not self.cfg.get('use_width_prior', True):
            import copy
            mdl = copy.copy(self.model)
            mdl.width_logprob = {w: 0.0 for w in self.model.width_logprob}
            cuts = mdl.decode(z, Lc, max_width=int(self.cfg['max_width']))
        else:
            cuts = self.model.decode(z, Lc, max_width=int(self.cfg['max_width']))
        for p in cuts:
            for (i, base, seq) in entries:
                pos = base + p
                if 0 < pos < len(seq) + base:
                    boundaries[i].add(pos)

    # ------------------------------------------------------------------
    # 水平分裂
    # ------------------------------------------------------------------
    def _horizontal_split(self, entries, kf: KF.KeyField, depth, boundaries,
                          key_fields, anchors, base0) -> bool:
        key = (base0, kf.start, kf.size)
        if key in self._h_memo:
            return False
        vals = []
        for (i, base, seq) in entries:
            if kf.mask is not None:
                vals.append((seq[kf.start] & kf.mask) >> kf.shift
                            if kf.start < len(seq) else -1)
            else:
                vals.append(int.from_bytes(seq[kf.start:kf.end], 'big')
                            if kf.end <= len(seq) else -1)
        buckets: Dict[int, List[Tuple[int, int, bytes]]] = defaultdict(list)
        for e, v in zip(entries, vals):
            buckets[v].append(e)
        if len(buckets) < 2 or len(buckets) > int(self.cfg['max_groups']):
            return False
        big = [g for g in buckets.values() if len(g) >= int(self.cfg['min_group'])]
        if len(big) < 2:
            return False
        self._h_memo.add(key)
        for g in big:
            self._depth_groups.append([e[0] for e in g])
            if depth == 0:
                self._top_groups.append([e[0] for e in g])
            self._rec(g, depth + 1, boundaries, key_fields, anchors,
                      context='struct')
        return True

    # ------------------------------------------------------------------
    # 垂直分裂
    # ------------------------------------------------------------------
    def _vertical_split(self, entries, kf: KF.KeyField, depth, boundaries,
                        key_fields, anchors) -> bool:
        min_region = int(self.cfg['min_region'])
        before, block, tail = [], [], []
        for (i, base, seq) in entries:
            if kf.end > len(seq):
                continue
            v = int.from_bytes(seq[kf.start:kf.end], kf.endian)
            if v <= 0:
                continue
            blk_end = kf.end + v
            if blk_end > len(seq):
                blk_end = len(seq)
            if kf.start >= min_region:
                before.append((i, base, seq[:kf.start]))
            if blk_end - kf.end >= 1:
                block.append((i, base + kf.end, seq[kf.end:blk_end]))
            if len(seq) - blk_end >= min_region:
                tail.append((i, base + blk_end, seq[blk_end:]))
            if 0 < base + blk_end < base + len(seq):
                boundaries[i].add(base + blk_end)

        if len(block) < max(3, int(self.cfg['min_group']) // 2):
            return False

        if len(before) >= 4:
            self._rec(before, depth + 1, boundaries, key_fields, anchors,
                      context='before')
        # 块内：优先再做一次关键字段识别（嵌套长度字段/嵌套结构标识）
        if len(block) >= 4:
            self._rec(block, depth + 1, boundaries, key_fields, anchors,
                      context='block')
        if len(tail) >= 4:
            self._rec(tail, depth + 1, boundaries, key_fields, anchors,
                      context='tail')
        return True

    # ------------------------------------------------------------------
    # 关键字段选取
    # ------------------------------------------------------------------
    def _pick_sif(self, sif: List[KF.KeyField]) -> Optional[KF.KeyField]:
        best = None
        div_min = float(self.cfg.get('sif_split_div', 0.0))
        for f in sif:
            if float(f.meta.get('gain', 0.0)) < float(self.cfg['sif_split_gain']):
                continue
            if float(f.meta.get('divergence', 0.0)) < div_min:
                continue
            if f.score < float(self.cfg['sif_split_score']):
                continue
            if best is None or f.score > best.score:
                best = f
        return best

    def _pick_lf(self, lf: List[KF.KeyField]) -> Optional[KF.KeyField]:
        best = None
        for f in lf:
            if f.score < float(self.cfg['lf_split_score']):
                continue
            if best is None or f.score > best.score:
                best = f
        return best

    # ------------------------------------------------------------------
    # 跨结构语义迁移
    # ------------------------------------------------------------------
    def _transfer_anchors(self, entries, M, V, base0, depth) -> List[SemanticField]:
        """小样本结构：从已识别的共享语义中迁移假设并做本地验证。"""
        adopted: List[SemanticField] = []
        seqs = [e[2] for e in entries]
        n = len(seqs)
        if n < 3:
            return adopted
        for a in self._shared_anchors:
            s = a.start - base0
            e = a.end - base0
            if s < 0 or e <= s:
                continue
            vals = [q[s:e] for q in seqs if e <= len(q)]
            if len(vals) < 3:
                continue
            # 只迁移“能在本地被独立验证”的语义：协议标识（本地仍全同）
            # 与长度字段（本地仍闭合）。常量游程不迁移——它在不同结构里
            # 的位置并不稳定，迁过去往往只是把兄弟结构的常量段硬贴过来。
            if a.label == 'protocol_id':
                if len(set(vals)) == 1:
                    adopted.append(SemanticField(a.start, a.end, a.label, 0.9,
                                                 {'transfer': 1.0}))
            elif a.label == 'length':
                nums, res = [], []
                for q in seqs:
                    if e > len(q):
                        continue
                    v = int.from_bytes(q[s:e], 'big')
                    nums.append(v)
                    res.append(len(q) - v)
                if nums and np.ptp(nums) > 0 and np.std(res) <= 2.0:
                    adopted.append(SemanticField(a.start, a.end, 'length', 0.85,
                                                 {'transfer': 1.0}))
        for a in adopted:
            if not any(abs(a.start - b.start) < 1 and a.label == b.label
                       for b in self._shared_anchors):
                self._shared_anchors.append(a)
        return adopted

    @staticmethod
    def _globalize(f: KF.KeyField, base: int) -> KF.KeyField:
        return KF.KeyField(start=f.start + base, size=f.size, label=f.label,
                           score=f.score, endian=f.endian, mask=f.mask,
                           shift=f.shift, meta=dict(f.meta))
