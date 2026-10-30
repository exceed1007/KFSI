#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
字段切分性能评价模块

功能：
  1. 用 tshark PDML（-T pdml）获取参考解析结果中每个字段在报文中的
     字节区间（pos / size），构建 ground truth 字段区间；
  2. 把 PFBI 的字段切分结果（recursive_analyzer 输出的 boundaries）
     标注到每个报文的字节区间上；
  3. 按区间匹配（IoU 阈值）统计精确率 Precision、召回率 Recall、
     F1 得分；
  4. 按不同协议分别导出为表格文件（CSV 与 Excel）。

区间坐标系说明：
  - PFBI 的 boundaries 是在“会话消息矩阵 M”的列坐标上（同一会话各
    报文按列对齐，列号即字节位置）；
  - tshark 的字段 pos 相对“整帧”起点，需要减去该帧 TCP 载荷起始位置
    （tcp.payload 的 pos，或 data 层 pos）换算为“载荷内偏移”，
    再按报文内各帧的拼接顺序累加为“消息内偏移”，与 M 的列一一对应。
"""

import csv
import json
import logging
import re
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# 基础网络层（这些层的字段不作为应用层字段，不进入 ground truth）
_BASE_LAYER_NAMES = {
    'geninfo', 'frame', 'eth', 'ethertype', 'ip', 'ipv6', 'arp', 'icmp',
    'icmpv6', 'vlan', 'radiotap', 'wlan', 'sll', 'nsh', 'mpls', 'tcp',
    'udp', 'tcp.segments', 'data', 'data.data', 'text',
}

# tshark 生成的辅助/元数据字段名（不进入 ground truth）
_GT_EXCLUDED_PREFIXES = (
    'frame.', 'tcp.', 'udp.', 'ip.', 'ipv6.', 'eth.', '_ws.', 'expert',
    'data.', 'text.',
)

# tshark 对比特级（不足 1 字节的）字段以“位图”形式展示 showname，
# 例如 '..1. .... = Destination Specifier: ...'、'0100 .... = Version: 4'。
# 前缀中非 '.' 的 0/1/x 字符个数即该字段占用的比特数（bit）。
_BIT_PATTERN_RE = re.compile(r'^([01xX.\s]+?)\s*=')


class TsharkGroundTruth:
    """基于 tshark PDML 的参考字段区间提取器。"""

    def __init__(self, tshark_path: str = 'tshark', timeout: int = 300):
        self.tshark_path = tshark_path
        self.timeout = timeout
        # 缓存：pcap -> (frame_fields, payload_info)
        self._cache: Dict[str, Tuple[Dict[int, List[dict]], Dict[int, dict]]] = {}

    # ------------------------------------------------------------------
    # 对外接口
    # ------------------------------------------------------------------
    def load(self, pcap_file: str) -> Tuple[Dict[int, List[dict]], Dict[int, dict]]:
        """
        解析 pcap，返回：
          frame_fields: {frame_number: [ {'name','start','end','layer'} ]}
                        start/end 为相对“整帧”起点的字节区间（含端点）
          payload_info: {frame_number: {'payload_pos': int, 'payload_len': int}}
        """
        key = str(pcap_file)
        if key in self._cache:
            return self._cache[key]

        frame_fields: Dict[int, List[dict]] = {}
        payload_info: Dict[int, dict] = {}

        stdout = self._run_pdml(pcap_file)
        if stdout:
            try:
                root = ET.fromstring(stdout)
                for packet in root.findall('packet'):
                    frame_num = None
                    for p in packet.findall('proto'):
                        if p.get('name') == 'frame':
                            fn = p.find("./field[@name='frame.number']")
                            if fn is not None:
                                try:
                                    frame_num = int(fn.get('show'))
                                except (TypeError, ValueError):
                                    frame_num = None
                            break
                    if frame_num is None:
                        continue

                    payload_info[frame_num] = self._extract_payload_info(packet)
                    frame_fields[frame_num] = self._extract_field_intervals(packet)
            except ET.ParseError as e:
                logger.warning(f"解析 PDML 失败 {pcap_file}: {e}")

        self._cache[key] = (frame_fields, payload_info)
        return frame_fields, payload_info

    # ------------------------------------------------------------------
    # tshark 调用
    # ------------------------------------------------------------------
    def _run_pdml(self, pcap_file: str) -> str:
        cmd = [self.tshark_path, '-r', str(pcap_file), '-T', 'pdml']
        try:
            result = subprocess.run(
                cmd, capture_output=True, timeout=self.timeout,
                encoding='utf-8', errors='replace',
            )
        except Exception as e:
            logger.warning(f"tshark PDML 执行失败 {pcap_file}: {e}")
            return ''
        if result.returncode != 0:
            logger.warning(
                f"tshark PDML 返回错误 {pcap_file}: {(result.stderr or '')[:200]}"
            )
            return ''
        return result.stdout or ''

    # ------------------------------------------------------------------
    # PDML 解析
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_payload_info(packet: ET.Element) -> dict:
        """
        获取该帧应用层载荷（即消息体）在整帧中的起始位置与长度。

        取值优先级：
          1. tcp.payload / udp.payload 字段的 pos/size（最准确）；
          2. data.data / data 字段的 pos/size（tshark 归入数据层时）；
          3. 最外层“应用层 proto”的 pos/size 作为回退。
             （UDP 类协议如 BACnet/IP、HART-IP 等没有 tcp.payload，
              若不回退则 payload_len=0，导致消息内坐标换算失效、
              ground truth 区间为空 → P/R/F1 全 0。）
        """
        payload_pos = None
        payload_len = 0

        # 1) tcp.payload / udp.payload / data.*
        for proto in packet.iter('proto'):
            name = proto.get('name')
            if name in ('tcp', 'udp', 'data'):
                for f in proto.iter('field'):
                    if f.get('name') in ('tcp.payload', 'udp.payload',
                                         'data.data', 'data'):
                        try:
                            payload_pos = int(f.get('pos'))
                            payload_len = int(f.get('size') or 0)
                        except (TypeError, ValueError):
                            pass
                        break
                if payload_pos is not None and payload_len > 0:
                    break

        # 2) 回退：最外层应用层 proto 的 pos/size
        if payload_pos is None or payload_len <= 0:
            for proto in packet.iter('proto'):
                name = proto.get('name') or ''
                if name in _BASE_LAYER_NAMES:
                    continue
                try:
                    p = int(proto.get('pos'))
                    s = int(proto.get('size') or 0)
                except (TypeError, ValueError):
                    continue
                if s > 0:
                    payload_pos, payload_len = p, s
                    break

        if payload_pos is None:
            payload_pos = 0
        return {'payload_pos': payload_pos, 'payload_len': payload_len}

    @staticmethod
    def _field_bit_width(child: ET.Element) -> Optional[int]:
        """
        推断字段的位宽（bit）。

        tshark 的 PDML 中 pos/size 的单位是字节，且对比特级（不足 1 字节）
        的子字段，size 会被向上取整为 1（如 1 bit 的 bacnet.control_res1
        也是 size=1），因此无法仅凭 size 判断字段是否只有若干比特。
        但这类字段的 showname 会以“位图”形式给出，例如：
            '..1. .... = Destination Specifier: ...'  → 1 bit
            '0100 .... = Version: 4'                  → 4 bit
            '0000 0010 00.. .... .... .... .... .... = Object Type: device'
                                                      → 10 bit
        前缀中非 '.' 的 0/1/x 字符个数即该字段占用的比特数。

        返回 None 表示该字段不是比特级字段（或无法判定），此时按字节口径处理。
        """
        m = _BIT_PATTERN_RE.match(child.get('showname') or '')
        if not m:
            return None
        return sum(1 for c in m.group(1) if c in '01xX')

    def _extract_field_intervals(self, packet: ET.Element) -> List[dict]:
        """
        递归遍历 PDML，收集应用层字段的字节区间。

        过滤规则：
          - 跳过基础网络层（frame/eth/ip/tcp/udp/data 等）下的字段；
          - 跳过 generated=yes 的合成字段；
          - 跳过 _ws./expert 等辅助字段；
          - 仅保留同时具备 pos 与 size 且 size>0 的字段。

        每个区间在 name/start/end 之外，还附带层级信息（供上层做
        “比特级子字段归并到上一级字节级字段”的统计）：
          - bit_width：字段位宽（bit），None 表示非比特级/无法判定；
          - parent：最近一级“具名字段”的区间摘要
            {'name','start','end','bit_width'}，没有父字段时为 None。
        """
        intervals: List[dict] = []

        def walk(elem: ET.Element, in_base_layer: bool,
                 parent: Optional[dict]):
            for child in elem:
                if child.tag == 'proto':
                    name = child.get('name') or ''
                    is_base = in_base_layer or name in _BASE_LAYER_NAMES
                    # 协议层不是“字段”，父字段信息原样传递
                    walk(child, is_base, parent)
                elif child.tag == 'field':
                    if in_base_layer:
                        continue
                    name = child.get('name') or ''
                    if any(name.startswith(p) for p in _GT_EXCLUDED_PREFIXES):
                        continue
                    if child.get('generated') == 'yes':
                        continue
                    pos = child.get('pos')
                    size = child.get('size')
                    if pos is None or size is None:
                        continue
                    try:
                        pos_i = int(pos)
                        size_i = int(size)
                    except (TypeError, ValueError):
                        continue
                    if size_i <= 0:
                        continue
                    bit_width = self._field_bit_width(child)
                    intervals.append({
                        'name': name,
                        'start': pos_i,
                        'end': pos_i + size_i - 1,
                        'bit_width': bit_width,
                        'parent': parent,
                    })
                    # 字段内部可能还有子字段（嵌套），一并收集
                    # （无名包装字段不作为父字段，父字段信息继续上溯）
                    child_parent = parent
                    if name:
                        child_parent = {
                            'name': name,
                            'start': pos_i,
                            'end': pos_i + size_i - 1,
                            'bit_width': bit_width,
                        }
                    walk(child, in_base_layer, child_parent)

        walk(packet, False, None)
        return intervals


class FieldSplitEvaluator:
    """字段切分性能评价器（P/R/F1 统计与表格导出）。"""

    def __init__(self, config: dict, loader, tshark_gt: Optional[TsharkGroundTruth] = None):
        self.config = config
        self.loader = loader
        self.tshark_gt = tshark_gt or TsharkGroundTruth()

        ev = (config.get('evaluation') or {})
        # 区间匹配 IoU 阈值：>= 该值视为命中
        self.iou_threshold = float(ev.get('iou_threshold', 0.5))
        # 是否把 'data'（未识别/载荷）区间排除在预测结果之外
        self.exclude_data = bool(ev.get('exclude_data_from_prediction', True))
        # 匹配模式：
        #   'coverage'（默认）——覆盖率匹配。参考解析（tshark）的字段粒度
        #     远细于本方法输出的“字段”（tshark 会报告协议内每个子字段），
        #     用 1 对 1 贪心匹配会使一个预测字段只能匹配一个参考字段、
        #     其余全部计为漏检（FN），从而系统性低估召回率。故采用覆盖率
        #     口径：预测区间只要与某参考区间重叠达到 IoU 阈值即视为命中该
        #     参考字段（一个预测可覆盖多个参考字段）；同理，参考字段只要
        #     被任一预测覆盖即计为被召回。
        #   'greedy'——严格 1 对 1 贪心匹配（论文对照口径）。
        self.match_mode = str(ev.get('match_mode', 'coverage')).lower()
        self.output_dir = Path(
            ev.get('output_dir')
            or (Path(config['data']['output_dir']) / 'evaluation')
        )
        self.export_csv = bool(ev.get('export_csv', True))
        self.export_excel = bool(ev.get('export_excel', True))

    # ------------------------------------------------------------------
    # 主流程
    # ------------------------------------------------------------------
    def evaluate_pcap(self, pcap_file: str, protocol_name: str,
                      details: List[dict],
                      source_df) -> dict:
        """
        对单个 pcap 的切分结果做评价。

        参数:
            pcap_file:    样本文件路径（用于读取 tshark ground truth）
            protocol_name: 协议名（作为导出表格的分组键）
            details:      每会话的明细，含
                          {'session_id','matrix','messages','boundaries','packets'}
            source_df:    该 pcap 的报文 DataFrame（含 frame_number/payload）
        返回:
            {
              'protocol': ..., 'source_file': ...,
              'rows': [ {每报文一行：预测区间/参考区间/TP/FP/FN} ],
              'metrics': {'precision','recall','f1','tp','fp','fn','n_messages'},
            }
        """
        frame_fields, payload_info = self.tshark_gt.load(pcap_file)

        rows: List[dict] = []
        total_tp = total_fp = total_fn = 0

        for detail in details:
            session_id = detail.get('session_id', '')
            M = detail.get('matrix')
            messages = detail.get('messages') or []
            boundaries = detail.get('boundaries') or []
            packets = detail.get('packets') or []

            if M is None or getattr(M, 'size', 0) == 0:
                continue

            # M 的行 = 过滤掉 len<4 的消息后的序列（见 build_data_matrix）
            msgs = [m for m in messages if m and len(m) >= 4]
            n_rows = min(M.shape[0], len(msgs))

            # 预测区间（列坐标，所有报文相同）
            pred_intervals = self._predicted_intervals(boundaries)

            # 逐报文（行）比对
            frame_map = self._map_messages_to_frames(msgs, packets)
            for i in range(n_rows):
                frames = frame_map[i] if i < len(frame_map) else []
                gt = self._gt_intervals_for_message(
                    frames, frame_fields, payload_info, len(msgs[i])
                )
                tp, fp, fn = self._match_intervals(pred_intervals, gt,
                                                   self.iou_threshold)
                m = self.compute_metrics(tp, fp, fn)
                total_tp += tp
                total_fp += fp
                total_fn += fn
                rows.append({
                    'protocol': protocol_name,
                    'source_file': Path(pcap_file).name,
                    'session_id': session_id,
                    'message_index': i,
                    'frame_numbers': ','.join(str(f) for f in frames if f),
                    'message_length': len(msgs[i]),
                    'predicted_ranges': self._format_ranges(pred_intervals),
                    'gt_ranges': self._format_ranges(gt),
                    'tp': tp, 'fp': fp, 'fn': fn,
                    'precision': round(m['precision'], 4),
                    'recall': round(m['recall'], 4),
                    'f1': round(m['f1'], 4),
                })

        metrics = self.compute_metrics(total_tp, total_fp, total_fn)
        return {
            'protocol': protocol_name,
            'source_file': Path(pcap_file).name,
            'rows': rows,
            'metrics': {
                'precision': round(metrics['precision'], 4),
                'recall': round(metrics['recall'], 4),
                'f1': round(metrics['f1'], 4),
                'tp': total_tp, 'fp': total_fp, 'fn': total_fn,
                'n_messages': len(rows),
            },
        }

    # ------------------------------------------------------------------
    # 区间转换
    # ------------------------------------------------------------------
    def _predicted_intervals(self, boundaries: List[dict]) -> List[Tuple[int, int]]:
        """
        把 boundaries 转为**左闭右开**的 (start, end) 列表。

        排除口径（exclude_data_from_prediction）：
          仅排除“**未覆盖空隙填充**”字段（`_gap=True`，即分析中未被任何
          模式识别、统一标定为数据/载荷的区域）。这些区域并不是“字段边界
          识别”的产出，故默认不计入预测。

        注意：**不能**按 `type == 'data'` 排除——多机制框架下 `data` 是
        匹配结果的合法回退类型（真实字段语义无法确定时即为 data），
        按 type 排除会把几乎所有预测字段误删，导致 P=R=F1=0。
        """
        out = []
        for b in boundaries or []:
            if self.exclude_data and b.get('_gap'):
                continue
            try:
                s = int(b.get('start'))
                e = int(b.get('end'))
            except (TypeError, ValueError):
                continue
            if e > s >= 0:
                out.append((s, e))
        return sorted(set(out))

    def _map_messages_to_frames(self, messages: List[bytes],
                                packets: List[dict]) -> List[List[int]]:
        """
        把会话消息映射到其来源帧号列表（按与 TCPSessionReassembler 相同的
        PSH 边界规则重放组装过程）。
        """
        if not packets:
            return [[] for _ in messages]
        try:
            framed = self._reassemble_with_frames(packets)
        except Exception as e:
            logger.debug(f"消息-帧映射失败: {e}")
            return [[] for _ in messages]

        # 按时间排序（与 Session.messages 一致）
        framed.sort(key=lambda x: x[0])
        seqs = [item[1] for item in framed]

        mapping: List[List[int]] = []
        used = [False] * len(seqs)
        for msg in messages:
            found = None
            for idx, m in enumerate(seqs):
                if not used[idx] and m == msg:
                    found = idx
                    break
            if found is None:
                mapping.append([])
            else:
                used[found] = True
                mapping.append(framed[found][2])
        return mapping

    @staticmethod
    def _reassemble_with_frames(packets: List[dict]):
        """
        复现 TCPSessionReassembler 的组装逻辑，额外记录每条消息的来源帧号。

        返回 [(first_timestamp, msg_bytes, [frame_numbers]), ...]
        """
        buffers = defaultdict(list)
        completed = []

        def stream_key(p):
            return (p.get('src_ip'), p.get('src_port'),
                    p.get('dst_ip'), p.get('dst_port'))

        sorted_pkts = sorted(packets, key=lambda x: x.get('timestamp', 0))
        for pd in sorted_pkts:
            if not pd.get('is_tcp') or not pd.get('payload'):
                continue
            k = stream_key(pd)
            if any(e.get('seq') == pd.get('seq') for e in buffers[k]):
                continue
            buffers[k].append(pd)

            pkts = buffers[k]
            if len(pkts) < 2:
                continue
            pkts.sort(key=lambda x: x.get('seq', 0))
            consumed = set()
            i, n = 0, len(pkts)
            while i < n:
                group_end = i
                while (group_end + 1 < n and
                       pkts[group_end + 1].get('seq') ==
                       pkts[group_end].get('seq', 0) + len(pkts[group_end].get('payload') or b'')):
                    group_end += 1
                group_start = i
                j = i
                while j <= group_end:
                    if (pkts[j].get('flags', 0) or 0) & 0x08:
                        seg = pkts[group_start:j + 1]
                        msg = b''.join(x.get('payload') or b'' for x in seg)
                        completed.append((
                            seg[0].get('timestamp', 0), msg,
                            [x.get('frame_number') for x in seg],
                        ))
                        for kk in range(group_start, j + 1):
                            consumed.add(kk)
                        group_start = j + 1
                    j += 1
                i = group_end + 1
            if consumed:
                buffers[k] = [p for idx, p in enumerate(pkts)
                              if idx not in consumed]

        # flush
        for k in list(buffers.keys()):
            pkts = buffers[k]
            if not pkts:
                buffers[k] = []
                continue
            pkts.sort(key=lambda x: x.get('seq', 0))
            groups = []
            cur = [pkts[0]]
            for pkt in pkts[1:]:
                if pkt.get('seq') == (cur[-1].get('seq', 0) +
                                      len(cur[-1].get('payload') or b'')):
                    cur.append(pkt)
                else:
                    groups.append(cur)
                    cur = [pkt]
            groups.append(cur)
            for g in groups:
                gs = 0
                for kk, pkt in enumerate(g):
                    if (pkt.get('flags', 0) or 0) & 0x08:
                        seg = g[gs:kk + 1]
                        msg = b''.join(x.get('payload') or b'' for x in seg)
                        if msg:
                            completed.append((
                                seg[0].get('timestamp', 0), msg,
                                [x.get('frame_number') for x in seg],
                            ))
                        gs = kk + 1
                if gs < len(g):
                    seg = g[gs:]
                    msg = b''.join(x.get('payload') or b'' for x in seg)
                    if msg:
                        completed.append((
                            seg[0].get('timestamp', 0), msg,
                            [x.get('frame_number') for x in seg],
                        ))
            buffers[k] = []

        return completed

    def _gt_intervals_for_message(self, frames: List[int],
                                  frame_fields: Dict[int, List[dict]],
                                  payload_info: Dict[int, dict],
                                  msg_len: int) -> List[Tuple[int, int]]:
        """
        把参考字段的“帧内绝对区间”换算为“消息内区间”。

        对消息中的每一帧：
          rel = field.pos - frame.payload_pos（载荷内偏移）
        再按帧在消息中的拼接连加偏移。
        """
        if not frames or msg_len <= 0:
            return []

        intervals: List[Tuple[int, int]] = []
        offset = 0
        for fnum in frames:
            if fnum is None:
                continue
            info = payload_info.get(fnum) or {}
            base = int(info.get('payload_pos') or 0)
            flen = int(info.get('payload_len') or 0)
            for field in frame_fields.get(fnum) or []:
                # tshark PDML 的 pos/size：字段占 [pos, pos+size)（左闭右开）
                s = int(field['start']) - base
                e = int(field['end']) - base + 1   # 统一为左闭右开
                if e <= 0:
                    continue
                s = max(0, s)
                if flen > 0:
                    e = min(e, flen)
                if e <= s:
                    continue
                intervals.append((offset + s, offset + e))
            offset += flen

        # 合并重复区间，并按位置排序；裁剪到消息长度内（左闭右开）
        merged = sorted(set(
            (min(s, msg_len), min(e, msg_len))
            for s, e in intervals if s < msg_len
        ))
        return [iv for iv in merged if iv[1] > iv[0]]

    # ------------------------------------------------------------------
    # 匹配与度量
    # ------------------------------------------------------------------
    def _match_intervals(self, pred: List[Tuple[int, int]],
                         gt: List[Tuple[int, int]],
                         iou_thr: float) -> Tuple[int, int, int]:
        """
        以 IoU 阈值的贪心匹配统计 TP / FP / FN。

        匹配规则：预测区间与参考区间按 IoU 从大到小贪心配对，
        IoU >= iou_thr 计为 TP；未配对的预测为 FP，未配对的参考为 FN。
        """
        if not pred and not gt:
            return 0, 0, 0
        if not pred:
            return 0, 0, len(gt)
        if not gt:
            return 0, len(pred), 0

        pairs = []
        for pi, (ps, pe) in enumerate(pred):
            for gi, (gs, ge) in enumerate(gt):
                # 左闭右开：交集与并集均按半开区间长度计算
                inter = min(pe, ge) - max(ps, gs)
                if inter <= 0:
                    continue
                union = (pe - ps) + (ge - gs) - inter
                iou = inter / union if union > 0 else 0.0
                if iou >= iou_thr:
                    pairs.append((iou, pi, gi))

        if self.match_mode == 'greedy':
            # 严格 1 对 1 贪心匹配（对照口径）
            pairs.sort(reverse=True)
            used_p, used_g = set(), set()
            tp = 0
            for _, pi, gi in pairs:
                if pi in used_p or gi in used_g:
                    continue
                used_p.add(pi)
                used_g.add(gi)
                tp += 1
            fp = len(pred) - len(used_p)
            fn = len(gt) - len(used_g)
            return tp, fp, fn

        # 覆盖率匹配：预测命中任一参考即 TP；参考被任一预测命中即召回
        hit_p = {pi for _, pi, _ in pairs}
        hit_g = {gi for _, _, gi in pairs}
        tp_p = len(hit_p)
        tp_g = len(hit_g)
        fp = len(pred) - tp_p
        fn = len(gt) - tp_g
        # TP 取“被命中的预测数”（用于精确率）与“被命中的参考数”的较大者
        # 作为统一 TP 计数，使 P、R 口径一致且不虚高。
        return max(tp_p, tp_g), fp, fn

    @staticmethod
    def compute_metrics(tp: int, fp: int, fn: int) -> Dict[str, float]:
        """
        由 TP/FP/FN 计算 P / R / F1（宏平均在调用方按汇总值计算）。

        覆盖率匹配下 TP 同时用于精确率分母（TP+FP）与召回率分母（TP+FN），
        故此处以同一 TP 计数给出两项指标，保持口径一致。
        """
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) > 0 else 0.0)
        return {'precision': precision, 'recall': recall, 'f1': f1}

    # ------------------------------------------------------------------
    # 导出
    # ------------------------------------------------------------------
    def export_tables(self, per_protocol: Dict[str, dict]) -> Dict[str, List[str]]:
        """
        按协议分别导出表格文件。

        per_protocol: {protocol_name: {'rows': [...], 'metrics': {...}}}
        返回: {protocol_name: [导出的文件路径, ...]}
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        written: Dict[str, List[str]] = {}

        # 1) 每协议一个明细 CSV
        if self.export_csv:
            for proto, data in per_protocol.items():
                safe = self._safe_name(proto)
                path = self.output_dir / f'{safe}_field_metrics.csv'
                self._write_rows_csv(path, data.get('rows') or [])
                written.setdefault(proto, []).append(str(path))

        # 2) 汇总表（全部协议）
        summary_path = None
        if self.export_csv:
            summary_path = self.output_dir / 'field_metrics_summary.csv'
            self._write_summary_csv(summary_path, per_protocol)
            written.setdefault('_summary', []).append(str(summary_path))

        # 3) Excel：每协议一个 sheet + Summary sheet
        if self.export_excel:
            try:
                xlsx_path = self.output_dir / 'field_metrics.xlsx'
                self._write_excel(xlsx_path, per_protocol)
                written.setdefault('_excel', []).append(str(xlsx_path))
            except Exception as e:
                logger.warning(f"导出 Excel 失败（可改用 CSV）: {e}")

        # 4) 同时保存 JSON（含每报文标注，便于后续分析）
        try:
            json_path = self.output_dir / 'field_annotations.json'
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(per_protocol, f, ensure_ascii=False, indent=1, default=str)
            written.setdefault('_json', []).append(str(json_path))
        except Exception as e:
            logger.warning(f"导出标注 JSON 失败: {e}")

        return written

    @staticmethod
    def _safe_name(name: str) -> str:
        return ''.join(c if (c.isalnum() or c in '-_') else '_' for c in str(name)) or 'unknown'

    @staticmethod
    def _format_ranges(intervals: List[Tuple[int, int]]) -> str:
        """区间统一以左闭右开 [s,e) 形式输出。"""
        return ';'.join(f'[{s},{e})' for s, e in intervals)

    @staticmethod
    def _write_rows_csv(path: Path, rows: List[dict]) -> None:
        if not rows:
            path.write_text('', encoding='utf-8-sig')
            return
        fieldnames = list(rows[0].keys())
        with open(path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def _write_summary_csv(path: Path, per_protocol: Dict[str, dict]) -> None:
        fieldnames = ['protocol', 'source_file', 'n_messages',
                      'tp', 'fp', 'fn', 'precision', 'recall', 'f1']
        with open(path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for proto, data in per_protocol.items():
                m = data.get('metrics') or {}
                writer.writerow({
                    'protocol': proto,
                    'source_file': data.get('source_file', ''),
                    'n_messages': m.get('n_messages', 0),
                    'tp': m.get('tp', 0), 'fp': m.get('fp', 0),
                    'fn': m.get('fn', 0),
                    'precision': m.get('precision', 0.0),
                    'recall': m.get('recall', 0.0),
                    'f1': m.get('f1', 0.0),
                })

    @staticmethod
    def _write_excel(path: Path, per_protocol: Dict[str, dict]) -> None:
        import pandas as pd

        sheets = {}
        summary_rows = []
        for proto, data in per_protocol.items():
            rows = data.get('rows') or []
            main = data.get('metrics') or {}
            # Excel sheet 名要求：<=31 字符、不含 []:*?/\ 等特殊字符
            sheet_name = FieldSplitEvaluator._safe_name(proto)[:31] or 'protocol'
            sheets[sheet_name] = pd.DataFrame(rows)
            summary_rows.append({
                'protocol': proto,
                'source_file': data.get('source_file', ''),
                'n_messages': main.get('n_messages', 0),
                'tp': main.get('tp', 0), 'fp': main.get('fp', 0),
                'fn': main.get('fn', 0),
                'precision': main.get('precision', 0.0),
                'recall': main.get('recall', 0.0),
                'f1': main.get('f1', 0.0),
            })

        summary_df = pd.DataFrame(summary_rows)
        with pd.ExcelWriter(path, engine='openpyxl') as writer:
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            for name, df in sheets.items():
                if name == 'Summary':
                    name = 'Summary2'
                if df.empty:
                    pd.DataFrame([{'info': 'no data'}]).to_excel(
                        writer, sheet_name=name, index=False)
                else:
                    df.to_excel(writer, sheet_name=name, index=False)