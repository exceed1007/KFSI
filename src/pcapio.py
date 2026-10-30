#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
数据加载与预处理模块
支持TCP流重组
"""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
from collections import defaultdict
import numpy as np
import pandas as pd
import logging

from scapy.all import rdpcap, IP, TCP, UDP, Raw
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

logger = logging.getLogger(__name__)


class Packet:
    """报文数据结构"""
    def __init__(self, data: Dict):
        self.timestamp = data.get('timestamp', 0)
        self.src_ip = data.get('src_ip')
        self.dst_ip = data.get('dst_ip')
        self.src_port = data.get('src_port')
        self.dst_port = data.get('dst_port')
        self.protocol = data.get('protocol')
        self.payload = data.get('payload', b'')
        self.seq = data.get('seq', 0)
        self.ack = data.get('ack', 0)
        self.flags = data.get('flags', 0)
        self.is_tcp = data.get('is_tcp', False)
        self.length = len(self.payload) if self.payload else 0


class TCPSessionReassembler:
    """
    TCP会话重组器
    将同一TCP连接中的分片数据重组为完整的应用层报文

    说明：
    - 使用四元组 (src_ip, src_port, dst_ip, dst_port) 区分方向，
      同一TCP连接的两个方向分别缓存，互不干扰。
    - 重组时仅在同一流方向内合并序列号连续的数据段；
      即使两个同方向报文中间穿插了反向报文（如 a→b、b→a、a→b），
      也会按 PSH 边界独立切分，不会被错误合并。
    - 带 PSH 标志（应用层消息边界）的数据段才会输出完整消息；
      未完成的消息保留在缓冲区等待后续分片。
    """

    def __init__(self):
        # 存储每个方向的数据缓冲区
        # key: (src_ip, src_port, dst_ip, dst_port) 或反向
        self.buffers = defaultdict(list)
        self.reassembled_messages = []
        # 已输出完整消息记录：(消息首包时间戳, 消息内容)
        # 用于最后按真实时序统一排序
        self.completed_messages: List[Tuple[float, bytes]] = []

    def _stream_key(self, packet: Packet) -> tuple:
        """生成流的四元组key（区分方向）"""
        return (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port)

    def add_packet(self, packet: Packet) -> List[bytes]:
        """
        添加一个TCP包到重组器
        返回：如果检测到完整的应用层报文，返回重组后的报文列表
        """
        if not packet.is_tcp or not packet.payload:
            return []

        # 确定流方向
        stream_key = self._stream_key(packet)

        # 检查是否是重传或乱序包
        if self._is_duplicate_or_retransmit(packet, stream_key):
            return []

        # 添加到缓冲区
        self.buffers[stream_key].append(packet)

        # 尝试重组完整的应用层消息
        complete_messages = self._try_reassemble(stream_key)

        return complete_messages

    def get_sorted_messages(self) -> List[bytes]:
        """
        返回所有已输出完整消息，按消息首包时间戳（真实时序）排序。
        取回后清空内部记录，避免重复获取。
        """
        self.completed_messages.sort(key=lambda x: x[0])
        messages = [msg for _, msg in self.completed_messages]
        self.completed_messages = []
        return messages

    def _is_duplicate_or_retransmit(self, packet: Packet, stream_key: tuple) -> bool:
        """检查是否是重复包或重传包"""
        for existing in self.buffers.get(stream_key, []):
            if existing.seq == packet.seq:
                return True
        return False

    def _try_reassemble(self, stream_key: tuple) -> List[bytes]:
        """
        尝试从缓冲区重组完整的应用层消息

        重组规则：
        1. 仅在同一流方向（stream_key）内按序列号合并数据；
        2. 仅当数据段之间序列号连续（无间隙/丢包）时才拼接；
        3. 带 PSH 标志的数据段是应用层消息边界：

           - 若数据段带 PSH，则该段（连同其之前 seq 连续的未输出段）
             构成一条完整应用层消息，立即输出；
           - 连续两个带 PSH 的段（即使 seq 连续）也会被切分为
             两条独立消息，避免将交替传输中的同方向报文错误合并。
        4. 未形成完整消息的数据保留在缓冲区，等待后续分片。
        """
        packets = self.buffers[stream_key]
        if len(packets) < 2:
            return []

        # 按序列号排序
        packets.sort(key=lambda x: x.seq)

        complete_messages = []
        consumed_indices = set()

        i = 0
        n = len(packets)
        while i < n:
            # 找到从 i 开始的 seq 连续分组（无间隙/丢包）
            group_end = i
            while (group_end + 1 < n and
                   packets[group_end + 1].seq == packets[group_end].seq + len(packets[group_end].payload)):
                group_end += 1

            # 在连续分组内按 PSH 边界切分完整消息
            group_start = i
            j = i
            while j <= group_end:
                if packets[j].flags & 0x08:  # PSH flag：应用层消息边界
                    # 从 group_start 到 j 的数据构成一条完整消息
                    msg = b''.join(p.payload for p in packets[group_start:j + 1])
                    complete_messages.append(msg)
                    # 记录消息及其首包时间戳，用于最终按真实时序统一排序
                    self.completed_messages.append((packets[group_start].timestamp, msg))
                    for k in range(group_start, j + 1):
                        consumed_indices.add(k)
                    group_start = j + 1
                j += 1

            # group_start 之后到 group_end 的数据没有 PSH，保留在缓冲区
            i = group_end + 1

        # 移除已输出消息消费的包
        if complete_messages:
            remaining = [p for idx, p in enumerate(packets) if idx not in consumed_indices]
            self.buffers[stream_key] = remaining

        return complete_messages

    def flush(self) -> List[bytes]:
        """
        刷新所有缓冲区，返回所有未完成的消息。
        按 seq 连续性分组，组内再按 PSH 边界切分（与 _try_reassemble 一致），
        保证独立 PSH 报文即使 seq 连续也不会被合并。
        """
        all_messages = []
        for stream_key in list(self.buffers.keys()):
            packets = self.buffers[stream_key]
            if not packets:
                self.buffers[stream_key] = []
                continue
            packets.sort(key=lambda x: x.seq)

            # 按 seq 连续性分组（无间隙/丢包）
            groups = []
            current_group = [packets[0]]
            for pkt in packets[1:]:
                if pkt.seq == current_group[-1].seq + len(current_group[-1].payload):
                    current_group.append(pkt)
                else:
                    groups.append(current_group)
                    current_group = [pkt]
            groups.append(current_group)

            # 每个连续分组内按 PSH 边界切分
            for group in groups:
                group_start = 0
                for k, pkt in enumerate(group):
                    if pkt.flags & 0x08:  # PSH flag：应用层消息边界
                        msg = b''.join(p.payload for p in group[group_start:k + 1])
                        if msg:
                            all_messages.append(msg)
                            # 记录消息及其首包时间戳，用于最终按真实时序统一排序
                            self.completed_messages.append((group[group_start].timestamp, msg))
                        group_start = k + 1
                # 组内剩余无 PSH 的数据也输出（flush 语义：会话结束，全部输出）
                if group_start < len(group):
                    msg = b''.join(p.payload for p in group[group_start:])
                    if msg:
                        all_messages.append(msg)
                        self.completed_messages.append((group[group_start].timestamp, msg))
            self.buffers[stream_key] = []
        return all_messages


class Session:
    """会话数据结构"""
    def __init__(self, session_id: str, packets: List[Dict], reassembled: bool = False):
        self.session_id = session_id
        self.packets = packets  # 原始包列表
        self.reassembled = reassembled
        self.messages = []  # 重组后的应用层消息
        
        # 如果是TCP且需要重组，执行重组
        if self._is_tcp_session() and not reassembled:
            self._reassemble_tcp_session()
    
    def _is_tcp_session(self) -> bool:
        """检查是否是TCP会话"""
        for packet in self.packets:
            if packet.get('is_tcp', False):
                return True
        return False
    
    def _reassemble_tcp_session(self):
        """重组TCP会话中的应用层消息
        幂等：重复调用不会导致消息重复追加。
        """
        # 幂等保护：每次重组前重置，避免重复调用导致消息翻倍
        self.messages = []

        reassembler = TCPSessionReassembler()

        # 按时间顺序处理包
        sorted_packets = sorted(self.packets, key=lambda x: x.get('timestamp', 0))

        for packet_data in sorted_packets:
            packet = Packet(packet_data)
            reassembler.add_packet(packet)

        # 刷新剩余数据
        reassembler.flush()

        # 统一按消息首包时间戳（真实时序）排序取回
        self.messages = reassembler.get_sorted_messages()

        self.reassembled = True

        if self.messages:
            logger.debug(f"TCP会话 {self.session_id} 重组: {len(self.packets)} 个包 -> {len(self.messages)} 条应用层消息")
    
    def get_messages(self) -> List[bytes]:
        """获取应用层消息列表"""
        if self.reassembled:
            return self.messages
        # 如果未重组，返回每个包的载荷
        return [p.get('payload', b'') for p in self.packets if p.get('payload')]


class ProtocolDataLoader:
    """协议数据加载器"""

    # 每个会话最多保留的报文数（按时间排序后的前N个报文）。
    # 说明：默认不再截断（0 / None 表示不限制）。原先硬编码 100 会使 DCERPC
    # (318 条) 与 S7comm (302 条) 等大样本被截去 2/3 报文，导致评价与论文
    # 报告的样本规模不一致；如需限制可在 config['data'] 中设置。
    MAX_PACKETS_PER_SESSION = 0

    def __init__(self, config):
        self.config = config
        self.ascii_threshold = config['feature']['ascii_threshold']
        
    def load_pcap(self, filepath: str) -> pd.DataFrame:
        """
        加载pcap文件，返回报文DataFrame

        注意：入参必须是**单个样本文件**。若传入目录，rdpcap 在 Windows 上
        会抛出 PermissionError: [Errno 13] Permission denied（尝试以文件方式
        打开目录）。此处显式拦截并给出明确提示，避免难以理解的权限错误。
        """
        p = Path(filepath)
        if p.is_dir():
            logger.error(
                f"load_pcap 需要的是单个样本文件，但收到的是目录: {filepath}\n"
                "请改为传入具体文件（如 xxx.pcap），或使用上层接口的目录模式"
                "（analyze/evaluate 已支持目录，会自动展开其中所有样本）。"
            )
            return pd.DataFrame()
        if not p.exists():
            logger.error(f"样本文件不存在: {filepath}")
            return pd.DataFrame()

        try:
            packets = rdpcap(filepath)
            data = []
            
            for idx, pkt in enumerate(packets):
                packet_info = {
                    'timestamp': pkt.time,
                    'len': len(pkt),
                    'frame_number': idx + 1,  # tshark帧号（1-based），用于tshark字段定位
                    'src_ip': None,
                    'dst_ip': None,
                    'src_port': None,
                    'dst_port': None,
                    'protocol': None,
                    'payload': None,
                    'seq': 0,
                    'ack': 0,
                    'flags': 0,
                    'is_tcp': False
                }
                
                # 提取IP层信息
                if IP in pkt:
                    ip_layer = pkt[IP]
                    packet_info['src_ip'] = ip_layer.src
                    packet_info['dst_ip'] = ip_layer.dst
                    packet_info['protocol'] = ip_layer.proto
                    
                    # 提取传输层信息
                    if TCP in pkt:
                        tcp_layer = pkt[TCP]
                        packet_info['src_port'] = tcp_layer.sport
                        packet_info['dst_port'] = tcp_layer.dport
                        packet_info['seq'] = tcp_layer.seq
                        packet_info['ack'] = tcp_layer.ack
                        packet_info['flags'] = tcp_layer.flags
                        packet_info['is_tcp'] = True
                    elif UDP in pkt:
                        udp_layer = pkt[UDP]
                        packet_info['src_port'] = udp_layer.sport
                        packet_info['dst_port'] = udp_layer.dport
                
                # 提取载荷
                if Raw in pkt:
                    packet_info['payload'] = bytes(pkt[Raw])
                
                data.append(packet_info)
            
            return pd.DataFrame(data)
            
        except Exception as e:
            logger.error(f"加载pcap文件失败 {filepath}: {str(e)}")
            return pd.DataFrame()
    
    def extract_sessions(self, df: pd.DataFrame) -> List[Session]:
        """
        按五元组提取会话，支持TCP流重组
        """
        sessions_dict = {}
        
        for idx, row in df.iterrows():
            if row['src_ip'] is None or row['dst_ip'] is None:
                continue
            
            # 构建五元组（规范化排序，忽略方向）
            src_ip, dst_ip = row['src_ip'], row['dst_ip']
            src_port, dst_port = row['src_port'], row['dst_port']
            protocol = row['protocol']
            
            # 确保五元组唯一性（忽略方向）
            if src_ip > dst_ip or (src_ip == dst_ip and src_port > dst_port):
                key = (dst_ip, dst_port, src_ip, src_port, protocol)
            else:
                key = (src_ip, src_port, dst_ip, dst_port, protocol)
            
            if key not in sessions_dict:
                sessions_dict[key] = []
            
            sessions_dict[key].append(row.to_dict())
        
        sessions = []
        for key, packets in sessions_dict.items():
            # 按时间排序
            packets.sort(key=lambda x: x['timestamp'])

            # 性能优化：可选的每会话报文数上限（0/None 表示不限制）。
            # 默认不截断，以保证评价样本量与 ground truth 统计一致。
            cap = self.MAX_PACKETS_PER_SESSION
            if cap:
                packets = packets[:cap]

            # 判断是否为TCP会话
            is_tcp = any(p.get('is_tcp', False) for p in packets)

            # 创建会话（Session.__init__ 内部已自动完成TCP重组，
            # 此处无需重复调用，避免消息重复）
            session = Session(
                session_id=f"{key[0]}:{key[1]}-{key[2]}:{key[3]}",
                packets=packets,
                reassembled=False
            )

            sessions.append(session)

        return sessions
    
    # 已知二进制工业/物联网协议的默认服务端口白名单。
    # 这些协议本质是二进制协议，但报文常含大量可打印字符
    # （如 MQTT 的协议名 "MQTT"、topic 名、JSON 载荷等），
    # 仅凭 ASCII 比例会把它们误判为文本协议而被过滤掉
    # （MQTT.pcap 会话 ascii_ratio≈0.83 > 阈值 0.4 即被误删的根因）。
    # 命中该白名单端口的会话直接认定为二进制协议、跳过 ASCII 判定。
    _BINARY_PROTOCOL_PORTS = frozenset({
        1883, 8883, 8884,     # MQTT / MQTT over TLS / MQTT over WebSocket
        102,                  # S7comm (ISO-TSAP)
        502,                  # Modbus TCP
        44818, 2222,          # EtherNet/IP (enip) / CIP
        20000,                # DNP3
        2404,                 # IEC 60870-5-104
        47808,                # BACnet/IP
        5094,                 # HART-IP
        135,                  # DCERPC
        4840,                 # OPC UA
        34964,                # PROFINET
    })

    def _session_ports(self, session: Session) -> set:
        """提取会话中出现的所有端口（用于协议端口白名单判定）"""
        ports = set()
        for p in session.packets:
            for key in ('src_port', 'dst_port'):
                val = p.get(key)
                if val is None:
                    continue
                try:
                    port = int(val)
                except (TypeError, ValueError):
                    continue
                if port > 0:
                    ports.add(port)
        return ports

    def filter_binary_protocols(self, sessions: List[Session]) -> List[Session]:
        """
        过滤文本协议，仅保留二进制协议。

        判定顺序：
          1. 端口白名单优先：若会话端口命中已知二进制协议端口
             （MQTT 1883/8883、S7comm 102、Modbus 502、enip 44818 等），
             直接认定为二进制协议（这些协议的报文常含大量可打印字符，
             仅凭 ASCII 比例会误判为文本协议而被过滤）。
          2. 否则按可打印 ASCII 字符比例 < ascii_threshold 判定。
        """
        binary_sessions = []

        for session in sessions:
            # 获取消息内容
            messages = session.get_messages()
            if not messages:
                continue

            # 1) 端口白名单：命中已知二进制协议端口则直接保留
            if self._session_ports(session) & self._BINARY_PROTOCOL_PORTS:
                binary_sessions.append(session)
                continue

            is_binary = True
            total_bytes = 0
            printable_bytes = 0

            for msg in messages[:10]:  # 检查前10条消息
                if msg:
                    total_bytes += len(msg)
                    printable = sum(1 for b in msg if 32 <= b <= 126 or b in [9, 10, 13])
                    printable_bytes += printable

            if total_bytes > 0:
                ascii_ratio = printable_bytes / total_bytes
                if ascii_ratio > self.ascii_threshold:
                    is_binary = False

            if is_binary:
                binary_sessions.append(session)

        return binary_sessions
    
    def build_data_matrix(self, session: Session, source_file: str = "") -> Tuple[np.ndarray, Dict]:
        """
        构建二维数据矩阵 M[N x L_max]
        使用重组后的应用层消息
        返回：(数据矩阵, 会话信息)
        """
        # 获取重组后的消息
        messages = session.get_messages()
        
        if not messages:
            return np.array([]), {}
        
        # 过滤过短的消息
        messages = [msg for msg in messages if len(msg) >= 4]
        
        if not messages:
            return np.array([]), {}
        
        # 找到最大长度
        max_len = max(len(msg) for msg in messages)
        
        # 构建矩阵
        N = len(messages)
        M = np.zeros((N, max_len), dtype=np.uint8)

        for i, msg in enumerate(messages):
            M[i, :len(msg)] = np.frombuffer(msg, dtype=np.uint8)

        # 方案C：裁掉尾部“全列为0”的零填充列。
        # 跨消息等长后超出的 0 填充会在特征上形成“常数列”，
        # 与训练/匹配的结构字段占位无关，只让匹配端把尾列糊成 data 伪字段。
        while M.shape[1] > 1 and not M[:, -1].any():
            M = M[:, :-1]
        if M.shape[1] == 0:
            return np.array([]), {}

        session_info = {
            'session_id': session.session_id,
            'source_file': source_file,  # 来源文件名
            'packet_count': len(session.packets),
            'message_count': N,
            'max_length': max_len,
            'reassembled': session.reassembled
        }
        
        return M, session_info
    
    def extract_fields_with_tshark(self, pcap_file: str) -> Dict:
        """
        使用tshark提取协议字段
        返回字段名到值列表的映射
        """
        # 先尝试用tshark获取所有可用的字段
        try:
            # 获取协议层次结构
            cmd = ['tshark', '-r', pcap_file, '-T', 'fields', '-e', 'frame.protocols']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {}
            
            # 解析协议层次，获取应用层协议
            protocols = set()
            for line in result.stdout.strip().split('\n'):
                if line:
                    for proto in line.split(':'):
                        if proto and proto not in ['eth', 'ip', 'tcp', 'udp', 'frame', 'data']:
                            protocols.add(proto)
            
            if not protocols:
                return {}
            
            # 对每个协议尝试提取字段
            all_fields = {}
            for proto in protocols:
                try:
                    # 获取该协议的所有字段
                    cmd = ['tshark', '-r', pcap_file, '-G', 'fields']
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode != 0:
                        continue
                    
                    # 解析字段列表
                    proto_fields = []
                    for line in result.stdout.strip().split('\n'):
                        if line and line.startswith(proto + '.'):
                            field_name = line.split()[0]
                            proto_fields.append(field_name)
                    
                    # 提取字段值
                    if proto_fields:
                        cmd = ['tshark', '-r', pcap_file, '-T', 'fields']
                        for field in proto_fields[:20]:  # 限制字段数量
                            cmd.extend(['-e', field])
                        cmd.extend(['-E', 'header=n'])
                        
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        if result.returncode == 0:
                            field_values = {field: [] for field in proto_fields[:20]}
                            lines = result.stdout.strip().split('\n')
                            for line in lines:
                                if not line.strip():
                                    continue
                                parts = line.split('\t')
                                for i, field in enumerate(proto_fields[:20]):
                                    if i < len(parts):
                                        val = parts[i].strip()
                                        if val:
                                            try:
                                                field_values[field].append(bytes.fromhex(val.replace(':', '')))
                                            except:
                                                field_values[field].append(val)
                                        else:
                                            field_values[field].append(None)
                            all_fields.update(field_values)
                except:
                    continue
            
            return all_fields
            
        except Exception as e:
            logger.error(f"tshark提取字段失败: {str(e)}")
            return {}