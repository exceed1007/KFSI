# -*- coding: utf-8 -*-
"""生成论文插图（英文版，200 dpi PNG，黑白友好、适合期刊排版）。

用法::

    python scripts/make_figures.py --out outputs/fig
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import font_manager
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

ROOT = Path(__file__).resolve().parents[1]

plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman', 'DejaVu Serif']
plt.rcParams['mathtext.fontset'] = 'stix'
plt.rcParams['axes.unicode_minus'] = False

INK = '#1a1a1a'
GREY = '#5f5f5f'
F_STEP = '#f7f7f7'
F_KEY = '#e8e8e8'
F_OUT = '#ffffff'
F_BAR = '#d0d0d0'
BAND = '#fbfbfb'

# 灰度色阶：用于多方法对比（黑白打印仍可区分）
SHADES = ['#2b2b2b', '#6f6f6f', '#a6a6a6', '#cbcbcb', '#ececec']


def box(ax, cx, cy, w, h, text, fill=F_STEP, fs=9.0, bold=False, ls='-',
        lw=0.9, zorder=3, va='center'):
    ax.add_patch(FancyBboxPatch((cx - w / 2, cy - h / 2), w, h,
                                boxstyle='round,pad=0.0,rounding_size=0.05',
                                linewidth=lw, edgecolor=INK, facecolor=fill,
                                linestyle=ls, zorder=zorder))
    ax.text(cx, cy, text, ha='center', va=va, fontsize=fs, color=INK,
            zorder=zorder + 1, fontweight='bold' if bold else 'normal',
            linespacing=1.5)


def arrow(ax, p0, p1, label=None, fs=7.8, ls='-', rad=0.0, color=INK,
          lw=0.9, lx=0.0, ly=0.0, style='-|>'):
    ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle=style, mutation_scale=9,
                                 linewidth=lw, color=color, linestyle=ls,
                                 connectionstyle=f'arc3,rad={rad}', zorder=2,
                                 shrinkA=0, shrinkB=0))
    if label:
        ax.text((p0[0] + p1[0]) / 2 + lx, (p0[1] + p1[1]) / 2 + ly, label,
                ha='center', va='center', fontsize=fs, color=GREY, zorder=6,
                bbox=dict(fc='white', ec='none', pad=1.0))


def band(ax, x0, y0, w, h, title):
    ax.add_patch(Rectangle((x0, y0), w, h, facecolor=BAND, edgecolor='#d8d8d8',
                           linewidth=0.7, zorder=1))
    ax.text(x0 + 0.16, y0 + h - 0.16, title, ha='left', va='top',
            fontsize=8.2, color=GREY, zorder=5, fontweight='bold')


def badge(ax, x, y, n, r=0.22):
    ax.add_patch(plt.Circle((x, y), r, facecolor=INK, edgecolor='none',
                            zorder=7))
    ax.text(x, y - 0.01, str(n), ha='center', va='center', fontsize=7.4,
            color='white', zorder=8, fontweight='bold')


# ----------------------------------------------------------------------
def fig_framework(path: Path):
    """总体框架：分层带状布局，左侧主脊为处理流程，右侧为跨结构机制。"""
    fig, ax = plt.subplots(figsize=(7.4, 6.5))
    ax.set_xlim(0, 13.0)
    ax.set_ylim(0, 13.0)
    ax.axis('off')

    LX, RX = 0.30, 9.55          # 主区左右边界
    CX = (LX + RX) / 2           # 主区中心 4.925

    # ---------------- 带 A：输入 ----------------
    band(ax, LX, 11.35, RX - LX, 1.35, '(a) Input')
    box(ax, CX, 11.75, 8.5, 0.80,
        'Application-layer message sequence (reassembled by session, '
        'with timestamps and directions)', F_OUT, 8.2, True)

    # ---------------- 带 B：关键字段识别 ----------------
    band(ax, LX, 7.70, RX - LX, 3.40,
         '(b) Key-field identification (per region)')
    # 三类判据并列，各占一栏，避免文字相互压盖
    bw3, gap3 = 2.90, 0.28
    c1 = LX + bw3 / 2
    c2 = c1 + bw3 + gap3
    c3 = c2 + bw3 + gap3
    box(ax, c1, 9.30, bw3, 1.80,
        '1) Global semantic anchors\nChecksum (prefix-incremental)\n'
        'Strictly increasing sequence no.\n'
        'Timestamp (linear in capture time)', F_STEP, 6.7)
    box(ax, c2, 9.30, bw3, 1.80,
        '2) Structure identifier field SIF\nGrouping structure gain G(s,w)\n'
        'Local gain (next 10 columns), max', F_STEP, 6.7)
    box(ax, c3, 9.30, bw3, 1.80,
        '3) Length field LF\nRobust closure '
        '$\\kappa$\nAlignment gain A, boundary strength',
        F_KEY, 6.7, True)

    # ---------------- 带 C：分裂与递归 ----------------
    band(ax, LX, 3.35, RX - LX, 4.05, '(c) Splitting and recursion')
    box(ax, CX, 6.55, 7.6, 1.00,
        '4) Split decision: SIF above threshold → horizontal;\n'
        'else LF above threshold → vertical', F_STEP, 7.8, True)
    box(ax, 2.75, 5.05, 4.2, 1.35,
        '5)a Horizontal splitting\nBucket by SIF value (or masked bits)\n'
        'Homogeneous buckets; statistics recomputed', F_STEP, 7.0)
    box(ax, 7.10, 5.05, 4.2, 1.35,
        '5)b Vertical splitting\nCut prefix | block | remainder\n'
        'Remainder offsets reset; drift removed', F_STEP, 7.0)
    arrow(ax, (3.55, 6.10), (2.92, 5.60))
    arrow(ax, (6.30, 6.10), (6.93, 5.60))
    box(ax, CX, 3.95, 7.6, 0.92,
        '6) Return to (b) for every sub-region\n'
        '(depth <= 3, messages >= 4)', '#efefef', 7.8)
    arrow(ax, (2.75, 4.50), (3.65, 4.33))
    arrow(ax, (7.10, 4.50), (6.20, 4.33))

    # 递归回边：沿左侧留白上行，不穿越任何方框
    ax.add_patch(FancyArrowPatch((LX + 0.08, 3.95), (LX + 0.08, 9.25),
                                 arrowstyle='-|>', mutation_scale=9,
                                 linewidth=0.8, color=GREY, linestyle=':',
                                 zorder=2))
    ax.add_patch(FancyArrowPatch((LX + 0.08, 3.95), (0.60, 3.95),
                                 arrowstyle='-', linewidth=0.8, color=GREY,
                                 linestyle=':', zorder=2))

    # ---------------- 带 D：叶子推断 ----------------
    band(ax, LX, 0.30, RX - LX, 2.75,
         '(d) Boundary inference on homogeneous regions')
    box(ax, 2.05, 1.45, 3.1, 1.15,
        '7) Position-level evidence\n18 features (Table 1)', F_STEP, 7.6)
    box(ax, 5.45, 1.45, 3.1, 1.15,
        '8) Width prior + MAP\nGlobal optimum by DP\nO(L·w_max)',
        F_KEY, 7.6, True)
    box(ax, 8.35, 1.45, 2.1, 1.15, '9) Output\nfield boundary\nset',
        F_OUT, 7.8, True)
    arrow(ax, (3.62, 1.45), (3.88, 1.45))
    arrow(ax, (7.02, 1.45), (7.28, 1.45))
    arrow(ax, (CX, 3.57), (CX, 2.72))

    # ---------------- 右列：跨结构机制 ----------------
    bx0, bw = 9.80, 2.95
    ax.add_patch(Rectangle((bx0, 3.35), bw, 7.75, facecolor='#f2f2f2',
                           edgecolor='#c8c8c8', linewidth=0.7, linestyle='--',
                           zorder=1))
    ax.text(bx0 + bw / 2, 10.78, 'Cross-structure mechanisms',
            ha='center', va='center', fontsize=7.8, fontweight='bold',
            color=INK, zorder=5)
    box(ax, bx0 + bw / 2, 9.15, bw - 0.35, 1.85,
        'Mechanism A\nThe split key lies at the\nsame offset in all structures;\n'
        'its endpoints are reused', '#ffffff', 6.9, ls='--', lw=0.8)
    box(ax, bx0 + bw / 2, 6.55, bw - 0.35, 1.85,
        'Mechanism B\nKey fields confirmed on\nsibling structures are verified\n'
        'locally before transfer to\nsample-sparse structures', '#ffffff',
        6.9, ls='--', lw=0.8)
    box(ax, bx0 + bw / 2, 4.35, bw - 0.35, 1.15,
        'Evidence grading\nVerifiable → hard anchor\nIndicative → soft evidence',
        '#ffffff', 6.9, ls='--', lw=0.8)
    arrow(ax, (RX, 9.25), (bx0, 9.15), '', ls='--', color=GREY, lw=0.8)
    arrow(ax, (RX, 5.05), (bx0, 6.45), '', ls='--', color=GREY, lw=0.8, rad=0.12)

    # 带与带之间的主流程箭头
    arrow(ax, (CX, 11.35), (CX, 11.12))
    arrow(ax, (CX, 7.70), (CX, 7.43))

    ax.text(0.30, 0.02, 'Note: dashed lines are the cross-structure mechanisms, the dotted arrow '
            'is the recursion edge; termination conditions of 6) are in Section 5.4.',
            fontsize=7.0, color=GREY, ha='left', va='bottom')

    fig.subplots_adjust(left=0.008, right=0.992, top=0.995, bottom=0.015)
    fig.savefig(path, dpi=220, facecolor='white')
    plt.close(fig)


# ----------------------------------------------------------------------
def fig_split(path: Path):
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.5),
                             gridspec_kw={'width_ratios': [1.0, 1.0]})

    # ================= (a) 水平分裂 =================
    ax = axes[0]
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.axis('off')
    ax.set_title('(a) Horizontal splitting: bucketing by SIF value',
                 fontsize=9.6, color=INK, pad=8)

    h = 0.9
    ax.text(0.1, 9.55, 'Original messages (mixed structures)',
            fontsize=8.6, color=GREY, ha='left', va='center')
    _bar(ax, 1.45, 8.2, h,
         [('SIF', 1.0, F_BAR, False), ('b1', 0.75, F_STEP, False),
          ('b2', 0.75, F_STEP, False), ('b3', 0.75, F_STEP, False),
          ('payload', 1.5, '#f2f2f2', True)])

    rows = [
        ('type = 1 → structure A: b2 starts the variable-length topic',
         [('SIF', 1.0, F_BAR, False), ('b1', 0.75, F_STEP, False),
          ('b2', 1.75, '#ececec', False), ('b3', 0.75, F_STEP, False),
          ('payload', 1.1, '#f2f2f2', True)]),
        ('type = 2 → structure B: b1 is the message identifier',
         [('SIF', 1.0, F_BAR, False), ('b1', 1.45, '#ececec', False),
          ('b2', 0.75, F_STEP, False), ('b3', 0.75, F_STEP, False),
          ('payload', 1.4, '#f2f2f2', True)]),
        ('type = 3 → structure C: no payload (acknowledgement)',
         [('SIF', 1.0, F_BAR, False), ('b1', 0.75, F_STEP, False),
          ('b2', 0.75, F_STEP, False), ('b3', 0.75, F_STEP, False)]),
    ]
    ys = [6.55, 4.35, 2.15]
    for (tag, segs), y in zip(rows, ys):
        _bar(ax, 1.45, y, h, segs)
        ax.text(1.45, y - 0.42, tag, fontsize=8.8, color=GREY, ha='left',
                va='center')

    ax.add_patch(FancyArrowPatch((1.05, 8.15), (1.05, 2.6),
                                 arrowstyle='-', linewidth=1.0, color=GREY,
                                 zorder=2))
    for y in ys:
        ax.add_patch(FancyArrowPatch((1.05, y + h / 2), (1.43, y + h / 2),
                                     arrowstyle='-|>', mutation_scale=8,
                                     linewidth=1.0, color=GREY, zorder=2))
    ax.text(0.82, 5.4, 'Group by SIF value', fontsize=8.2, color=GREY,
            rotation=90, ha='center', va='center')

    ax.text(0.1, 0.75, 'Buckets are homogeneous, column statistics are comparable again;\n'
                       'fields shared across buckets stay at the same offset.',
            fontsize=8.0, color=GREY, ha='left', va='center',
            linespacing=1.7)

    # ================= (b) 垂直分裂 =================
    ax = axes[1]
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.axis('off')
    ax.set_title('(b) Vertical splitting: three parts by the length field',
                 fontsize=9.6, color=INK, pad=8)

    def vrow(y, v, note):
        segs = [('prefix', 1.35, F_STEP, False), ('LF', 0.7, F_BAR, False),
                ('block', v, '#ececec', False),
                ('remainder', 4.4 - v, '#f2f2f2', True)]
        _bar(ax, 0.55, y, h, segs)
        ax.text(0.55, y - 0.42, note, fontsize=8.8, color=GREY, ha='left',
                va='center')

    vrow(7.3, 1.5, 'Message i: length field v = 5, block = 5 bytes')
    vrow(4.9, 2.6, 'Message j: length field v = 9, block = 9 bytes')

    ax.add_patch(FancyBboxPatch((0.55, 1.55), 8.3, 1.60,
                                boxstyle='round,pad=0.0,rounding_size=0.1',
                                linewidth=0.9, edgecolor=GREY,
                                facecolor='white', linestyle='--', zorder=3))
    ax.text(0.80, 2.72, 'Offsets inside the block are decoupled from the prefix',
            fontsize=8.0, color=GREY, ha='left', va='center', zorder=4)
    ax.text(0.80, 2.05, 'The remainder restarts at offset 0; drift is removed',
            fontsize=8.0, color=GREY, ha='left', va='center', zorder=4)

    fig.subplots_adjust(left=0.01, right=0.99, top=0.92, bottom=0.02,
                        wspace=0.14)
    fig.savefig(path, dpi=220, facecolor='white')
    plt.close(fig)


def _bar(ax, x, y, h, segs):
    cursor = x
    for label, w, fc, dashed in segs:
        ax.add_patch(Rectangle((cursor, y), w, h, facecolor=fc, edgecolor=INK,
                               linewidth=0.8, linestyle='--' if dashed else '-',
                               zorder=3))
        ax.text(cursor + w / 2, y + h / 2, label, ha='center', va='center',
                fontsize=8.4, color=INK, zorder=4)
        cursor += w


# ----------------------------------------------------------------------
def fig_coverage(path: Path, seed: int = 7):
    """覆盖度截断示例：余部长度不齐时，靠后的列只被少数长报文覆盖。"""
    rng = np.random.default_rng(seed)
    lens = np.array([34, 36, 37, 40, 41, 43, 45, 46, 49, 52])
    n = len(lens)
    L = int(lens.max())

    fig, axes = plt.subplots(2, 1, figsize=(7.0, 3.9), sharex=True,
                             gridspec_kw={'height_ratios': [1.35, 1.0],
                                          'hspace': 0.12})
    ax = axes[0]
    for i, ln in enumerate(lens):
        ax.add_patch(Rectangle((0, i - 0.34), ln, 0.68, facecolor='#dcdcdc',
                               edgecolor=INK, linewidth=0.7))
    ax.set_ylim(-0.8, n + 0.75)
    ax.set_ylabel('Message index', fontsize=8.6)
    ax.set_yticks(range(n))
    ax.tick_params(labelsize=7.6, length=2.5)
    ax.set_title('Remainder region: unequal lengths reduce coverage of '
                 'later columns', fontsize=9.0, pad=6)
    for s in ('top', 'right'):
        ax.spines[s].set_visible(False)

    cov = np.array([(lens > c).mean() for c in range(L)])
    Lc = int(np.max(np.where(cov >= 0.6)[0])) + 1
    axes[1].plot(np.arange(L) + 0.5, cov, '-o', color=INK, markersize=3,
                 linewidth=1.1, zorder=3)
    axes[1].axhline(0.6, color=GREY, linestyle='--', linewidth=1.0, zorder=2)
    axes[1].axvline(Lc, color=INK, linestyle=':', linewidth=1.1, zorder=2)
    axes[1].annotate(f'truncation $L_c$ = {Lc}', xy=(Lc, 0.62),
                     xytext=(Lc + 2.2, 0.86), fontsize=8.4, color=INK,
                     arrowprops=dict(arrowstyle='->', color=INK, lw=0.9))
    axes[1].text(1.0, 0.64, 'coverage floor 0.6', fontsize=7.8, color=GREY,
                 ha='left', va='bottom')
    axes[1].set_xlabel('Column offset', fontsize=8.6)
    axes[1].set_ylabel('Coverage', fontsize=8.6)
    axes[1].set_ylim(-0.03, 1.05)
    axes[1].set_xlim(0, L)
    axes[1].tick_params(labelsize=7.6, length=2.5)
    for s in ('top', 'right'):
        axes[1].spines[s].set_visible(False)

    # 在图上标出“若在截断点之后切分，只有少数报文支持”
    ax.annotate('', xy=(Lc, n - 0.35), xytext=(Lc, -0.9),
                arrowprops=dict(arrowstyle='-', color=INK, lw=0.9,
                                linestyle=':'))
    ax.text(1.0, n + 0.30,
            f'Dotted line: truncation $L_c$ = {Lc}; only the '
            f'{int((lens > Lc).sum())} longest messages have content to its '
            f'right, too few to support cutting',
            fontsize=7.6, color=GREY, ha='left', va='center')

    fig.subplots_adjust(left=0.09, right=0.985, top=0.9, bottom=0.14)
    fig.savefig(path, dpi=220, facecolor='white')
    plt.close(fig)


# ----------------------------------------------------------------------
def fig_results(path: Path):
    main = json.load(open(ROOT / 'outputs' / 'main.json', encoding='utf-8'))
    bl = json.load(open(ROOT / 'outputs' / 'baselines' / 'baselines.json',
                        encoding='utf-8'))
    order = ['bacnet', 'DCERPC', 'dnp3', 'hart_ip', 'IEC104', 'modbus',
             'MQTT', 'S7comm']
    rows = {r['protocol']: r for r in main['batch']['rows']}
    irows = {r['protocol']: r for r in main['isolated']['rows']}
    methods = [('KFSI (batch)', {p: rows[p]['F1'] for p in order}),
               ('KFSI (isolated)', {p: irows[p]['F1'] for p in order})]
    label = {'binaryinferno': 'BinaryInferno', 'pft': 'PFT', 'reinpro': 'REInPro'}
    for k in ('binaryinferno', 'pft', 'reinpro'):
        if k in bl:
            methods.append((label[k], {r['protocol']: r['F1']
                                       for r in bl[k]['rows']}))

    fig, ax = plt.subplots(figsize=(7.0, 3.1))
    x = np.arange(len(order))
    w = 0.84 / len(methods)
    for i, (name, d) in enumerate(methods):
        vals = [d.get(p, 0.0) for p in order]
        ax.bar(x + (i - (len(methods) - 1) / 2) * w, vals, w,
               label=name, color=SHADES[i % len(SHADES)], edgecolor=INK,
               linewidth=0.5, zorder=3)
    ax.set_xticks(x)
    ax.set_xticklabels(order, fontsize=9.0)
    ax.set_ylabel('F1', fontsize=9.6)
    ax.set_ylim(0, 1.0)
    ax.tick_params(labelsize=8.0, length=2.5)
    for s in ('top', 'right'):
        ax.spines[s].set_visible(False)
    ax.grid(axis='y', linestyle=':', color='#cccccc', linewidth=0.7, zorder=0)
    ax.legend(fontsize=8.4, ncol=len(methods), frameon=False,
              loc='upper center', bbox_to_anchor=(0.5, 1.10),
              handlelength=1.6, columnspacing=1.1)
    fig.subplots_adjust(left=0.085, right=0.99, top=0.86, bottom=0.14)
    fig.savefig(path, dpi=220, facecolor='white')
    plt.close(fig)


# ----------------------------------------------------------------------
def fig_ablation(path: Path):
    ab = json.load(open(ROOT / 'outputs' / 'ablation.json', encoding='utf-8'))
    skip = {'w/o 水平+垂直', 'w/o MAP 解码'}
    ab = [r for r in ab if r['variant'] not in skip]
    base = ab[0]['f1']
    EN = {'KFSI_full': 'KFSI full',
          'w/o 水平分裂': 'w/o horizontal splitting',
          'w/o 垂直分裂': 'w/o vertical splitting',
          'w/o 关键字段端点': 'w/o key-field endpoints',
          'w/o 语义锚点': 'w/o semantic anchors',
          'w/o 跨结构迁移': 'w/o cross-structure transfer',
          'w/o 宽度先验': 'w/o width prior',
          'w/o 比特级 SIF': 'w/o bit-level SIF',
          'w/o 学习权重': 'w/o learned weights',
          'w/o 局部结构增益': 'w/o local structure gain'}
    names, deltas = [], []
    for r in ab[1:]:
        names.append(EN.get(r['variant'], r['variant']))
        deltas.append(100 * (r['f1'] - base))
    order = np.argsort(deltas)
    names = [names[i] for i in order]
    deltas = [deltas[i] for i in order]

    fig, ax = plt.subplots(figsize=(7.2, 2.9))
    y = np.arange(len(names))
    colors = [INK if d <= -3 else '#9a9a9a' for d in deltas]
    ax.barh(y, deltas, color=colors, edgecolor=INK, linewidth=0.5, height=0.62,
            zorder=3)
    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=9.2)
    ax.axvline(0, color=INK, linewidth=0.9)
    ax.set_xlabel('ΔF1 (percentage points, relative to the full method)',
                 fontsize=9.2)
    ax.tick_params(labelsize=8.0, length=2.5)
    for i, d in enumerate(deltas):
        ax.text(0.9, i, f'{d:+.2f}', va='center', ha='left', fontsize=8.4,
                color=INK)
    lo = min(deltas) - 4
    ax.set_xlim(lo if lo < 0 else -1, 7.0)
    for s in ('top', 'right'):
        ax.spines[s].set_visible(False)
    ax.grid(axis='x', linestyle=':', color='#cccccc', linewidth=0.7, zorder=0)
    fig.subplots_adjust(left=0.34, right=0.985, top=0.96, bottom=0.17)
    fig.savefig(path, dpi=220, facecolor='white')
    plt.close(fig)


# ----------------------------------------------------------------------
def fig_sensitivity(path: Path):
    se = json.load(open(ROOT / 'outputs' / 'sensitivity.json', encoding='utf-8'))
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.7))

    ax = axes[0]
    d = se['theta']
    ax.plot([x['value'] for x in d], [x['F1'] for x in d], '-o', color=INK,
            markersize=3.4, linewidth=1.2, zorder=3)
    ax.set_xlabel('Decision threshold $\\theta$', fontsize=9.2)
    ax.set_ylabel('F1', fontsize=9.2)
    ax.set_title('(a) Decision threshold', fontsize=9.4, pad=5)
    ax.tick_params(labelsize=7.8, length=2.5)
    ax.grid(linestyle=':', color='#cccccc', linewidth=0.7, zorder=0)

    ax = axes[1]
    d = se['sif_split_gain']
    xs = [x['value'] for x in d]
    ys = [x['F1'] for x in d]
    ax.plot(xs, ys, '-o', color=INK, markersize=3.4, linewidth=1.2, zorder=3)
    best = xs[int(np.argmax(ys))]
    ax.axvline(best, color=GREY, linestyle='--', linewidth=0.9, zorder=2)
    ax.annotate(f'peak {max(ys):.3f}', xy=(best, max(ys)),
                xytext=(best + 0.075, max(ys) + 0.004), fontsize=8.4,
                color=GREY, va='center',
                arrowprops=dict(arrowstyle='->', color=GREY, lw=0.8,
                                shrinkB=4))
    ax.set_xlabel('Split gain threshold $\\tau_g$', fontsize=9.2)
    ax.set_ylabel('F1', fontsize=9.2)
    ax.set_title('(b) Split gain threshold', fontsize=9.4, pad=5)
    ax.tick_params(labelsize=7.8, length=2.5)
    ax.grid(linestyle=':', color='#cccccc', linewidth=0.7, zorder=0)

    for ax in axes:
        for s in ('top', 'right'):
            ax.spines[s].set_visible(False)
    fig.subplots_adjust(left=0.085, right=0.985, top=0.86, bottom=0.19,
                        wspace=0.28)
    fig.savefig(path, dpi=220, facecolor='white')
    plt.close(fig)


# ----------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=str(ROOT / 'outputs' / 'fig_en'))
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    fig_framework(out / 'fig1_framework.png')
    fig_split(out / 'fig2_split.png')
    fig_coverage(out / 'fig3_coverage.png')
    if (ROOT / 'outputs' / 'baselines' / 'baselines.json').exists():
        fig_results(out / 'fig4_results.png')
    if (ROOT / 'outputs' / 'ablation.json').exists():
        fig_ablation(out / 'fig5_ablation.png')
    if (ROOT / 'outputs' / 'sensitivity.json').exists():
        fig_sensitivity(out / 'fig6_sensitivity.png')
    print('figures written to', out)


if __name__ == '__main__':
    main()
