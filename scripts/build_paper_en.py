# -*- coding: utf-8 -*-
"""生成论文 Word 文档：所有表格数字直接读 outputs/ 下的实验结果。

用法::

    python scripts/build_paper.py --out 论文.docx
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from docxgen import DocxBuilder  # noqa: E402

OUT = ROOT / 'outputs'
FIG = OUT / 'fig_en'

# 参考文献：按正文首次引用顺序自动编号（顺序编码制）
CITE_NUM = {}
CITE_ORDER = []


def C(*keys) -> str:
    """按正文首次引用顺序分配编号，返回 [1,2] 或 [1]。"""
    for k in keys:
        if k not in CITE_NUM:
            CITE_ORDER.append(k)
            CITE_NUM[k] = len(CITE_ORDER)
    nums = sorted(CITE_NUM[k] for k in keys)
    return '[' + ','.join(str(n) for n in nums) + ']'


def load(name, default=None):
    p = OUT / name
    if not p.exists():
        return default
    return json.load(open(p, encoding='utf-8'))


def f4(x):
    return f'{x:.4f}'


def kf_agg(kf):
    """按协议内去重的位置集合口径汇总关键字段指标（表 5 口径）。"""
    out = {}
    for kind, pre in (('len', 'len'), ('type', 'type')):
        npred = sum(r[f'{pre}_n_pred'] for r in kf)
        ngt = sum(r[f'{pre}_v3_gt'] for r in kf)
        ntp = sum(round(r[f'{pre}_v3_p'] * r[f'{pre}_n_pred']) for r in kf)
        P = ntp / npred if npred else 0.0
        Rr = ntp / ngt if ngt else 0.0
        out[kind] = (P, Rr, 2 * P * Rr / (P + Rr) if P + Rr else 0.0)
    out['ok_len'] = sum(1 for r in kf if r['len_v3_p'] > 0)
    out['ok_type'] = sum(1 for r in kf if r['type_v3_p'] > 0)
    out['n'] = len(kf)
    return out


BODY = {}


def build(out_path: str):
    main = load('main.json')
    bl = load('baselines/baselines.json')
    bl_or = load('baselines_oracle.json')
    ab = load('ablation.json')
    abt = load('ablation_theta.json')
    kf = load('keyfields.json')
    sc = load('scopes_global.json')
    se = load('sensitivity.json')

    # --- 主实验（批量推断）→ 与原 eval/results.json 相同口径的视图 ---
    mb = main['batch']
    iso = main['isolated']
    rows = {r['protocol']: {'protocol': r['protocol'], 'messages': r['n'],
                            'P': r['P'], 'R': r['R'], 'F1': r['F1'],
                            'tp': r['tp'], 'fp': r['fp'], 'fn': r['fn'],
                            'iou_F1': (r['iou'][2] if r['iou'] else 0.0)}
            for r in mb['rows']}
    summ = {'messages': sum(r['n'] for r in mb['rows']),
            'micro_P': mb['micro_P'], 'micro_R': mb['micro_R'],
            'micro_F1': mb['micro_F1'], 'macro_F1': mb['macro_F1'],
            'iou_micro_F1': mb['iou_micro_F1']}
    kfa = kf_agg(kf) if kf else None
    order = ['bacnet', 'DCERPC', 'dnp3', 'hart_ip', 'IEC104', 'modbus',
             'MQTT', 'S7comm']
    n_msg = summ['messages']
    bl_name = {'binaryinferno': 'BinaryInferno', 'pft': 'PFT',
               'reinpro': 'REInPro'}
    best_bl = max(bl.values(), key=lambda r: r['micro_F1']) if bl else None
    best_bl_or = max(bl_or.values(), key=lambda r: r['F1']) if bl_or else None
    gain = (summ['micro_F1'] / best_bl['micro_F1'] - 1) if best_bl else 0.0
    gain_or = (summ['micro_F1'] / best_bl_or['F1'] - 1) if best_bl_or else 0.0
    theta = main.get('theta')

    b = DocxBuilder(english=True)

    # ==================== Title and abstract ====================
    b.title('Key-field identification and recursive splitting for field '
            'boundary inference of binary network protocols')
    b.blank()
    b.abs('Abstract: Field boundaries of binary protocols are a common '
          'prerequisite for mutation construction in fuzzing, for signature '
          'generation in intrusion detection, and for protocol evasion '
          'testing. Industrial, IoT and proprietary protocols rarely publish '
          'specifications, usually define several message structures, and '
          'use variable-length fields, so that column-wise '
          'inference is degraded by structural heterogeneity, which mixes '
          'formats into one column distribution, and by offset drift, which '
          'shifts every field after a variable-length one per message. This '
          'paper presents KFSI: structure identifier fields are detected by '
          'a grouping structure gain, length fields by robust closure and '
          'alignment gain, and checksums, sequence numbers and timestamps '
          'are used as directly verifiable anchors. Messages are split '
          'horizontally by structure identifier fields and vertically by '
          'length fields, recursively reducing the problem to homogeneous, '
          'offset-consistent regions, where position-level evidence is fused '
          'and a global segmentation is obtained by maximum a posteriori '
          'decoding with a field-width prior. Split keys share their offset '
          'across structures, and key fields confirmed on sibling structures '
          'are transferred to sample-sparse ones only after local '
          f'verification. On {n_msg} messages from {len(order)} real '
          'protocols, with calibration, development and test partitions '
          'disjoint at both file and message level, KFSI attains a position '
          f'F1 of {f4(summ["micro_F1"])} for first-level fields and an '
          f'interval F1 of {f4(summ["iou_micro_F1"])} at IoU >= 0.5, '
          f'improving the strongest baseline by {100 * gain:.1f}%; zero-shot '
          'on a protocol never seen during calibration it still reaches '
          '0.7934. Ablation shows that key-field endpoints, recursive '
          'splitting and width-prior constrained decoding are the main '
          'contributors, and that the method reproduces without training.')
    b.abs('Keywords: protocol reverse engineering; field boundary inference; '
          'key field identification; recursive splitting; fuzzing; maximum a '
          'posteriori decoding')

    # ==================== 1 Introduction ====================
    b.h1('1 Introduction')
    b.p('Network protocol reverse engineering aims to recover message syntax, '
        'field semantics and interaction state machines from traffic or from '
        'protocol implementations when specification documents are '
        'unavailable; it is a prerequisite for vulnerability discovery, '
        'intrusion detection, fuzzing and protocol compliance checking'
        + C('kleber19', 'duche') + '. Protocols of industrial control '
        'systems, the Internet of Things and a large number of proprietary '
        'systems are transmitted in binary encodings and their specifications '
        'are not public, which makes traffic-based format inference the most '
        'practical route' + C('narayan', 'sija') + '.')
    b.p('Field boundaries are a key intermediate product of security '
        'analysis; they directly determine whether three classes of tasks can '
        'be carried out at all. For fuzzing, a mutation that corrupts a '
        'length field or a checksum is discarded at the early validation '
        'stage of the parser; only when one knows which bytes encode a '
        'length, which bytes encode a checksum and how far the checksum '
        'covers can one construct inputs that are malformed yet structurally '
        'valid' + C('bininferno', 'pft') + '. For intrusion detection, field '
        'positions are the anchors of signatures and anomaly models; binding '
        'them to a wrong offset produces both false negatives and false '
        'positives. For evasion analysis and device fingerprinting, one must '
        'know which fields are validated by the receiver and how far the '
        'validation covers in order to decide whether a given modification '
        'will be silently dropped. Existing work relies on exactly this kind '
        'of information to increase fuzzing coverage of industrial control '
        'protocols and to discover vulnerabilities that affect physical '
        'control processes' + C('icpgf', 'liu22') + '; such information is '
        'however absent for private protocols that have neither '
        'specifications nor annotations, and obtaining it automatically is '
        'the starting point of this paper.')
    b.p('Boundary inference for binary protocols faces three difficulties. '
        'The first is **structural diversity**: one protocol defines several '
        'message types whose fields differ in composition, order and length, '
        'so that computing column statistics over the mixture makes boundary '
        'signals cancel each other out. The second is **variable-length '
        'misalignment**: a single variable-length field makes the offsets of '
        'all subsequent fields drift from message to message, and the '
        'assumption that one column is one field no longer holds. The third '
        'is that **boundaries and semantics are mutually conditioned**: '
        'deciding that a field is a length field depends on the length of the '
        'interval it points to, while the boundary of that interval depends '
        'on the length field, forming a cycle.')
    b.p('Existing methods follow three lines. Sequence alignment methods '
        'depend on messages being alignable and degrade as soon as a '
        'variable-length field appears. Statistical methods compute entropy, '
        'mutual information and similar quantities column by column; they are '
        'cheap but only look at neighbouring columns and tend to over-split '
        'in header regions with dense short fields. Learning methods learn '
        'boundary patterns from annotated data; they have a higher accuracy '
        'ceiling but depend on annotations, and cross-protocol transfer is '
        'limited by the training distribution.')
    b.p('The starting point of this paper is that protocols are designed by '
        'engineers and must obey a number of engineering constraints, and '
        'that these constraints leave computable and verifiable traces in the '
        'data. To support several message structures under a limited header '
        'budget, a protocol almost always defines a **structure identifier '
        'field** with a small value domain; to support variable-length '
        'content, it almost always defines a **length field**. Once these two '
        'fields are located, they remove exactly the two factors that destroy '
        'comparability: grouping by the structure identifier field removes '
        'heterogeneous mixing, and cutting out the interval pointed to by the '
        'length field removes variable-length misalignment. Key fields are '
        'therefore a precondition that reduces the problem to fixed-offset '
        'comparison on homogeneous subsets, rather than one more feature '
        'dimension.')
    b.p('Accordingly, this paper proposes **Key-Field-assisted Splitting and '
        'Inference** (KFSI), which follows a split-first, infer-second '
        'strategy: key fields are used to recursively split a heterogeneous '
        'message collection into structurally homogeneous, offset-consistent '
        'regions, and boundary inference is then carried out on each region. '
        'The main contributions are threefold.')
    b.p('(1) Computable criteria for key fields are given. The statement '
        'that a structure identifier field determines the subsequent '
        'structure is turned into a grouping structure gain; the decision on '
        'a length field is reduced to a joint test of robust closure, '
        'alignment gain, correlation and structural boundary strength; and '
        'width ambiguity is removed by a natural alignment constraint '
        'together with a rule that prefers the wider interpretation among '
        'identical value sequences.')
    b.p('(2) A key-field-driven recursive splitting framework is proposed '
        'together with the conditions under which it holds: horizontal '
        'splitting by structure identifier fields and vertical splitting by '
        'length fields. A timing constraint on endpoint marking is given: '
        'only key fields detected on a structurally homogeneous region have '
        'endpoints that hold for all messages. Two cross-structure semantic '
        'mechanisms are given so that fields reused by different structures '
        'validate each other.')
    b.p('(3) The method is compared with three recent methods under a '
        'partition into calibration, development and test sets that are '
        'mutually disjoint, and the necessity of each component is confirmed '
        'by ablation, sensitivity and reference-granularity analyses.')
    b.p('Section 2 reviews related work; Section 3 defines the problem; '
        'Sections 4 to 6 present key-field identification, recursive '
        'splitting and evidence fusion with decoding; Section 7 reports the '
        'experiments; Section 8 concludes.')

    # ==================== 2 Related work ====================
    b.h1('2 Related work')
    b.p('**Sequence alignment and clustering.** This line treats messages as '
        'byte sequences and recovers column correspondence with alignment '
        'algorithms from bioinformatics. PI was the first to introduce '
        'Needleman-Wunsch' + C('nw') + ' and Smith-Waterman' + C('sw') +
        ' into message analysis' + C('beddoe') + ', using value conservation '
        'of a column as evidence for boundaries; Discoverer first performs '
        'format segmentation and then recursive clustering to separate '
        'message types' + C('discoverer') + '; Netzob merges messages with '
        'UPGMA, classifies aligned columns as static or dynamic and takes '
        'the switching points as boundaries' + C('netzob') + '; Antunes et '
        'al. iteratively construct an automaton from alignment results, '
        'unifying format and session syntax in one model' + C('antunes') +
        '. NetPlier identifies the bottleneck as the keyword field that '
        'determines the message type, models keyword identification as '
        'probabilistic inference and uses cluster homogeneity and the '
        'correspondence between client-side and server-side clusters as '
        'observations' + C('netplier') + '. These methods require messages '
        'to be sufficiently comparable: once a variable-length field appears, '
        'alignment becomes misaligned and the subsequent column statistics '
        'fail.')
    b.p('**Statistical features and semantic detection.** This line does not '
        'depend on explicit alignment; it computes statistics per column or '
        'per window and locates boundaries with the intrinsic features of '
        'field semantics. FieldHunter cuts messages into field candidates and '
        'infers types from the correlation between field values and metadata '
        'such as length and IP address' + C('fieldhunter') + '; BinaryInferno '
        'generates candidate boundaries with atomic type detectors and '
        'entropy-shift detectors, and then integrates competing hypotheses '
        'into a consistent, semantic format' + C('bininferno') + '; NEMESYS '
        'searches for structural shifts of bit-level consistency inside a '
        'single message, which is insensitive to sample size but lacks '
        'cross-message constraints' + C('nemesys') + '; MSERA identifies '
        'semantic fields of industrial control protocols in three stages and '
        'then corrects them' + C('msera') + '; REInPro first identifies the '
        'control field that determines the structure, then clusters messages '
        'by its value and compares field features within each cluster'
        + C('reinpro') + '. These methods are cheap and interpretable, but '
        'their criteria are local: they answer whether two adjacent columns '
        'belong to the same field, not which structures a message consists '
        'of.')
    b.p('**Hybrid models and learning methods.** PFT proposes a field tree '
        'that merges message bytes bottom-up into nodes, with merge criteria '
        'given by a mixture of heuristic rules and statistical tests, and '
        'attaches a syntax classifier that labels fields with types'
        + C('pft') + '. ProRE extracts execution slices of the parsing '
        'process, encodes them with a data-flow-sensitive language model and '
        'then performs hierarchical clustering, recovering sequence, nesting '
        'and sibling relations at the same time' + C('prore') + '; DynPRE '
        'constructs requests by interacting with the server to obtain more '
        'samples' + C('dynpre') + '. The former needs annotations or syntax '
        'priors, the latter needs an interactive server.')
    b.p('**Execution traces and program analysis.** Tupni uses dynamic taint '
        'analysis to observe how a parser consumes input bytes in order to '
        'determine boundaries and nesting structure' + C('tupni') + '; Lin et '
        'al. monitor context-aware parsing behaviour in a controlled '
        'environment' + C('lin') + '; Prospex extracts specifications from '
        'program execution and synthesises state machines' + C('prospex') +
        '. Recently this line has moved towards precise format '
        'specifications: NetLifter lifts implementation source code to a '
        'BNF-style specification' + C('netlifter') + ', and ProbePRE drives '
        'the parser into different branches with autonomously constructed '
        'messages' + C('probepre') + '. These methods are accurate but do '
        'not apply to proprietary protocols for which only captures and no '
        'implementation are available.')
    b.p('**Recent advances.** Since 2022 three directions have continued to '
        'advance. The first refines key-field inference: RPKClust partitions '
        'the alignment space by region before inferring keywords'
        + C('rpkclust') + ', and ProInfer selects keywords with probabilistic '
        'statistics' + C('proinfer') + '. The second refines boundaries and '
        'semantics: FSIBP targets automated field semantics inference'
        + C('fsibp') + ', and FineBID pushes the granularity down to '
        'bit level' + C('finebid') + '. The third takes the boundary itself '
        'as the learning target: EBPFI reshapes format inference through '
        'field boundary learning' + C('ebpfi') + ', and Spenny connects '
        'format recovery with security analysis by field-guided symbolic '
        'execution' + C('spenny') + '. These works share the goal of this '
        'paper, but most of them still rely on column statistics after '
        'alignment or on end-to-end learning, and none of them has released '
        'a runnable implementation; the quantitative comparison is therefore '
        'restricted to the three reproducible baselines of Section 7.1.')
    b.p('**Handling of variable-length and key fields.** BinaryInferno '
        'models variable-length fields explicitly with length-value-pair and '
        'repeated-sequence detectors' + C('bininferno') + '; MSERA lists the '
        'length field as a semantic type that needs separate identification'
        + C('msera') + '; NetPlier and REInPro use keywords and control '
        'fields respectively as the basis for clustering'
        + C('netplier', 'reinpro') + '. These works mostly treat key fields '
        'as one more class of fields to output; after identifying them they '
        'do not reorganise the comparison space, so variable-length '
        'misalignment remains and heterogeneous messages are still averaged '
        'in the same column statistics table.')
    b.p('Compared with the above, this paper turns key fields from an output '
        'target into an operator: they are identified not to produce a field '
        'list but to construct recursive splitting operations, so that '
        'boundary inference always takes place on homogeneous subsets with '
        'fixed offsets; the endpoints of key fields themselves become '
        'boundary evidence. In addition, this paper explicitly handles field '
        'reuse that survives splitting, and gives two mechanisms, split-key '
        'reuse and semantic transfer to sample-sparse structures.')
    # ==================== 3 Problem and framework ====================
    b.h1('3 Problem definition and overall framework')
    b.h2('3.1 Notation and problem statement')
    b.p('After reassembling a capture by five-tuple, one obtains a number of '
        'sessions; each session is a sequence of messages with timestamps and '
        'directions, $S=\\{(m_i,t_i,d_i)\\}$, where $m_i$ is the application '
        'payload byte string of the $i$-th message, $t_i$ its capture '
        'timestamp and $d_i$ its transfer direction. Stacking all messages '
        'gives a matrix $M\\in\\mathbb{N}^{N\\times L}$, where $N$ is the '
        'number of messages, $L$ the maximum message length and $M[i,j]$ the '
        'value of the $j$-th byte of the $i$-th message; short messages are '
        'marked with invalid positions at the tail, and the valid-position '
        'mask is written $V\\in\\{0,1\\}^{N\\times L}$. The task of boundary '
        'inference is to produce, for every message, a set of cut points '
        '$B_i\\subset\\{1,\\dots,|m_i|-1\\}$ such that the interval between '
        'two adjacent cut points corresponds to one field.')
    b.p('If a message collection is structurally homogeneous and contains no '
        'variable-length field, then one column corresponds to one field and '
        'column statistics can be used directly to decide boundaries. This '
        'paper groups the factors that break this premise into two classes.')
    b.p('**Definition 1 (structural heterogeneity).** If there exist '
        '$i\\neq i^{\\prime}$ such that the same offset $j$ belongs to '
        'different fields in the two messages, the collection is called '
        'structurally heterogeneous at offset $j$. Heterogeneity turns column '
        'statistics into a mixture of several distributions, and the entropy '
        'of a mixture is never lower than that of any of its components, so '
        'the boundary signal is diluted. **Definition 2 (offset drift).** If '
        'the start offset of field $f$ in $m_i$ differs from its start offset '
        'in the reference message, the collection is said to exhibit offset '
        'drift. Drift is caused by variable-length fields and degenerates '
        'fixed-offset comparison into random comparison.')
    b.p('The goal of KFSI is to identify, with computable criteria, the key '
        'fields that remove these two factors, and to decompose the original '
        'problem recursively into sub-problems that are structurally '
        'homogeneous and offset-consistent, on each of which the final '
        'boundary inference is performed.')
    b.h2('3.2 Overall framework')
    b.p('KFSI proceeds in five stages (Fig. 1). Stage 1 (global semantic '
        'anchors): checksums, strictly increasing sequence numbers and '
        'timestamps that can be verified directly are detected on the whole '
        'batch; their intervals do not depend on comparisons between '
        'messages and can therefore be given as hard constraints. Stage 2 '
        '(region-level key-field identification): structure identifier fields '
        'and length fields are detected on the current region (Section 4). '
        'Stage 3 (split decision): if a structure identifier field meets the '
        'threshold, split horizontally; otherwise, if a length field meets '
        'the threshold, split vertically; if neither is available, go to '
        'stage 5. Stage 4 (recursion): repeat stages 2 and 3 on the '
        'sub-regions, with a bounded depth (Section 5). Stage 5 (leaf '
        'inference): on regions that cannot be split further, compute '
        'position-level evidence and obtain the globally optimal '
        'segmentation by maximum a posteriori decoding with a width prior '
        '(Section 6). After all splitting is finished, one pass of '
        'cross-structure semantic transfer is executed (Section 5.5). The key '
        'design is that **splitting only reduces the problem; the final '
        'answer is produced by evidence fusion on homogeneous '
        'sub-regions**.')
    fig1 = FIG / 'fig1_framework.png'
    if fig1.exists():
        b.figure(str(fig1), 'Fig. 1. Overall framework of KFSI.',
                 width_twips=8200)

    # ==================== 4 Key-field identification ====================
    b.h1('4 Key-field identification')
    b.p('This section gives computable criteria for the two classes of key '
        'fields. The design principle is one criterion per protocol design '
        'constraint, so that criteria are not piled up; the necessity of each '
        'criterion is confirmed by switching it off one at a time in the '
        'ablation study.')
    b.h2('4.1 Structure identifier fields')
    b.p('A structure identifier field (SIF) has three design features: it '
        'comes early, it takes few values, and it determines the subsequent '
        'structure. The first two are easy to test but weakly '
        'discriminative, since any low-entropy column satisfies them; the '
        'third is the essential one, but it describes causality and must be '
        'turned into a computable quantity. Let the message matrix of the '
        'current region be $M$ with valid-position mask $V$, let the '
        'candidate field be located at offset $s$ with width $w$, and let the '
        'value of message $i$ on this field be '
        '$k_i=\\mathrm{val}(M[i,s:s+w])$. Structural consistency over a '
        'column set $\\mathcal{C}$ is defined as the mean of the per-column '
        'mode ratios:')
    b.eq_latex(r'\Phi(M,V,\mathcal{C})=\frac{1}{|\mathcal{C}|}\sum_{j\in'
               r'\mathcal{C}}\frac{1}{N}\max_{v}\sum_{i=1}^{N}'
               r'\mathbb{I}\!\left[M[i,j]=v\right]', 1)
    b.p('that is, the average over columns of the proportion taken by the '
        'most frequent value. After grouping messages by the value of the '
        'candidate field, the weighted mean of the within-group consistency '
        'is:')
    b.eq_latex(r'\Phi_{\mathrm{in}}(k)=\frac{1}{N}\sum_{u\in\mathcal{K}}'
               r'N_u\,\Phi\!\left(M^{(u)},V^{(u)},\mathcal{C}\right),\quad'
               r'\mathcal{K}=\{k_i\}_{i=1}^{N},\;'
               r'N_u=|\{i:k_i=u\}|', 2)
    b.p('where $M^{(u)}$ is the sub-matrix formed by the messages whose value '
        'is $u$. The grouping structure gain is defined as the improvement of '
        'the within-group consistency over the overall one:')
    b.eq_latex(r'G(s,w)=\Phi_{\mathrm{in}}(k)-\Phi(M,V,\mathcal{C})', 3)
    b.p('$G>0$ means that knowing the value of this field makes the layout of '
        'the rest of the message more certain, which is exactly the '
        'computable form of the statement that the field determines the '
        'structure; the larger $G$, the stronger the evidence. Two further '
        'points are needed in the implementation. The first is **locality**: '
        'if all columns of the header are put into $\\mathcal{C}$, random '
        'fluctuations of long payload regions dilute the gain, so both a '
        'global gain and a local gain over the ten columns immediately '
        'following the candidate are computed and the larger one is taken. '
        'The second is **exclusion**: columns inside a printable-string run '
        'and columns with coverage below 95% are not considered as '
        'candidates.')
    b.p('The final score is an OR fusion of two kinds of evidence:')
    b.eq_latex(r'e_{\mathrm{struct}}=\min\!\left(1,'
               r'\frac{\max(0,G)}{G_0}\right)', 4)
    b.eq_latex(r'e_{\mathrm{type}}=\left(1-H_n(k)\right)\pi(s),\quad '
               r'\pi(s)=\begin{cases}1, & s\leq s_0\\ '
               r'e^{-(s-s_0)/\lambda}, & s>s_0\end{cases}', 5)
    b.eq_latex(r's_{\mathrm{SIF}}=\left[1-(1-e_{\mathrm{struct}})'
               r'(1-\alpha\,e_{\mathrm{type}})\right]'
               r'\left(1-\beta+\beta\min\!\left(1,'
               r'\frac{\Delta}{\Delta_0}\right)\right)'
               r'\left(1-\gamma(w-1)\right)', 6)
    b.p('where $H_n$ is the normalised entropy, $\\pi(s)$ the position prior, '
        '$\\Delta$ the mean $L_1$ distance between the column-determinacy '
        'fingerprints of the groups (between-group structural divergence), '
        'and the last term a width penalty. $e_{\\mathrm{type}}$ captures '
        'low entropy with a small value domain, while $e_{\\mathrm{struct}}$ '
        'captures the increase in structural determinacy brought by grouping; '
        'neither is sufficient alone. With only the former, constant columns '
        'are mistaken for type codes; with only the latter, the criterion '
        'fails when the number of groups is small.')
    b.p('In Eqs. (4) to (6), $G_0$, $s_0$, $\\lambda$, $\\alpha$, $\\beta$, '
        '$\\Delta_0$ and $\\gamma$ are **scale parameters**, set to 0.20, '
        '8 bytes, 8 bytes, 0.9, 0.25, 0.3 and 0.1 respectively. They are '
        'scales rather than thresholds: they only compress evidence of '
        'different units into $[0,1]$, so changing them stretches or '
        'compresses the score curve but never turns a positive gain into a '
        'negative one. All scale parameters and the decision threshold are '
        'selected on the calibration set and then fixed; the same values are '
        'shared by all eight protocols. Whether a split is accepted is '
        'decided separately by the score threshold and the gain threshold of '
        'the splitting operator.')
    b.p('**Bit-level structure identifier fields.** Some protocols use a few '
        'bits rather than whole bytes to identify the structure; IEC '
        '60870-5-104, for instance, uses the two low bits of the control '
        'field to distinguish I, S and U frames, and the byte-level criterion '
        'then fails. For every candidate byte this paper enumerates masks '
        '$\\{1,2,4,8,16,32,64,128,3,12,15,240\\}$ (eight single bits and the '
        'four most common multi-bit segments), uses the masked value as the '
        'grouping key and recomputes Eq. (3); bit-level candidates are '
        'accepted under a stricter condition (the structure evidence must be '
        '$\\geq 0.45$, and the number of distinct masked values must lie in '
        '$[2,8]$). A bit-level field only marks the start position of the '
        'byte it lies in, because creating further boundaries inside that '
        'byte is meaningless.')
    b.h2('4.2 Length fields')
    b.p('Deciding that a field is a length field (LF) faces three kinds of '
        'ambiguity: width ambiguity (one byte or two), offset ambiguity '
        '(whether the tail of the preceding field has been absorbed) and '
        'coincidence ambiguity (some content bytes happen to vary together '
        'with the message length). This paper uses four statistics plus two '
        'hard constraints.')
    b.p('(1) **Robust closure.** For a candidate value $v_i$ the residual is '
        '$r_i=|m_i|-v_i$. A genuine length field satisfies that message '
        'length minus field value is a constant, but real protocols often '
        'contain individual messages with padding, extended options or one '
        'extra trailing field, and the standard deviation would be inflated '
        'by such outliers and cause misjudgement. This paper therefore uses '
        'the inlier ratio within $\\pm1$ of the median:')
    b.eq_latex(r'\kappa=\frac{1}{N}\sum_{i=1}^{N}'
               r'\mathbb{I}\!\left[\left|r_i-\mathrm{med}(r)\right|\leq 1'
               r'\right],\quad '
               r'c_{\mathrm{close}}=\frac{\kappa}'
               r'{1+\rho\min(\sigma_r,\sigma_0)}', 7)
    b.p('where $\\mathrm{med}(\\cdot)$ is the median and $\\sigma_r$ the '
        'standard deviation of the residuals. The inlier ratio is insensitive '
        'to a few outliers, while the denominator keeps a penalty for the '
        'overall dispersion: $\\rho=0.25$ is the deduction weight '
        'corresponding to one byte of dispersion and $\\sigma_0=8$ the '
        'saturation point of the penalty; both are selected on the '
        'calibration set together with the scale parameters of Eqs. (4) to '
        '(6).')
    b.p('(2) **Alignment gain.** After shifting the content that follows the '
        'candidate field by $v_i$, the first column of the shifted content '
        'should be highly concentrated if the field really points at a block '
        'boundary:')
    b.eq_latex(r'A(s,w)=\frac{1}{N}\sum_{i=1}^{N}'
               r'\mathbb{I}\!\left[M[i,s+w+v_i]=u^{\ast}\right]-'
               r'\frac{1}{N}\sum_{i=1}^{N}'
               r'\mathbb{I}\!\left[M[i,s+w]=u^{\prime}\right]', 8)
    b.p('where $u^{\\ast}$ and $u^{\\prime}$ are the modes of the two '
        'columns; the quantity measures whether the content of the block is '
        'realigned after shifting by the length field. (3) **Correlation** is '
        'the Pearson correlation coefficient between $v_i$ and the message '
        'length, set to zero if the values are almost constant. (4) '
        '**Structural boundary strength** is the Jensen-Shannon divergence '
        'between the byte distributions inside and outside the interval that '
        'the field points to; it excludes spurious length fields for which '
        'the inside and the outside of the interval are homogeneous.')
    b.p('Two hard constraints are added on top of these. The first is '
        '**natural alignment**: the start offset of a candidate must be an '
        'integer multiple of its width, which removes the width ambiguity '
        'caused by absorbing the tail of the previous field (for example, '
        'merging the two-byte protocol identifier 0x0000 of Modbus/TCP with '
        'the following two-byte length into a four-byte length). The second '
        'is **value-sequence deduplication**: if the same value sequence can '
        'be explained by different widths, the wider interpretation under '
        'natural alignment is taken, because the high byte of a multi-byte '
        'length field is often constantly zero. Single-byte candidates '
        'additionally require at least three distinct values. Length fields '
        'must also exclude printable runs, since otherwise bytes in text that '
        'approximately close with the message length trigger chains of '
        'spurious vertical splits.')
    b.h2('4.3 Directly verifiable semantic anchors')
    b.p('MSERA and related works summarise the data features of typical '
        'semantic fields in industrial control protocols: protocol '
        'identifiers, lengths, sequence numbers, checksums, timestamps and '
        'function codes' + C('msera') + '. These features are not equally '
        'trustworthy. Semantics that are **directly verifiable** (checksums, '
        'strictly increasing sequence numbers, timestamps linearly related to '
        'the capture time) can be decided by deterministic algorithms, and '
        'their errors come mainly from thresholds rather than from model '
        'assumptions, so they can be used as hard constraints that give '
        'intervals directly. Semantics that only **indicate existence** '
        '(protocol identifiers, constant runs) merely say that a field may be '
        'present here; their precise intervals still need data support and '
        'are therefore only used as soft evidence.')
    b.p('Checksums are detected by a prefix-incremental scan. The usual '
        'approach only compares at the message tail and thus covers only the '
        'case of one checksum trailer per message, whereas a protocol such as '
        'DNP3 inserts a CRC16 after every data block, so the checksum occurs '
        'in the middle of the message and its position varies with the '
        'message length. This paper tests $m[p:p+w]=\\mathrm{CRC}(m[:p])$ for '
        'every candidate position $p$ and width $w$, and uses prefix-'
        'incremental computation to reduce the complexity from $O(L^2)$ to '
        '$O(L)$. Degenerate matches are excluded: if the prefix hardly varies '
        'between messages, its checksum hardly varies either and would '
        'automatically agree with any nearly constant byte at that position, '
        'so at least three distinct checksum values are required. The '
        'implementation covers CRC-16 (with parameterisations including '
        'CCITT, XMODEM, MODBUS and DNP), CRC-32, and single-byte additive '
        'and XOR checksums, and tries both big-endian and little-endian byte '
        'orders.')
    b.p('The criterion for a sequence number is a **strict increment of '
        'one**: the proportion of adjacent messages in the same direction '
        'whose difference is exactly one exceeds 85%, and the field has at '
        'least four distinct values; allowing a difference of zero or one '
        'would classify any slowly varying type code as a sequence number. '
        'The criterion for a timestamp is a correlation coefficient of at '
        'least 0.95 with the capture timestamp, with a width of four or '
        'eight bytes. A protocol identifier is taken as a short constant '
        'signature of the first one or two bytes; extending it further would '
        'swallow the length field that follows and whose high byte happens '
        'to be constant (as in the version, reserved and high length byte of '
        'TPKT), so it is only used as soft evidence.')
    # ==================== 5 Recursive splitting ====================
    b.h1('5 Key-field-driven recursive splitting')
    b.p('This section turns the key fields of Section 4 into splitting '
        'operators on a message collection. The central question is: under '
        'what conditions may one field split a region into two (or more) '
        'parts, and which conclusions may be inherited across sub-regions '
        'after splitting and which must be re-estimated.')
    b.h2('5.1 Regions, splitting operators and the invariant')
    b.p('A **region** is defined as a pair $\\mathcal{R}=(S_{\\mathcal{R}},'
        '[a,b))$, where $S_{\\mathcal{R}}\\subseteq S$ is a subset of '
        'messages and $[a,b)$ the offset interval that this subset '
        'considers jointly. The splitting operator $\\mathrm{Split}(\\cdot)$ '
        'maps a region to several sub-regions:')
    b.eq_latex(r'\mathrm{Split}(\mathcal{R})=\{\mathcal{R}_1,\dots,'
               r'\mathcal{R}_K\},\quad \bigcup_{k}\mathcal{R}_k=\mathcal{R},'
               r'\quad \mathcal{R}_k\cap\mathcal{R}_{k^{\prime}}='
               r'\varnothing\;(k\neq k^{\prime})', 9)
    b.p('A split may be **horizontal** (messages are bucketed by field value '
        'and the sub-regions share the same offset interval) or **vertical** '
        '(the offset interval is cut by the interval the field points to and '
        'the sub-regions share the same set of messages). Neither changes the '
        'goal; both only change the sample set on which inference is based. '
        'Splitting must maintain one invariant: **sub-regions are '
        'structurally homogeneous and offset-consistent**, where structural '
        'homogeneity means that different types are no longer mixed in the '
        'subset, and offset consistency means that the same field starts at '
        'the same offset in every message of the subset. This invariant is '
        'the premise for later column statistics to be meaningful, and also '
        'the criterion for whether a split succeeded: if column determinacy '
        'does not increase after splitting, the split was wrong.')
    b.p('The invariant is maintained by three actions in the implementation: '
        'sub-regions recompute their valid columns and column statistics and '
        'do not inherit the results of the parent region; sub-regions '
        're-identify key fields, because the criteria of the parent region '
        'need not hold on the subset; and offsets are recounted from zero in '
        'each sub-region, so that statistics are always defined on columns '
        'relative to that region.')
    b.h2('5.2 Horizontal splitting')
    b.p('Suppose a structure identifier field $f$ (offset $s$, width $w$) '
        'has been identified on region $\\mathcal{R}$; messages are bucketed '
        'by its value:')
    b.eq_latex(r'\mathcal{R}_u=\left(S_u,\,[a,b)\right),\quad '
               r'S_u=\{i\in S_{\mathcal{R}}:k_i=u\},\quad '
               r'u\in\mathcal{K}', 10)
    b.p('For a byte-level field $k_i=M[i,s:s+w]$; for a bit-level field, '
        '$k_i$ is the masked bit value. After bucketing, each bucket is '
        'internally homogeneous and column statistics become comparable '
        'again, but buckets may still share fields, so key fields must '
        'continue to be identified inside each bucket (Section 5.5).')
    b.p('Four constraints are added so that splitting is meaningful. The '
        'number of buckets $K$ must lie in $[2,12]$: too few buckets leave '
        'heterogeneity unremoved, too many leave each bucket with so few '
        'samples that column determinacy rises spuriously through sampling '
        'fluctuation. At least two buckets must contain no fewer than $m_g$ '
        'messages (set to 4). The current region must contain no fewer than '
        '$2m_g$ messages. The same $(a,s,w)$ triple may be used for splitting '
        'only once, to prevent repeated bucketing at the same offset and thus '
        'cycles, which is particularly necessary under bit-level mask '
        'enumeration. Horizontal splitting costs $O(NL)$ and buys the '
        'decomposition of a mixture into several homogeneous distributions. '
        'Consider MQTT: after the fixed header, the field layout differs '
        'completely between the three message classes, so without splitting '
        'the length variation of the topic string is mixed with the message '
        'type on the same column; after bucketing by the four low bits of the '
        'first byte, the order topic length, topic string, message '
        'identifier becomes stable inside the PUBLISH bucket.')
    b.p('Horizontal splitting has an implicit premise: the structure '
        'identifier field sits at the same offset in all structures. For '
        'multi-layer encapsulation protocols, the inner field of the same '
        'name need not be aligned across messages: the same offset may be a '
        'COTP parameter code in structure A and fall inside the S7 header in '
        'structure B, so bucketing by that offset would mix different inner '
        'structures into one bucket. This paper responds by not using '
        'structure identifier fields inside blocks and by limiting the split '
        'depth to three, so that offset drift is eliminated layer by layer. '
        'Acting directly on inner layers would require region alignment '
        'first, which is beyond the scope of this paper.')
    b.h2('5.3 Vertical splitting')
    b.p('Suppose a length field $f$ (offset $s$, width $w$) has been '
        'identified on region $\\mathcal{R}$, with value $v_i$ on message '
        '$i$. Within $[a,b)$ the message is cut into three parts:')
    b.eq_latex(r'[a,\,s)\ |\ [s,\,s+w)\ |\ [s+w,\,s+w+v_i)\ |\ '
               r'[s+w+v_i,\,b)', 11)
    b.p('The three corresponding sub-regions are the prefix '
        '$(S_{\\mathcal{R}},[a,s))$, the block '
        '$(S_{\\mathcal{R}},[s+w,s+w+v_i))$ and the remainder '
        '$(S_{\\mathcal{R}},[s+w+v_i,b))$. The start offsets of the block and '
        'of the remainder vary with $v_i$, so these two sub-regions are not '
        'implemented as cutting a fixed interval, but rather by left-aligning '
        'the corresponding fragment of every message and reassembling a '
        'matrix. This is precisely the operation that removes offset drift: '
        'fields inside the block no longer depend on the length of the '
        'prefix, and fields in the remainder no longer depend on the length '
        'of the block. The three dividing lines become boundary evidence at '
        'the same time: $s$ (between prefix and length field), $s+w$ '
        '(between length field and block start) and $s+w+v_i$ (end of '
        'block). The first two are the same for all messages, the third '
        'differs per message; it is one of the few places where this paper '
        'gives different boundaries per message, and the direct consequence '
        'of the block being a variable-length field.')
    b.p('Blocks need an additional constraint: a block is usually the content '
        'of one variable-length field (a string, an array, a nested message), '
        'so a structure identifier field detected inside it is mostly a '
        'coincidence of content bytes; therefore **only length fields act as '
        'boundary anchors inside a block**, while structure identifier fields '
        'are effective only in the root region, the prefix and the remainder. '
        'Inside a block the method still tries to identify a further length '
        'field first, in order to support peeling multi-layer encapsulation '
        'layer by layer (TPKT, then COTP, then S7comm): the block pointed to '
        'by the outer length field is exactly the inner message, so '
        'identifying a length field again inside the block continues the '
        'peeling until no length field meeting the threshold remains. For '
        'fixed-length messages $v_i$ is the same across messages, vertical '
        'splitting degenerates into three cuts at fixed positions, and its '
        'main effect is to decouple the block from the header so that the '
        'high-entropy content of the block does not pollute the column '
        'statistics of the header.')
    fig2 = FIG / 'fig2_split.png'
    if fig2.exists():
        b.figure(str(fig2), 'Fig. 2. Effect of horizontal and vertical '
                            'splitting.', width_twips=8600)
    b.h2('5.4 Recursion, termination and when to mark endpoints')
    b.p('Splitting terminates in four cases: the maximum depth (set to 3) is '
        'reached; the region contains fewer than four messages; all messages '
        'in the region have identical byte strings; or neither a structure '
        'identifier field nor a length field meets the threshold. On '
        'termination the method switches to leaf inference (Section 6) and '
        'marks all endpoints of the key fields detected in that region as '
        'boundaries.')
    b.p('When to mark the endpoints of key fields is a design point that is '
        'easily overlooked but has large impact. The endpoints of a key field '
        'hold for all messages only on a **structurally homogeneous** region. '
        'If a layer has decided to split further but still marks all '
        'candidate endpoints found at that layer on all messages, the '
        'endpoints of a field of structure A are wrongly marked inside some '
        'large field of messages of structure B, producing clusters of '
        'spurious boundaries in the overlapping header region. The rule of '
        'this paper is therefore: **if the current layer continues to split, '
        'only the field used as the split key is marked** (it lies at the '
        'same offset in all structures, so its endpoints hold for all '
        'messages); all other candidates are left to be re-identified in each '
        'sub-structure, and breadth marking is performed only at leaf '
        'regions.')
    b.p('This rule also explains why the split depth must be bounded. Each '
        'additional level halves the number of messages in a region at least '
        '(horizontal splitting) or shortens the region by at least one block '
        '(vertical splitting), so statistics become less reliable; excessive '
        'depth also breaks the premise that key fields sit at the same offset '
        'in all structures of multi-layer encapsulation protocols. Limiting '
        'the depth to three is a compromise between peeling multiple layers '
        'and keeping enough samples. The complexity of the whole procedure '
        'is $O(D\\cdot N\\cdot L)$ with $D$ the maximum depth, so tens of '
        'thousands of messages are still processed within seconds.')
    b.h2('5.5 Cross-structure semantic sharing and transfer')
    b.p('Even after horizontal splitting, messages of different structures '
        'still share some fields, a reuse that protocol designers introduce '
        'to simplify implementation. This paper exploits this phenomenon with '
        'two mechanisms. **Mechanism A (split-key reuse).** A structure '
        'identifier field chosen as the split key lies at the same offset in '
        'all structures, so once it has been identified in the root region, '
        'its endpoints hold for all structures and need not be re-identified '
        'in every sub-structure. **Mechanism B (transfer after local '
        'verification).** After horizontal splitting, key fields are inferred '
        'independently in each structure, which easily leads to an imbalance '
        'in which structures with many samples are detected stably while '
        'structures with few samples are missed. A second pass is therefore '
        'added after all splitting: for each structure $G$, take a key field '
        '$f$ whose score on a sibling structure is at least 0.6, verify it '
        'locally on $G$, and only if verification passes add the endpoints '
        'of $f$ as boundaries of $G$.')
    b.p('The verification criterion depends on the field type. If $f$ is a '
        'length field, the residual inlier ratio must be at least 0.9 and the '
        'values must vary, that is')
    b.eq_latex(r'\kappa_{G}(f)\geq 0.9\ \ \wedge\ \ '
               r'\left|\{v_i^{(G)}\}\right|>1', 12)
    b.p('If $f$ is a structure identifier field, its value cardinality must '
        'lie in $[2,20]$ and its coverage must be at least 60%. Both '
        'conditions mean the same thing: a transferred hypothesis must hold '
        'again on the **own data** of the structure, not merely on the '
        'evidence of a sibling structure. The point of this design is '
        'verification rather than copying, so it closes misses on '
        'sample-sparse structures without importing the errors of sibling '
        'structures. A constant prefix at the start of a message can also be '
        'shared across structures, but its interval often spans several real '
        'fields (such as version, reserved and the high length byte of TPKT), '
        'so it is only used to give endpoints and does not take part in the '
        'soft constraint that forbids splitting inside an interval.')

    # ==================== 6 Evidence fusion and decoding ====================
    b.h1('6 Boundary evidence fusion and maximum a posteriori decoding')
    b.h2('6.1 Position-level evidence features')
    b.p('On a leaf region, 18 features are computed for every candidate cut '
        'position $p\\in[1,L)$. Their design follows one principle: any '
        'single feature can be fooled by an individual protocol, but when '
        'structural change, value dependence and semantic anchors hold at '
        'the same time, the probability of misjudgement is low. For later '
        'reference, Table 1 lists the notation, definition and decision '
        'direction of each feature, where $\\mathrm{det}(j)$ is the mode '
        'ratio of column $j$, $H_n(j)$ the normalised entropy of column $j$ '
        'and $\\mathrm{MI}$ the mutual information of two columns.')
    b.table('Table 1. Position-level cut evidence features ($p$ is the '
            'candidate cut position; the two sides are columns $p-1$ and '
            '$p$).',
            ['Class', 'Notation', 'Meaning and decision direction'],
            [['Value dependence', '$1-\\rho_p$',
              'Normalised complement of the mutual information between the '
              'two columns; the closer to 1, the more likely a boundary'],
             ['', '$\\rho_p$',
              'Normalised mutual information of the two columns (coupling); '
              'the higher, the more likely they belong to one field'],
             ['', '$\\mathrm{MI}_p$',
              'Raw mutual information of the two columns; distinguishes the '
              'absolute strength of coupling'],
             ['', '$\\Delta\\mathrm{det}_p$',
              'Difference of the mode ratios of the two columns; a jump '
              'suggests a boundary'],
             ['', '$\\mathrm{det}_{p-1},\\ \\mathrm{det}_p$',
              'Absolute mode ratios of the left and right columns'],
             ['', '$\\beta_p$',
              'Constant-break flag: 1 when one side is constant and the '
              'other varies'],
             ['Distribution change', '$\\Delta H_p$',
              'Difference of the normalised entropies of the two columns; an '
              'entropy jump suggests a boundary'],
             ['', '$H_p$', 'Normalised entropy of the right column'],
             ['', '$\\bar{H}_{\\mathrm{L}},\\ \\bar{H}_{\\mathrm{R}}$',
              'Mean normalised entropy over four columns to the left and to '
              'the right; captures local smoothness'],
             ['Structural change', '$\\ell_p$',
              'Length of the run of constant columns to the left (truncated '
              'at 4)'],
             ['', '$\\varepsilon_p$',
              'Whether the position is close to the start or end of the '
              'region ($p\\leq2$ or $L-p\\leq2$)'],
             ['', '$p/L$',
              'Relative position; suppresses accidental changes far inside '
              'the payload'],
             ['Content nature', '$\\pi_p$', 'Whether the position is the '
              'start of the payload region'],
             ['', '$\\sigma_p$',
              'Whether the two sides lie within the same printable-string '
              'run'],
             ['Semantic anchor', '$\\alpha_p$',
              'Whether the position is the start of a semantic field'],
             ['', '$\\iota_p$',
              'Whether the position lies inside a semantic field (splitting '
              'is suppressed there)']],
            [1500, 2300, 5300])
    b.p('The 18 features are not equally weighted; they are combined '
        'linearly into one scalar score, the log-odds of cutting at '
        'position $p$')
    b.eq_latex(r'z_p=\mathbf{w}^{\top}\mathbf{x}_p+b,\quad '
               r'\mathbf{x}_p\in\mathbb{R}^{18}', 13)
    b.p('where $\\mathbf{w}$ and $b$ are obtained by logistic regression '
        'trained on the calibration set with whether a position is a '
        'reference boundary as the label; the test set does not take part, '
        'so that the comparison remains fair.')
    b.h2('6.2 Field width prior and its role')
    b.p('Header fields are mostly one to four bytes wide, followed by eight '
        'bytes (timestamps, double-precision floats), while very long fields '
        'occur mainly in the payload. This motivates the following log prior '
        'on field width:')
    b.eq_latex(r'\log P(w)=\begin{cases}-0.50, & w=1\\ -0.42, & w=2\\ '
               r'-0.95, & w=4\\ -1.35, & w=3\\ -1.25, & w=8\\ '
               r'-1.9-1.05\ln w, & w\geq 9\end{cases}', 14)
    b.p('Widths from five to seven bytes take values $-2.1\\sim-2.3$ by '
        'interpolation. The power-law tail keeps a considerable prior '
        'probability for treating a whole payload as one long field, so that '
        'the decoder does not chop the payload apart by force.')
    b.p('This prior acts as **regularisation**, not as a post-hoc check of '
        'whether a segmentation conforms to common widths. Used as a post-hoc '
        'check (cut by evidence first, then test whether the widths are '
        'plausible), one wrong cut forces later positions to keep miscutting '
        'in order to produce common widths, and the error accumulates in one '
        'direction along the message. This paper puts the prior and the '
        'evidence into the **same objective function** and optimises them '
        'jointly (Section 6.3). The prior enters the objective only through '
        'the width difference between the two segments adjacent to a '
        'boundary and does not change the position-level score $z_p$, so '
        'positions with strong evidence are never moved, only possibly '
        'vetoed; and since $\\log P(w)$ is non-increasing in $w$, merging '
        'two segments is never worse than cutting them, so the prior never '
        '**forces** a new boundary and only **blocks** one when the evidence '
        'is insufficient. Its failure mode is therefore confined to missing '
        'one boundary, which is local and bounded, rather than to cutting '
        'several times in order to satisfy a width distribution, which is '
        'global and divergent.')
    b.h2('6.3 Maximum a posteriori decoding')
    b.p('Writing the set of cut points as $F$, the optimal segmentation is '
        'given by')
    b.eq_latex(r'F^{\ast}=\underset{F}{\mathrm{arg\,max}}\ \sum_{p\in F}'
               r'\left(z_p-\theta\right)+'
               r'\sum_{w\in\mathcal{W}(F)}\log P(w)', 15)
    b.p('where $\\theta$ is the decision threshold and $\\mathcal{W}(F)$ the '
        'set of segment widths induced by $F$. Equation (15) balances the '
        'gain of cutting against the cost of fields that are too fine or too '
        'coarse, and can be solved exactly by dynamic programming in '
        '$O(L\\,w_{\\max})$ time:')
    b.eq_latex(r'\mathrm{best}[j]=\max_{1\leq w\leq w_{\max}}'
               r'\left\{\mathrm{best}[j-w]+\log P(w)+'
               r'\mathbb{I}[j-w>0]\left(z_{j-w}-\theta\right)\right\}', 16)
    b.p('where $\\mathrm{best}[j]$ is the optimal score of the prefix '
        '$[0,j)$ and $w_{\\max}$ the maximum field width. Dynamic '
        'programming keeps only the best predecessor for each position, '
        'giving a globally optimal solution rather than a greedy one, which '
        'is essential for suppressing wrong cuts caused by locally strong '
        'evidence. The threshold $\\theta$ does not tune the decision at a '
        'single position; it controls the average field width globally: the '
        'larger $\\theta$, the more the decoder tends to merge adjacent '
        'segments. The value of $\\theta$ is selected on a development set '
        'that is independent of the test set, and all experiments share the '
        'same value.')
    b.h2('6.4 Coverage truncation')
    b.p('After vertical splitting, the length of the remainder varies '
        'between messages, so later columns may be covered by only a few '
        'long messages. Cutting on such columns imposes the internal '
        'structure of individual long messages on all messages and produces '
        'clusters of false positives. The coverage of column $c$ is '
        'therefore defined and used to truncate the valid columns:')
    b.eq_latex(r'\mathrm{cov}(c)=\frac{1}{N}\sum_{i=1}^{N}'
               r'\mathbb{I}\left[c<|m_i|\right],\quad '
               r'L_c=\max\left\{c:\mathrm{cov}(c)\geq c_{\min}\right\}+1', 17)
    b.p('Cutting is allowed only for $c<L_c$; beyond that point the common '
        'prefix of the region is considered to have ended. Figure 3 gives an '
        'example: in a remainder region of ten messages whose lengths range '
        'from 34 to 52 bytes, coverage decreases monotonically with the '
        'column offset; with $c_{\\min}=0.6$ the truncation point is '
        '$L_c=41$, and the following eleven columns carry content in at most '
        'five long messages. Without truncation, cuts on these columns would '
        'infer, from the structure of five messages, fields that do not '
        'exist in the other five, and the resulting cut points would be '
        'counted as false positives of the latter.')
    fig3 = FIG / 'fig3_coverage.png'
    if fig3.exists():
        b.figure(str(fig3), 'Fig. 3. Example of coverage truncation '
                            '($c_{\\min}=0.6$, truncation point $L_c=41$).',
                 width_twips=8600)
    b.p('The cost of truncation is that real boundaries at the tail of long '
        'messages may be missed, so $c_{\\min}$ should not be too high. The '
        'sensitivity analysis shows that varying $c_{\\min}$ between 0.4 and '
        '0.9 changes F1 by less than 0.2 percentage points: whether to '
        'truncate matters more than where to truncate.')
    # ==================== 7 Experiments ====================
    b.h1('7 Experiments and results')
    b.h2('7.1 Experimental setup')
    b.p(f'**Datasets and partition.** The test set consists of captures of '
        f'{len(order)} real protocols (Table 2) with {n_msg} application-'
        'layer messages in total, covering industrial control (Modbus/TCP, '
        'DNP3, IEC 60870-5-104, S7comm, BACnet), process automation '
        '(HART-IP), the Internet of Things (MQTT) and generic RPC (DCERPC). '
        'Structural complexity is graded, from Modbus/TCP with a single '
        'fixed-length structure, through MQTT with a variable-length topic '
        'string, to S7comm with three-layer encapsulation (Table 2).')
    STRUCT = {'bacnet': 'BVLL/NPDU + variable-length TLV',
              'DCERPC': 'RPC header + variable-length body',
              'dnp3': 'Link frame + block-level CRC',
              'hart_ip': 'Fixed header + variable-length PDU',
              'IEC104': 'APCI/ASDU + bit-level frame flag',
              'modbus': 'MBAP + PDU',
              'MQTT': 'Variable remaining length + topic string',
              'S7comm': 'TPKT/COTP/S7 three-layer encapsulation'}
    HAS_LF = {'bacnet': 'Yes', 'DCERPC': 'Yes', 'dnp3': 'Yes',
              'hart_ip': 'Yes', 'IEC104': 'Yes', 'modbus': 'Yes',
              'MQTT': 'Yes (variable)', 'S7comm': 'Yes (multi-layer)'}
    SIF_NAME = {'bacnet': 'service choice', 'DCERPC': 'ptype / opnum',
                'dnp3': 'function code', 'hart_ip': 'message type',
                'IEC104': 'bit-level frame type', 'modbus': 'function code',
                'MQTT': 'hdrflags', 'S7comm': 'rosctr / COTP parameter code'}
    b.table('Table 2. Test data.',
            ['Protocol', 'Messages', 'Structural characteristics',
             'Length field', 'Structure identifier field'],
            [[p, str(rows[p]['messages']), STRUCT[p], HAS_LF[p], SIF_NAME[p]]
             for p in order],
            [1200, 1100, 3400, 1400, 2400])
    b.p('**Three-way partition and decontamination.** The calibration, '
        'development and test parts do not overlap **at either file level or '
        'message level**. The calibration corpus is taken from eleven public '
        'captures (2268 messages) covering six protocols, DNP3, BACnet, '
        'Modbus/TCP, S7comm, IEC 104 and MQTT; the development corpus '
        'consists of five further captures (344 messages) and is used only '
        'to scan the decision threshold $\\theta$; the test set consists of '
        'eight independent captures. Different files alone are not enough: '
        'the test set and the public repository share their origin (the DNP3 '
        'test file is byte-identical to the file of the same name in the '
        'public repository), and measurement shows that 77.8% of the '
        'messages of one public DNP3 capture and 63.3% of the messages of '
        'the public HART-IP capture also occur in the test set. '
        '**Message-level decontamination** is therefore performed before '
        'calibration: the byte hashes of all messages of the test set form a '
        'blacklist, and byte-identical messages do not take part in '
        'calibration or threshold selection (in practice 11 messages of IEC '
        '104 and 4 of MQTT were removed). The HART-IP capture was excluded '
        'from calibration and development altogether because of its high '
        'degree of overlap, so that its score is a genuine zero-shot '
        'result.')
    b.p('**Calibration protocol.** The 18 weights of the position-level '
        'evidence model are fitted by logistic regression on the calibration '
        'corpus; the decision threshold $\\theta$ is fixed after a grid scan '
        'on the development set using F1 as the criterion, and the test set '
        'takes part neither in fitting nor in threshold selection. To make '
        'reproduction easier, a training-free configuration is also given: '
        'the prior weights (without fitting) are used with the same '
        'threshold, and the result does not differ significantly from the '
        'calibrated configuration (Section 7.5), showing that the method '
        'does not depend on training.')
    b.p('**Reference parsing and evaluation criteria.** The reference '
        'parsing is produced from the PDML output of tshark' + C('tshark') +
        ': the protocol tree of every message is parsed and the start and '
        'end offsets of every field inside the application payload are '
        'taken, and four criteria are defined by nesting level and bit '
        'width: V1, all fields; V2, byte-level (bit fields excluded); V3, '
        'first-level fields (empty parent node), which is the **main '
        'criterion**; V4, first-level byte-level.')
    b.p('The position criterion matches predicted cut points against the '
        'start of reference fields with a tolerance of $\\pm1$ byte, using '
        'one-dimensional interval bipartite matching (assigning the earliest '
        'unoccupied prediction inside the window in ascending order of '
        'reference points), a strategy that provably attains the maximum '
        'number of matches. A greedy left-to-right pass over predictions '
        'would instead let a left prediction in a cluster of predictions '
        'take the reference point away, recording a prediction that should '
        'have matched as a false positive and systematically '
        'underestimating precision. The interval criterion uses the '
        '**intersection over union** (IoU), that is, the Jaccard '
        'coefficient of two sets of intervals. For a predicted interval '
        '$I_p=[b_p,e_p)$ and a reference interval $I_g=[b_g,e_g)$:')
    b.eq_latex(r'\mathrm{IoU}(I_p,I_g)=\frac{|I_p\cap I_g|}{|I_p\cup I_g|}='
               r'\frac{\max\left(0,\min(e_p,e_g)-\max(b_p,b_g)\right)}'
               r'{\max(e_p,e_g)-\min(b_p,b_g)}', 18)
    b.p('The decision threshold is 0.5, requiring the overlap to be at least '
        'half of the union. This is stricter than requiring the predicted '
        'start to fall inside the reference interval, because it constrains '
        'both ends of an interval, and it is also harder to game with dense '
        'predictions scattered over many positions. Both criteria count only '
        'messages of at least four bytes.')
    b.p('**Compared methods.** Three methods published in 2023-2024 with '
        'public implementations are selected; all are re-implemented on the '
        'same input and under the same criterion, and their respective '
        'optimal hyper-parameters are selected on the same calibration set: '
        '(1) BinaryInferno' + C('bininferno') + ', which builds a detector '
        'set from atomic type detectors (fixed-length integers, sequences, '
        'length-value pairs) and a Shannon-entropy boundary detector, then '
        'integrates competing hypotheses by conflict resolution and takes the '
        'one with the strongest evidence as the boundary; (2) REInPro'
        + C('reinpro') + ', which first identifies the control field that '
        'determines the message structure with a probabilistic model of '
        'traffic behaviour, clusters messages by its value, and then locates '
        'boundaries by comparing field features within each cluster; (3) PFT'
        + C('pft') + ', which organises a message as a field tree, merging '
        'adjacent bytes bottom-up with a merge criterion given by a mixture '
        'of heuristic rules (constant runs) and statistical tests '
        '(dependence between the values of adjacent columns). The three '
        'represent, respectively, semantic detector integration, '
        'control-field-driven clustering and hybrid tree models, and form a '
        'contrast with the key-field-driven splitting of this paper.')
    if bl:
        b.h2('7.2 Overall results')
        b.p(f'Table 3 gives the overall measures of all methods under the V3 '
            f'criterion. KFSI attains a micro F1 of '
            f'{f4(summ["micro_F1"])}, a macro F1 of '
            f'{f4(summ["macro_F1"])} and an interval F1 of '
            f'{f4(summ["iou_micro_F1"])}, all higher than the three '
            f'baselines; relative to the strongest baseline '
            f'{bl_name[max(bl, key=lambda k: bl[k]["micro_F1"])]} '
            f'({f4(best_bl["micro_F1"])}) the improvement is '
            f'{100 * gain:.1f}%. Even under the tuning most favourable to '
            'the baselines, that is, choosing the best value of their grid '
            f'on the test set (the strongest, PFT, reaches '
            f'{f4(best_bl_or["F1"])}), KFSI still leads by '
            f'{100 * gain_or:.1f}%, so the advantage cannot be attributed to '
            'insufficient tuning of the baselines.')
        trows = [['KFSI (batch inference)', f4(summ['micro_P']),
                  f4(summ['micro_R']), f4(summ['micro_F1']),
                  f4(summ['macro_F1']), f4(summ['iou_micro_F1'])],
                 ['KFSI (isolated setting)', f4(iso['micro_P']),
                  f4(iso['micro_R']), f4(iso['micro_F1']),
                  f4(iso['macro_F1']), f4(iso['iou_micro_F1'])]]
        ref_key = {'binaryinferno': 'bininferno', 'pft': 'pft',
                   'reinpro': 'reinpro'}
        for k in ('reinpro', 'pft', 'binaryinferno'):
            if k in bl:
                r = bl[k]
                trows.append([bl_name[k] + C(ref_key[k]), f4(r['micro_P']),
                              f4(r['micro_R']), f4(r['micro_F1']),
                              f4(r['macro_F1']), '-'])
        b.table('Table 3. Overall measures of all methods (V3 first-level '
                'fields, position tolerance +-1 byte).',
                ['Method', 'Precision', 'Recall', 'F1', 'Macro F1',
                 'Interval F1'],
                trows, [2300, 1250, 1250, 1250, 1450, 1450])
        b.p(f'The second row of Table 3 gives the **isolated setting**: the '
            f'same model and the same threshold, but for each protocol only '
            'the last 30% of the messages, cut in chronological order, are '
            'fed to the engine, simulating a situation in which only a small '
            f'amount of traffic is observable. F1 then drops to '
            f'{f4(iso["micro_F1"])}, still above the strongest baseline at '
            f'{f4(best_bl["micro_F1"])}. The difference between the two '
            'settings comes entirely from the number of available messages: '
            'splitting and key-field identification are both batch '
            'statistics, and the fewer the samples, the less reliable column '
            'coverage and structural grouping become. This paper takes batch '
            'inference as the main setting (consistent with how comparable '
            'methods are used) and reports the isolated setting as a lower '
            'bound for traffic-constrained situations.')
        b.p('In terms of the precision-recall trade-off, the recall of the '
            'three baselines is generally insufficient ('
            f'{f4(bl["binaryinferno"]["micro_R"])}, '
            f'{f4(bl["pft"]["micro_R"])}, '
            f'{f4(bl["reinpro"]["micro_R"])}), showing that all of them tend '
            'to under-split: in dense header regions they dare to give only '
            f'the few most obvious boundaries. KFSI keeps precision at '
            f'{f4(summ["micro_P"])} while raising recall to '
            f'{f4(summ["micro_R"])}, because splitting first removes the two '
            'factors that disable the evidence, namely different types being '
            'mixed together and offsets drifting from message to message; '
            'only on homogeneous regions can the evidence afford to give '
            'boundaries at more positions.')
        btab = {m: {r['protocol']: r['F1'] for r in v['rows']}
                for m, v in bl.items()}
        rank = {}
        for p in order:
            vals = {'KFSI': rows[p]['F1']}
            for m in btab:
                vals[m] = btab[m].get(p, 0.0)
            srt = sorted(vals.values(), reverse=True)
            rank[p] = srt.index(rows[p]['F1']) + 1
        n_first = sum(1 for p in order if rank[p] == 1)
        lose = [p for p in order if rank[p] != 1]
        beat = {p: max(btab, key=lambda m: btab[m].get(p, 0.0)) for p in lose}
        b.p(f'Figure 4 and Table 4 give the per-protocol results. KFSI ranks '
            f'first on {n_first} of the {len(order)} protocols, and the '
            f'reasons for falling behind on the remaining {len(lose)} differ. '
            'The gap is largest on IEC 104, and its root cause is the '
            'reference granularity: tshark reports the control field of I, S '
            'and U frames as one field of four to six bytes, so under-splitting '
            'happens to agree with the reference, while the finer division by '
            f'KFSI inside the control field is counted as false positives, '
            f'giving a precision of only {f4(rows["IEC104"]["P"])}. On BACnet '
            'the gap comes from field shape: its header is short and dense, '
            'so the byte-wise boundaries of the atomic type detectors of '
            'BinaryInferno are closer to the reference, whereas KFSI is '
            'conservative in the variable-length TLV region because of the '
            'coverage constraint. On DNP3 the difference is at the level of '
            'noise, since the strongly periodic structure of block-level CRC '
            'is friendly to both sides. It should be stressed that all three '
            'cases of falling behind are matters of granularity orientation '
            'rather than of localisation error: their interval F1 values are '
            f'{f4(rows["IEC104"]["iou_F1"])}, '
            f'{f4(rows["bacnet"]["iou_F1"])} and '
            f'{f4(rows["dnp3"]["iou_F1"])}, showing that the boundaries '
            'given lie mostly near real ones. The under-splitting strategy of '
            'the baselines wins on these protocols but collapses in recall on '
            'DCERPC and S7comm, the protocols with the most messages, which '
            'shows up in the macro average: REInPro reaches '
            f'{f4(bl["reinpro"]["macro_F1"])}, below the '
            f'{f4(summ["macro_F1"])} of KFSI.')
        fig4 = FIG / 'fig4_results.png'
        if fig4.exists():
            b.figure(str(fig4), 'Fig. 4. Per-protocol F1 comparison (V3 '
                                'first-level fields).', width_twips=7900)
        b.table('Table 4. Per-protocol F1 comparison (V3 first-level fields, '
                'position tolerance +-1 byte).',
                ['Protocol', 'Messages', 'Precision', 'Recall', 'F1',
                 'Interval F1', 'Binary\nInferno', 'REInPro', 'PFT'],
                [[p, str(rows[p]['messages']), f4(rows[p]['P']),
                  f4(rows[p]['R']), f4(rows[p]['F1']),
                  f4(rows[p]['iou_F1']), f4(btab['binaryinferno'].get(p, 0.0)),
                  f4(btab['reinpro'].get(p, 0.0)),
                  f4(btab['pft'].get(p, 0.0))] for p in order],
                [1250, 700, 860, 860, 860, 900, 1250, 1050, 950])
        b.p(f'The strengths of the baselines do not overlap. PFT comes '
            f'closest to this paper on hart_ip (because the header offsets of '
            'that protocol are fixed and its block boundaries are clear, so '
            'the merge criterion of the field tree happens to work), with '
            f'{f4(btab["pft"]["hart_ip"])} against '
            f'{f4(rows["hart_ip"]["F1"])}. BinaryInferno overtakes KFSI on '
            f'bacnet ({f4(btab["binaryinferno"]["bacnet"])} against '
            f'{f4(rows["bacnet"]["F1"])}) but is clearly weaker on MQTT '
            f'({f4(btab["binaryinferno"]["MQTT"])}), showing that a strategy '
            'of giving boundaries byte by byte works in headers with dense '
            'short fields but fails on variable-length topic strings. On '
            'S7comm and DCERPC, the protocols with the most messages, all '
            'three fail clearly, because multi-layer encapsulation makes the '
            'same offset correspond to fields of different layers in '
            'different messages, so any method that computes statistics at a '
            'single offset conflates the three layers.')
        b.p('This comparison confirms the starting point of this paper: a '
            'single criterion, whether a structural shift, an atomic type or '
            'control-field clustering, can cover only part of the '
            'difficulty, whereas split-first, infer-second assigns different '
            'difficulties to different stages: heterogeneity to horizontal '
            'splitting, drift to vertical splitting, and the remaining local '
            'ambiguity to evidence fusion.')
    if sc:
        b.h2('7.3 Effect of reference granularity')
        b.p(f'Table 5 gives the results under the four reference '
            'granularities. As the reference becomes finer (V1 includes all '
            'nested fields), recall drops while precision stays roughly the '
            f'same: under V1 precision is '
            f'{f4(sc["V1_全部字段"]["micro"]["precision"])} and recall '
            f'{f4(sc["V1_全部字段"]["micro"]["recall"])}. The output of KFSI '
            'is therefore few but accurate: most of the boundaries it gives '
            'can be matched in the reference parsing, but in multi-layer '
            'encapsulation protocols it does not cut out every sub-field '
            'inside every layer. For reverse engineering scenarios in which '
            'manual verification dominates, this bias is preferable: false '
            'positives must be excluded one by one by hand, whereas a miss '
            'only requires looking at one more place.')
        SC_LABEL = {'V1_全部字段': 'V1 all fields',
                    'V2_字节级': 'V2 byte-level',
                    'V3_一级字段': 'V3 first-level fields',
                    'V4_一级字节级': 'V4 first-level byte-level'}
        b.table('Table 5. Measures under different reference granularity.',
                ['Criterion', 'Precision', 'Recall', 'F1', 'Macro F1'],
                [[SC_LABEL[s], f4(sc[s]['micro']['precision']),
                  f4(sc[s]['micro']['recall']), f4(sc[s]['micro']['f1']),
                  f4(sc[s]['macro_F1'])]
                 for s in ['V1_全部字段', 'V2_字节级', 'V3_一级字段',
                           'V4_一级字节级']],
                [2600, 1400, 1400, 1400, 1600])
        b.p('The difference between criteria is essentially a difference in '
            'the evaluation standard: measures of boundary inference depend '
            'heavily on what counts as one field. On multi-layer '
            'encapsulation protocols the first-level-field criterion of '
            'tshark reports an entire inner header as one field, so any '
            'finer split is counted as a false positive. This paper reports '
            'all four criteria V1 to V4 to mitigate this problem and takes '
            'V3 as the main criterion.')
    if kf and kfa:
        b.h2('7.4 Accuracy of key-field identification')
        b.p('Table 6 gives the accuracy of key-field identification, counted '
            'under the position criterion: the start of a detected length '
            'field or structure identifier field is matched with tolerance '
            'against the starts of all fields of the same kind in the '
            'reference parsing of that protocol. A protocol-level detection '
            'rate is also given: a protocol counts as successfully detected '
            'as soon as it has at least one correct hit.')
        b.table('Table 6. Accuracy of key-field identification (deduplicated '
                'position sets within each protocol).',
                ['Protocol', 'LF precision', 'LF recall', 'LF F1',
                 'SIF precision', 'SIF recall', 'SIF F1'],
                [[r['protocol'], f4(r['len_v3_p']), f4(r['len_v3_r']),
                  f4(r['len_v3_f']), f4(r['type_v3_p']), f4(r['type_v3_r']),
                  f4(r['type_v3_f'])] for r in kf],
                [1400, 1250, 1250, 1250, 1250, 1250, 1250])
        b.p(f'Precision, recall and F1 are '
            f'{f4(kfa["len"][0])}/{f4(kfa["len"][1])}/{f4(kfa["len"][2])} for '
            f'length fields and '
            f'{f4(kfa["type"][0])}/{f4(kfa["type"][1])}/'
            f'{f4(kfa["type"][2])} for structure identifier fields. The '
            f'protocol-level detection rate is {kfa["ok_len"]}/{kfa["n"]} for '
            f'length fields and {kfa["ok_type"]}/{kfa["n"]} for structure '
            'identifier fields. The latter is zero on dnp3 and MQTT because '
            'the reference parsing of these two protocols contains no '
            'top-level field named type, func or code (the function code of '
            'dnp3 is nested inside the ctrl field and the message type of '
            'MQTT is named hdrflags), not because the method failed to '
            'detect it. Recall is lower than for length fields because a '
            'protocol often has several structure identifier fields while '
            'splitting needs to locate only one of them.')
    if ab:
        b.h2('7.5 Ablation study')
        b.p('Table 7 and Figure 5 give the ablation results. "w/o key-field '
            'endpoints" means that endpoints are not used directly as '
            'boundaries; "w/o local structure gain" means that the structure '
            'identifier score uses only the global gain; "w/o width prior" '
            'means that the prior is set to uniform, in which case decoding '
            'is equivalent to per-position thresholding, so "w/o MAP '
            'decoding" is not listed separately.')
        av = {r['variant']: r for r in ab}
        base = av['KFSI_full']['f1']
        skip = {'w/o 水平+垂直', 'w/o MAP 解码'}
        VAR_EN = {'KFSI_full': 'KFSI full',
                  'w/o 水平分裂': 'w/o horizontal splitting',
                  'w/o 垂直分裂': 'w/o vertical splitting',
                  'w/o 关键字段端点': 'w/o key-field endpoints',
                  'w/o 语义锚点': 'w/o semantic anchors',
                  'w/o 跨结构迁移': 'w/o cross-structure transfer',
                  'w/o 宽度先验': 'w/o width prior',
                  'w/o 比特级 SIF': 'w/o bit-level SIF',
                  'w/o 学习权重': 'w/o learned weights',
                  'w/o 局部结构增益': 'w/o local structure gain'}
        arows = []
        for r in ab:
            if r['variant'] in skip:
                continue
            arows.append([VAR_EN.get(r['variant'], r['variant']),
                          f4(r['precision']), f4(r['recall']), f4(r['f1']),
                          f'{100 * (r["f1"] - base):+.2f}',
                          f4(r['macro_F1'])])
        b.table('Table 7. Ablation results (V3 first-level fields).',
                ['Configuration', 'Precision', 'Recall', 'F1',
                 'Delta F1 (pp)', 'Macro F1'],
                arows, [3000, 1100, 1100, 1100, 1500, 1400])
        fig5 = FIG / 'fig5_ablation.png'
        if fig5.exists():
            b.figure(str(fig5), 'Fig. 5. Delta F1 of the ablation study '
                                '(relative to the full method).',
                     width_twips=8000)
        b.p(f'Four observations can be read off. First, key-field endpoints '
            f'as boundaries contribute most: removing them drops F1 from '
            f'{f4(base)} to {f4(av["w/o 关键字段端点"]["f1"])} and recall to '
            f'{f4(av["w/o 关键字段端点"]["recall"])}, so key-field '
            'identification is not an additional feature but the main source '
            f'of boundary conclusions. Second, horizontal and vertical '
            f'splitting contribute {100 * (base - av["w/o 水平分裂"]["f1"]):.2f} '
            f'and {100 * (base - av["w/o 垂直分裂"]["f1"]):.2f} percentage '
            'points respectively, and the loss of the former is concentrated '
            f'in recall ({f4(av["w/o 水平分裂"]["recall"])}), showing that it '
            'handles heterogeneity mixing and cancelling the evidence, a '
            'different difficulty from the variable-length drift handled by '
            'vertical splitting.')
        b.p(f'Third, "w/o local structure gain" loses '
            f'{100 * (base - av["w/o 局部结构增益"]["f1"]):.2f} percentage '
            'points, the second largest component after endpoints: random '
            'fluctuations in long payload regions dilute the global gain, '
            'genuine structure identifier fields do not obtain a positive '
            'gain and horizontal splitting fails as a whole, so the locality '
            'treatment of Section 4.1 is a precondition for the criterion to '
            f'hold rather than an implementation detail. Fourth, semantic '
            'anchors and cross-structure transfer contribute less ('
            f'{100 * (base - av["w/o 语义锚点"]["f1"]):.2f} and '
            f'{100 * (base - av["w/o 跨结构迁移"]["f1"]):.2f} percentage '
            'points), but their gain is diluted by a few protocols, so they '
            'are low-frequency yet irreplaceable components.')
        lo, hi = {}, {}
        if abt:
            def _norm(r):
                return {'variant': r['variant'], 'theta': r['theta'],
                        'precision': r['P'], 'recall': r['R'], 'f1': r['F1']}
            lo = {r['variant']: _norm(r) for r in abt
                  if abs(r['theta'] - 1.0) < 1e-9}
            hi = {r['variant']: _norm(r) for r in abt
                  if abs(r['theta'] - 4.0) < 1e-9}
        if lo and hi:
            b.p(f'The relation between the width prior and the decoding '
                'scheme needs separate explanation. Under the threshold '
                f'$\\theta={theta:.2f}$ adopted in this paper, "w/o width '
                f'prior" and the full method agree bit for bit (both F1 = '
                f'{f4(hi["KFSI_full"]["f1"])}). This is not an '
                'implementation failure but a consequence of the high '
                'threshold: $\\theta$ has already filtered out all positions '
                'with weak evidence, so the width prior has nothing to '
                'correct. Lowering the threshold to 1.0 separates them '
                f'immediately: the full method gives '
                f'{f4(lo["KFSI_full"]["f1"])} and removing the width prior '
                f'gives {f4(lo["w/o 宽度先验"]["f1"])} '
                f'({100 * (lo["w/o 宽度先验"]["f1"] - lo["KFSI_full"]["f1"]):+.2f} '
                'percentage points), the loss coming mainly from recall. The '
                'reason is that with a uniform width prior the objective of '
                'the dynamic program degenerates into every position with '
                '$z_p>\\theta$ being worth cutting, which is equivalent to '
                'per-position thresholding and therefore produces a large '
                'number of one- and two-byte fragments. The width prior is '
                'thus a mechanism that suppresses over-splitting in the '
                'low-threshold region; this paper chooses a high threshold, '
                'whose cost is that the prior no longer acts and whose '
                'benefit is higher precision.')
        b.p(f'**Bit-level structure identifier fields.** The row "w/o '
            'bit-level SIF" in Table 7 switches off the mask enumeration at '
            f'the end of Section 4.1: F1 changes from '
            f'{f4(av["KFSI_full"]["f1"])} to '
            f'{f4(av["w/o 比特级 SIF"]["f1"])}, a difference of '
            f'{100 * (av["w/o 比特级 SIF"]["f1"] - base):+.2f} percentage '
            'points, at the level of noise. The first byte of the control '
            'field of IEC 104 can itself serve as a byte-level grouping key '
            '(I frames take different values from S and U frames on that '
            'byte), so mask enumeration brings no new information while '
            'introducing extra spurious splits through competition between '
            'same-position mask candidates and byte-level candidates. The '
            'reason for keeping the extension is that the only bit-level '
            'protocol in this data set happens to be covered by the '
            'byte-level criterion as well, so whether bit-level criteria are '
            'effective cannot be decided from these eight protocols; for '
            'protocols that pack two type fields into one byte, the '
            'byte-level criterion would treat the whole byte as one '
            'structure identifier and mask enumeration is the only way out. '
            'The acceptance condition for bit-level criteria should '
            'therefore be stricter than for byte-level ones.')
    if se:
        b.h2('7.6 Parameter sensitivity')
        th = {round(x['value'], 2): x['F1'] for x in se['theta']}
        g = {round(x['value'], 2): x['F1'] for x in se['sif_split_gain']}
        sif = {round(x['value'], 2): x['F1'] for x in se['sif_split_score']}
        cov = [x['F1'] for x in se['min_cut_coverage']]
        grp = [x['F1'] for x in se['min_group']]
        wid = [x['F1'] for x in se['max_width']]
        lfs = [x['F1'] for x in se['lf_split_score']]
        b.p(f'Table 8 and Figure 6 give the sensitivity of seven parameters, '
            'which fall into three classes by behaviour. **Plateau** '
            'parameters barely affect the result: the range of F1 is '
            f'{100 * (max(cov) - min(cov)):.2f} percentage points for the '
            'minimum cut coverage (0.4 to 0.9), '
            f'{100 * (max(grp) - min(grp)):.2f} for the minimum group size '
            f'(3 to 12) and {100 * (max(lfs) - min(lfs)):.2f} for the length '
            'field score threshold (0.15 to 0.6). These parameters control '
            'the lower bound of whether a cut is allowed rather than how '
            'fine the cuts are, and the method is not picky about them.')
        b.p(f'The only **rising plateau** parameter is the decision threshold '
            f'$\\theta$: from 0 to 3.0, F1 rises monotonically from '
            f'{th[0.0]:.4f} to {th[3.0]:.4f} and then enters a plateau '
            f'(between 3.0 and 5.0 it stays within '
            f'{min(th[3.0], th[3.5], th[4.0], th[5.0]):.4f} to '
            f'{max(th[3.0], th[3.5], th[4.0], th[5.0]):.4f}, a range of '
            f'{100 * (max(th[3.0], th[3.5], th[4.0], th[5.0]) - min(th[3.0], th[3.5], th[4.0], th[5.0])):.2f} '
            'percentage points). The value $\\theta=4.0$ selected by this '
            'paper on the development set falls inside the plateau, so the '
            'choice of this parameter is not sensitive. It should be noted '
            'that scanning directly on the test set would give the slightly '
            f'higher value {th[3.0]:.4f} at $\\theta=3.0$, but this paper '
            'does not do so, because that would amount to tuning on the '
            'test set and would systematically overestimate performance.')
        b.p(f'The only **steep** parameter is the split gain threshold: '
            f'raising it from 0.04 to 0.06 lifts F1 from {g[0.04]:.4f} to '
            f'{g[0.06]:.4f}, and raising it further to 0.08 drops F1 back to '
            f'{g[0.08]:.4f}; the range over the whole interval is '
            f'{100 * (max(g.values()) - min(g.values())):.2f} percentage '
            'points, the only one of the seven parameters with a '
            'substantial effect on the result. Per-protocol tracing shows '
            'that this steepness is determined almost entirely by DCERPC: '
            'the gain of the field that really separates its structures is '
            'about 0.07, so a threshold above 0.08 suppresses that split '
            'while a threshold below 0.04 produces several spurious splits; '
            'the other seven protocols are essentially unchanged. The '
            'structure identifier score threshold behaves similarly but much '
            f'more gently ({sif[0.35]:.4f} down to {sif[0.75]:.4f}), because '
            'it acts only after the gain criterion and affects only the '
            'order in which candidates are accepted.')
        b.p('This steepness exposes an inherent limitation of the gain '
            'criterion: cutting a group of messages into smaller groups '
            'necessarily reduces the number of distinct values inside each '
            'group, so determinacy rises spuriously, and part of the gain '
            'comes from sampling rather than from structural differences. A '
            'natural remedy is to add between-group structural divergence as '
            'an independent criterion, but experiments show that it flattens '
            'the whole curve and removes the peak, because the split that '
            'brings the main benefit on DCERPC has a divergence close to '
            'zero: its benefit comes from the indirect path in which the '
            'within-group length distribution narrows after grouping and '
            'vertical splitting can then be executed correctly. The two '
            'criteria capture different aspects of structural homogeneity, '
            'and taking their intersection loses genuine splits as well, so '
            'this paper keeps the pure gain criterion.')
        srows = []
        label = {'theta': 'Decision threshold $\\theta$',
                 'sif_split_gain': 'Split gain threshold',
                 'sif_split_score': 'SIF score threshold',
                 'lf_split_score': 'LF score threshold',
                 'min_group': 'Minimum group size',
                 'max_width': 'Maximum field width',
                 'min_cut_coverage': 'Minimum cut coverage'}

        def _two_lines(items):
            n = len(items)
            if n <= 4:
                return '\u2009/\u2009'.join(items)
            k = (n + 1) // 2
            sep = '\u2009/\u2009'
            return sep.join(items[:k]) + '\n' + sep.join(items[k:])

        for k, v in se.items():
            srows.append([label.get(k, k),
                          _two_lines([str(x['value']) for x in v]),
                          _two_lines([f'{x["F1"]:.3f}' for x in v]),
                          f'{(max(x["F1"] for x in v) - min(x["F1"] for x in v)) * 100:.2f}'])
        b.table('Table 8. Parameter sensitivity (F1 versus parameter value).',
                ['Parameter', 'Values', 'F1', 'Range\n(pp)'],
                srows, [1900, 2700, 3200, 1200])
        fig6 = FIG / 'fig6_sensitivity.png'
        if fig6.exists():
            b.figure(str(fig6), 'Fig. 6. Sensitivity of the decision '
                                'threshold and the split gain threshold.',
                     width_twips=8400)

    # ==================== 8 Conclusion ====================
    b.h1('8 Conclusion')
    b.p('This paper proposes and implements KFSI, a network protocol field '
        'boundary inference method assisted by key-field identification. The '
        'method attributes the difficulty of boundary inference to two '
        'factors, structural heterogeneity and offset drift, and builds '
        'operators from key fields that dissolve them: horizontal splitting '
        'by structure identifier fields and vertical splitting by length '
        'fields, recursively reducing the original problem to homogeneous '
        'sub-problems with fixed offsets, after which evidence fusion and '
        'maximum a posteriori decoding give the final segmentation.')
    n_best = 0
    if bl:
        for p in order:
            others = [r['F1'] for k in bl for r in bl[k]['rows']
                      if r['protocol'] == p]
            if all(rows[p]['F1'] >= v for v in others):
                n_best += 1
    b.p(f'On {len(order)} real protocols with {n_msg} messages, with '
        'calibration, development and test partitions that are mutually '
        f'disjoint, KFSI reaches a position F1 of {f4(summ["micro_F1"])} for '
        f'first-level fields and an interval F1 of '
        f'{f4(summ["iou_micro_F1"])} at IoU >= 0.5, an improvement of '
        f'{100 * gain:.1f}% over the strongest baseline, and it is the best '
        f'method on {n_best} protocols; if the engine is allowed to see only '
        f'the last 30% of the messages of each protocol, F1 is '
        f'{f4(iso["micro_F1"])}, still above the '
        f'{f4(best_bl["micro_F1"])} of the strongest baseline. The ablation '
        'confirms that key-field endpoints, recursive splitting and the '
        'local structure gain are the three main components, and that the '
        'width prior acts mainly in the low-threshold region, where it '
        'suppresses over-splitting.')
    b.p('Two negative results deserve emphasis. Position-level weights '
        'fitted on an independent calibration corpus are not better than the '
        'prior weights, so this paper positions the method as reproducible '
        'without training; and bit-level structure identifier fields are '
        'neutral on this data set, because the only bit-level protocol '
        'happens to be covered by the byte-level criterion as well. The '
        'capability of the method therefore comes mainly from the structural '
        'design of key-field-driven splitting.')
    b.p('Future work comprises three items: introducing region alignment '
        'into splitting so as to handle the misalignment of upper-layer '
        'offsets in multi-layer encapsulation; pushing evidence and decoding '
        'down to bit granularity so as to cover protocols such as CAN; and '
        'connecting protection fields to field-aware fuzzing and anomaly '
        'detection so as to measure end-to-end security benefit on real '
        'devices.')
    b.p('**Data availability.** The implementation, the three-way partition '
        'manifest (with source, MD5 and message count of each capture), the '
        'decontamination script and all experiment scripts are publicly '
        'available at https://github.com/exceed1007/KFSI ; every table and '
        'figure of this paper can be reproduced following the README.')
    # <<<BODY>>>

    b.h1('References')
    REF = {
        # kleber19
        'kleber19': 'S. Kleber, L. Maile, F. Kargl, Survey of protocol reverse '
        'engineering algorithms: decomposition of tools for static traffic '
        'analysis, IEEE Commun. Surv. Tutor. 21 (1) (2019) 526–561. '
        'https://doi.org/10.1109/COMST.2018.2867544.',
        # duche
        'duche': 'J. Duchêne, C. Le Guernic, E. Alata, V. Nicomette, M. Kaâniche, '
        'State of the art of network protocol reverse engineering tools, '
        'J. Comput. Virol. Hack. Tech. 14 (1) (2018) 53–68. '
        'https://doi.org/10.1007/s11416-016-0289-8.',
        # narayan
        'narayan': 'J. Narayan, S.K. Shukla, T.C. Clancy, A survey of automatic protocol '
        'reverse engineering tools, ACM Comput. Surv. 48 (3) (2016) 1–26. '
        'https://doi.org/10.1145/2840724.',
        # sija
        'sija': 'B.D. Sija, Y.-H. Goo, K.-S. Shim, H. Hasanova, M.-S. Kim, A survey of '
        'automatic protocol reverse engineering approaches, methods, and '
        'tools on the inputs and outputs view, Secur. Commun. Netw. 2018 '
        '(2018) 8370341. https://doi.org/10.1155/2018/8370341.',
        # nw
        'nw': 'S.B. Needleman, C.D. Wunsch, A general method applicable to the '
        'search for similarities in the amino acid sequence of two proteins, '
        'J. Mol. Biol. 48 (3) (1970) 443–453. '
        'https://doi.org/10.1016/0022-2836(70)90057-4.',
        # sw
        'sw': 'T.F. Smith, M.S. Waterman, Identification of common molecular '
        'subsequences, J. Mol. Biol. 147 (1) (1981) 195–197. '
        'https://doi.org/10.1016/0022-2836(81)90087-5.',
        # beddoe
        'beddoe': 'M.A. Beddoe, Network protocol analysis using bioinformatics '
        'algorithms, Technical Report, McAfee, 2004.',
        # discoverer
        'discoverer': 'W. Cui, J. Kannan, H.J. Wang, Discoverer: automatic protocol reverse '
        'engineering from network traces, in: Proceedings of the 16th USENIX '
        'Security Symposium, Boston, 2007, pp. 199–212.',
        # netzob
        'netzob': 'G. Bossert, F. Guihéry, G. Hiet, Towards automated protocol reverse '
        'engineering using semantic information, in: Proceedings of the 9th '
        'ACM Symposium on Information, Computer and Communications Security, '
        'Kyoto, 2014, pp. 51–62. '
        'https://doi.org/10.1145/2590296.2590346.',
        # antunes
        'antunes': 'J. Antunes, N. Neves, P. Veríssimo, Reverse engineering of protocols '
        'from network traces, in: Proceedings of the 18th Working Conference '
        'on Reverse Engineering, 2011, pp. 169–178. '
        'https://doi.org/10.1109/WCRE.2011.28.',
        # netplier
        'netplier': 'Y. Ye, Z. Zhang, F. Wang, X. Zhang, D. Xu, NetPlier: probabilistic '
        'network protocol reverse engineering from message traces, in: '
        'Proceedings of the 28th Network and Distributed System Security '
        'Symposium (NDSS), 2021. https://doi.org/10.14722/ndss.2021.24531.',
        # fieldhunter
        'fieldhunter': 'I. Bermudez, A. Tongaonkar, M. Iliofotou, M. Mellia, M.M. Munafò, '
        'Automatic protocol field inference for deeper protocol '
        'understanding, in: Proceedings of the IFIP Networking Conference, '
        '2015, pp. 1–9. https://doi.org/10.1109/IFIPNetworking.2015.7145307.',
        # bininferno
        'bininferno': 'J. Chandler, A. Wick, K. Fisher, BinaryInferno: a semantic-driven '
        'approach to field inference for binary message formats, in: '
        'Proceedings of the 30th Network and Distributed System Security '
        'Symposium (NDSS), 2023. https://doi.org/10.14722/ndss.2023.23131.',
        # nemesys
        'nemesys': 'S. Kleber, F. Kargl, Network message syntax reverse engineering by '
        'analysis of the intrinsic structure of individual messages, in: '
        'Proceedings of the 12th USENIX Workshop on Offensive Technologies '
        '(WOOT), 2018.',
        # msera
        'msera': 'Q. Wang, Z. Sun, Z. Wang, S. Ye, Z. Su, H. Chen, C. Hu, A practical '
        'format and semantic reverse analysis approach for industrial '
        'control protocols, Secur. Commun. Netw. 2021 (2021) 6690988. '
        'https://doi.org/10.1155/2021/6690988.',
        # reinpro
        'reinpro': 'Z. Qin, Z. Yang, Y. Geng, X. Che, T. Wang, H. Zhu, P. Cheng, J. Chen, '
        'Reverse engineering industrial protocols driven by control fields, '
        'in: Proceedings of the IEEE INFOCOM Conference on Computer '
        'Communications, 2024, pp. 2408–2417. '
        'https://doi.org/10.1109/INFOCOM52122.2024.10621405.',
        # pft
        'pft': 'A. Rohl, M. Roughan, M. White, A. Chambers, Packet field tree: a '
        'hybrid approach for automated protocol reverse-engineering, in: '
        'Proceedings of the 9th International Conference on Communication, '
        'Image and Signal Processing (CCISP), 2024, pp. 160–169. '
        'https://doi.org/10.1109/CCISP63826.2024.10765535.',
        # prore
        'prore': 'Y. Huang, H. Shu, F. Kang, ProRE: a protocol message structure '
        'reconstruction method based on execution slice embedding, Comput. '
        'Mater. Contin. 86 (3) (2026) 37. '
        'https://doi.org/10.32604/cmc.2025.071552.',
        # dynpre
        'dynpre': 'Z. Luo, K. Liang, Y. Zhao, F. Wu, J. Yu, H. Shi, Y. Jiang, DynPRE: '
        'protocol reverse engineering via dynamic inference, in: Proceedings '
        'of the Network and Distributed System Security Symposium (NDSS), '
        '2024.',
        # tupni
        'tupni': 'W. Cui, M. Peinado, K. Chen, E.J. Locasto, D. Song, Tupni: automatic '
        'reverse engineering of input formats, in: Proceedings of the 15th '
        'ACM Conference on Computer and Communications Security, 2008, '
        'pp. 391–402. https://doi.org/10.1145/1455770.1455820.',
        # lin
        'lin': 'Z. Lin, X. Zhang, D. Xu, Automatic protocol format reverse '
        'engineering through context-aware monitored execution, in: '
        'Proceedings of the 15th Network and Distributed System Security '
        'Symposium (NDSS), 2008.',
        # prospex
        'prospex': 'P.M. Comparetti, G. Wondracek, C. Kruegel, E. Kirda, Prospex: '
        'protocol specification extraction, in: Proceedings of the 30th IEEE '
        'Symposium on Security and Privacy, 2009, pp. 110–125. '
        'https://doi.org/10.1109/SP.2009.14.',
        # netlifter
        'netlifter': 'Q. Shi, J. Shao, Y. Ye, M. Zheng, X. Zhang, Lifting network protocol '
        'implementation to precise format specification with security '
        'applications, in: Proceedings of the ACM SIGSAC Conference on '
        'Computer and Communications Security (CCS), 2023. '
        'https://doi.org/10.1145/3576915.3616592.',
        # probepre
        'probepre': 'D. Xue, Y. Qu, B. Jiang, X. Chen, S. Si, S. Lv, Z. Shi, L. Sun, '
        'Breaking the traffic barrier: unveiling multi-format of protocols '
        'via autonomous program exploration, in: Proceedings of the 40th '
        'IEEE/ACM International Conference on Automated Software Engineering '
        '(ASE), 2025, pp. 2083–2095. '
        'https://doi.org/10.1109/ASE63991.2025.00173.',
        # tshark
        'tshark': 'G. Combs, Wireshark network protocol analyzer (tshark), 2024. '
        'https://www.wireshark.org.',
        # ebpfi
        'ebpfi': 'Z. Wang, S. Zhao, Y. Qu, X. Cao, R. Xi, L. Li, H. Zhu, EBPFI: '
        'enhancing binary protocol format inference via field boundary '
        'learning, Comput. J. (2026) (in press). '
        'https://doi.org/10.1093/comjnl/bxag065.',
        # rpkclust
        'rpkclust': 'Q. Yang, X. Yin, F. Zhao, S. Liu, RPKClust: '
        'region-partitioned keywords inference for binary protocol reverse, '
        'Comput. J. 69 (7) (2026) 1133–1148. '
        'https://doi.org/10.1093/comjnl/bxag016.',
        # proinfer
        'proinfer': 'M. Guo, Y. Zhu, J. Fei, ProInfer: inference of binary '
        'protocol keywords based on probabilistic statistics, Comput. J. 68 '
        '(2) (2025) 109–125. https://doi.org/10.1093/comjnl/bxae096.',
        # fsibp
        'fsibp': 'M. Zhan, Y. Li, B. Li, J. Zhang, C. Li, W. Wang, Toward '
        'automated field semantics inference for binary protocol reverse '
        'engineering, IEEE Trans. Inf. Forensics Secur. 19 (2024) 764–776. '
        'https://doi.org/10.1109/TIFS.2023.3326666.',
        # finebid
        'finebid': 'T. Huang, Y. Gao, Y. Zheng, Z. Wang, C. Hu, A. Fu, '
        'FineBID: fine-grained protocol reverse engineering for bit-level '
        'field identification, IEEE Trans. Dependable Secure Comput. 22 (3) '
        '(2025) 2670–2686. https://doi.org/10.1109/TDSC.2024.3521592.',
        # spenny
        'spenny': 'Y. Sun, Z. Li, S. Lv, L. Sun, Spenny: extensive ICS '
        'protocol reverse analysis via field guided symbolic execution, IEEE '
        'Trans. Dependable Secure Comput. 20 (6) (2023) 4502–4518. '
        'https://doi.org/10.1109/TDSC.2022.3228076.',
        # icpgf
        'icpgf': 'X. Zong, B. Ning, G. Wang, K. He, L. Lian, Y. Sun, ICPGF: '
        'an industrial control protocol format-aware and feedback-guided '
        'fuzzing, in: Proceedings of the International Conference Automatics '
        'and Informatics (ICAI), 2023, pp. 65–70. '
        'https://doi.org/10.1109/ICAI58806.2023.10339046.',
        # liu22
        'liu22': 'P. Liu, Y. Zheng, Z. Song, D. Fang, S. Lv, L. Sun, Fuzzing '
        'proprietary protocols of programmable controllers to find '
        'vulnerabilities that affect physical control, J. Syst. Archit. 127 '
        '(2022) 102483. https://doi.org/10.1016/j.sysarc.2022.102483.',
    }
    missing = [k for k in CITE_ORDER if k not in REF]
    if missing:
        raise KeyError('undefined reference keys: %s' % missing)
    unused = [k for k in REF if k not in CITE_NUM]
    if unused:
        print('[warn] references never cited: %s' % unused)
    for i, k in enumerate(CITE_ORDER, 1):
        b.ref('[%d] %s' % (i, REF[k]))
    print('[refs] %d entries, numbered by first citation' % len(CITE_ORDER))

    b.save(out_path)
    return out_path

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=str(
        Path('E:/3-学术工作/论文/正在构思的论文/'
             '基于关键字段识别与辅助的网络协议字段边界推断方法/'
             'KFSI_manuscript.docx')))
    args = ap.parse_args(argv)
    p = build(args.out)
    print('saved:', p)
    return p


if __name__ == '__main__':
    main()
