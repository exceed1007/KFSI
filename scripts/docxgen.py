# -*- coding: utf-8 -*-
"""轻量 .docx 生成器（直接构造 OOXML，不依赖第三方库）。

支持的中文学术排版要素：
  * 标题（二号黑体居中）、一级/二级/三级标题（黑体）
  * 正文（宋体/Times New Roman 小四、1.5 倍行距、首行缩进 2 字符、两端对齐）
  * 公式行（居中、右侧编号）
  * 三线表（顶线/表头线/底线）
  * 图表题注（五号居中）
  * 参考文献条目（悬挂缩进、五号）

用法::

    from docxgen import DocxBuilder
    b = DocxBuilder()
    b.title('标题'); b.h1('1 引言'); b.p('正文……')
    b.table('表1 xxx', ['列1','列2'], [['a','b']], [3000,3000])
    b.save('out.docx')
"""

from __future__ import annotations

import os
import re
import zipfile

_TOKEN = re.compile(r'(\$[^$]+\$|\*\*)')

NS = ('xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
      'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
      'xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math"')

# Office 自带的 MathML→OMML 样式表，用于把 LaTeX 变成 Word 原生公式
_XSL_CANDIDATES = (
    r'C:\Program Files\Microsoft Office\root\Office16\MML2OMML.XSL',
    r'C:\Program Files (x86)\Microsoft Office\root\Office16\MML2OMML.XSL',
    r'C:\Program Files\Microsoft Office\Office16\MML2OMML.XSL',
)
_XSL = None
_MATH_CACHE: dict = {}


def _xsl():
    global _XSL
    if _XSL is None:
        from lxml import etree
        for p in _XSL_CANDIDATES:
            if os.path.exists(p):
                _XSL = etree.XSLT(etree.parse(p))
                break
        else:
            raise RuntimeError('未找到 MML2OMML.XSL，无法生成 Word 公式')
    return _XSL


# ----------------------------------------------------------------------
# 公式排版规范化：数字、运算符、括号一律正体
# ----------------------------------------------------------------------
# 数学斜体只应施加于单字母变量（x、G、w…）；数字、等号与不等号、
# 括号、逗号等必须正体。MathML→OMML 的转换会把相邻的运算符与变量
# 合并进同一个 run（例如“=min”“,G”），该 run 未显式指定样式时整体
# 被 Word 按斜体渲染，导致等号与逗号也变成斜体。这里按字符类别把
# 每个 run 拆成若干同质子 run，并显式给出 <m:sty>。
_MATH_RUN = re.compile(r'<m:r>(.*?)</m:r>', re.S)
_MATH_TXT = re.compile(r'<m:t[^>]*>(.*?)</m:t>', re.S)
_ITALIC = re.compile(r'([A-Za-z\u0370-\u03ff]+)')


def _is_italic_token(tok: str) -> bool:
    """单字母变量（含希腊字母）取斜体；多字母（min/max 及下标词）取正体。"""
    return len(tok) == 1


def _math_run(text: str, italic: bool) -> str:
    if text == '':
        return ''
    sty = '<m:rPr/>' if italic else '<m:rPr><m:sty m:val="p"/></m:rPr>'
    return ('<m:r>' + sty +
            '<w:rPr><w:rFonts w:ascii="Cambria Math" w:hAnsi="Cambria Math" '
            'w:cs="Cambria Math"/></w:rPr>'
            f'<m:t xml:space="preserve">{esc(text)}</m:t></m:r>')


def _normalize_math(s: str) -> str:
    def fix(m):
        body = m.group(1)
        t = _MATH_TXT.search(body)
        if not t:
            return m.group(0)
        text = (t.group(1).replace('&lt;', '<').replace('&gt;', '>')
                .replace('&amp;', '&'))
        if not text:
            return m.group(0)
        out, pos = [], 0
        for hit in _ITALIC.finditer(text):
            if hit.start() > pos:
                out.append(_math_run(text[pos:hit.start()], False))
            out.append(_math_run(hit.group(1), _is_italic_token(hit.group(1))))
            pos = hit.end()
        if pos < len(text):
            out.append(_math_run(text[pos:], False))
        return ''.join(out)
    return _MATH_RUN.sub(fix, s)


def _omml_core(latex: str) -> str:
    """单段 LaTeX（不含 \\quad）→ ``<m:oMath>…</m:oMath>``。"""
    import latex2mathml.converter as conv
    from lxml import etree
    mml = conv.convert(latex)
    root = etree.fromstring(mml.encode('utf-8'))
    out = _xsl()(root)
    s = etree.tostring(out, encoding='unicode')
    return ' '.join(s.split())


_QSPLIT = re.compile(r'(\\qquad|\\quad)')
_EM = {r'\quad': '\u2003', r'\qquad': '\u2003\u2003'}
_OMML_TAIL = '</m:oMath>'


def _split_omml(s: str):
    """拆成 (开标签, 内部内容)，用于拼接。"""
    i = s.index('>') + 1
    return s[:i], s[i:-len(_OMML_TAIL)]


def omml(latex: str) -> str:
    """LaTeX → OMML（Word 原生公式）片段，形如 ``<m:oMath>…</m:oMath>``。"""
    key = latex.strip()
    if key in _MATH_CACHE:
        return _MATH_CACHE[key]
    toks = _QSPLIT.split(key)
    # latex2mathml 会丢弃 \quad / \qquad，这里按它们切段后显式插入全角空格
    segs = toks[0::2]
    seps = toks[1::2]
    head, inner = _split_omml(_omml_core(segs[0]))
    for sep, seg in zip(seps, segs[1:]):
        _, body = _split_omml(_omml_core(seg))
        inner += ('<m:r><m:rPr><m:sty m:val="p"/></m:rPr>'
                  f'<m:t xml:space="preserve">{_EM[sep]}</m:t></m:r>') + body
    s = _normalize_math(head + inner + _OMML_TAIL)
    _MATH_CACHE[key] = s
    return s



def esc(t: str) -> str:
    return (str(t).replace('&', '&amp;').replace('<', '&lt;')
            .replace('>', '&gt;'))


def _png_size(data: bytes):
    """从 PNG 的 IHDR 块读取像素宽高（不依赖 Pillow）。"""
    if data[:8] != b'\x89PNG\r\n\x1a\n' or data[12:16] != b'IHDR':
        raise ValueError('不是有效的 PNG 文件')
    width = int.from_bytes(data[16:20], 'big')
    height = int.from_bytes(data[20:24], 'big')
    return width, height


# ----------------------------------------------------------------------
# 样式表
# ----------------------------------------------------------------------
def _style(sid, name, *, size=24, bold=False, ascii_font='Times New Roman',
           ea_font='宋体', align=None, indent_chars=0, hanging=0,
           before=0, after=0, line=360, outline=None, keep_next=False):
    pr = []
    if align:
        pr.append(f'<w:jc w:val="{align}"/>')
    if indent_chars:
        pr.append(f'<w:ind w:firstLineChars="{indent_chars}" '
                  f'w:firstLine="{int(size * 10 * indent_chars / 100)}"/>')
    elif hanging:
        pr.append(f'<w:ind w:hangingChars="{hanging}" '
                  f'w:hanging="{int(size * 10 * hanging / 100)}" w:left="0"/>')
    pr.append(f'<w:spacing w:before="{before}" w:after="{after}" '
              f'w:line="{line}" w:lineRule="auto"/>')
    if outline is not None:
        pr.append(f'<w:outlineLvl w:val="{outline}"/>')
    if keep_next:
        pr.append('<w:keepNext/>')
    rpr = (f'<w:rFonts w:ascii="{ascii_font}" w:hAnsi="{ascii_font}" '
           f'w:eastAsia="{ea_font}" w:cs="{ascii_font}"/>'
           f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>'
           + ('<w:b/><w:bCs/>' if bold else ''))
    return (f'<w:style w:type="paragraph" w:styleId="{sid}">'
            f'<w:name w:val="{name}"/><w:qFormat/>'
            f'<w:pPr>{"".join(pr)}</w:pPr>'
            f'<w:rPr>{rpr}</w:rPr></w:style>')


def build_styles() -> str:
    items = [
        _style('Title', 'Title', size=44, bold=True, ea_font='黑体',
               align='center', before=0, after=240, line=360, outline=0),
        _style('H1', 'heading 1', size=30, bold=True, ea_font='黑体',
               before=240, after=120, line=360, outline=0, keep_next=True),
        _style('H2', 'heading 2', size=26, bold=True, ea_font='黑体',
               before=180, after=90, line=360, outline=1, keep_next=True),
        _style('H3', 'heading 3', size=24, bold=True, ea_font='黑体',
               before=120, after=60, line=360, outline=2, keep_next=True),
        _style('Body', 'Body Text', size=24, align='both',
               indent_chars=200, line=300),
        _style('Abs', 'Abstract', size=21, align='both', indent_chars=200,
               line=290),
        _style('Eq', 'Equation', size=24, align='center', before=60,
               after=60, line=320),
        _style('Cap', 'Caption', size=21, bold=True, ea_font='黑体',
               align='center', before=60, after=60, line=280),
        _style('Txt', 'Table Text', size=21, align='center', line=260),
        _style('TxtL', 'Table Text Left', size=21, align='left', line=260),
        _style('Ref', 'Reference', size=21, align='left', hanging=200,
               line=280),
        _style('Note', 'Note', size=21, align='both', line=300),
        _style('Fig', 'Figure', size=21, align='center', before=120,
               after=60, line=240),
    ]
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:styles {NS}><w:docDefaults><w:rPrDefault><w:rPr>'
            '<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" '
            'w:eastAsia="宋体" w:cs="Times New Roman"/>'
            '<w:sz w:val="24"/><w:szCs w:val="24"/>'
            '</w:rPr></w:rPrDefault>'
            '<w:pPrDefault><w:pPr><w:widowControl w:val="0"/>'
            '</w:pPr></w:pPrDefault></w:docDefaults>'
            + ''.join(items) + '</w:styles>')


# ----------------------------------------------------------------------
class DocxBuilder:
    def __init__(self):
        self.blocks = []
        self._tbl_id = 0
        self.media = []      # [(文件名, 字节)]
        self._img_id = 0

    # -- 基本块 --------------------------------------------------------
    def _p(self, text, style='Body', bold_prefix=None):
        runs = ''
        if bold_prefix and text.startswith(bold_prefix):
            runs += self._run(bold_prefix, bold=True)
            text = text[len(bold_prefix):]
        runs += self._run(text)
        self.blocks.append(
            f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr>{runs}</w:p>')

    def _run(self, text, bold=False):
        """单个 run；支持 ``**加粗**``、``$行内公式$`` 与 ``\\n`` 强制换行。"""
        if text == '':
            return ''
        lines = str(text).split('\n')
        if len(lines) == 1:
            return self._run_line(lines[0], bold)
        out = []
        for i, ln in enumerate(lines):
            if i:
                out.append('<w:r><w:br/></w:r>')
            out.append(self._run_line(ln, bold))
        return ''.join(out)

    def _run_line(self, text, bold=False):
        """单行内的 run 序列（不含换行）。"""
        if text == '':
            return ''
        parts = _TOKEN.split(str(text))
        out = []
        b = bold
        for seg in parts:
            if seg == '**':
                b = not b
                continue
            if not seg:
                continue
            if len(seg) > 2 and seg.startswith('$') and seg.endswith('$'):
                out.append(omml(seg[1:-1]))
                continue
            rpr = '<w:rPr><w:b/><w:bCs/></w:rPr>' if b else ''
            out.append(f'<w:r>{rpr}<w:t xml:space="preserve">{esc(seg)}</w:t></w:r>')
        return ''.join(out)

    def title(self, t):
        self._p(t, 'Title')

    def h1(self, t):
        self._p(t, 'H1')

    def h2(self, t):
        self._p(t, 'H2')

    def h3(self, t):
        self._p(t, 'H3')

    def p(self, t, bold_prefix=None):
        self._p(t, 'Body', bold_prefix)

    def abs(self, t, bold_prefix=None):
        self._p(t, 'Abs', bold_prefix)

    def eq(self, t):
        self._p(t, 'Eq')

    def eq_latex(self, latex, number=None):
        """居中排版的 Word 原生公式，编号右对齐（制表位定位）。"""
        tabs = ('<w:tabs><w:tab w:val="center" w:pos="4535"/>'
                '<w:tab w:val="right" w:pos="9070"/></w:tabs>')
        num = (f'<w:r><w:t xml:space="preserve">（{number}）</w:t></w:r>'
               if number else '')
        self.blocks.append(
            f'<w:p><w:pPr><w:pStyle w:val="Eq"/>{tabs}'
            '<w:ind w:firstLine="0" w:left="0"/></w:pPr>'
            f'<w:r><w:tab/></w:r>{omml(latex)}<w:r><w:tab/></w:r>{num}</w:p>')

    def cap(self, t):
        self._p(t, 'Cap')

    def note(self, t):
        self._p(t, 'Note')

    def ref(self, t):
        self._p(t, 'Ref')

    def blank(self):
        self.blocks.append('<w:p><w:pPr><w:pStyle w:val="Body"/>'
                           '<w:spacing w:line="240" w:lineRule="auto"/>'
                           '</w:pPr></w:p>')

    def pagebreak(self):
        self.blocks.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')

    # -- 插图 ----------------------------------------------------------
    def figure(self, png_path, caption, width_twips=7600):
        """插入 PNG 图片 + 图题。宽高比按图片实际像素自动保持。"""
        data = open(png_path, 'rb').read()
        w_px, h_px = _png_size(data)
        cx = int(width_twips * 635)                  # 1 twip = 635 EMU
        cy = int(cx * h_px / w_px)
        self._img_id += 1
        rid = f'rIdImg{self._img_id}'
        name = f'image{self._img_id}.png'
        self.media.append((name, data))
        drawing = (
            '<w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" '
            'distR="0" xmlns:wp="http://schemas.openxmlformats.org/drawingml/'
            '2006/wordprocessingDrawing">'
            f'<wp:extent cx="{cx}" cy="{cy}"/>'
            f'<wp:docPr id="{self._img_id}" name="Figure {self._img_id}"/>'
            '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/'
            '2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/'
            'drawingml/2006/picture">'
            '<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/'
            '2006/picture">'
            f'<pic:nvPicPr><pic:cNvPr id="{self._img_id}" name="{name}"/>'
            '<pic:cNvPicPr/></pic:nvPicPr>'
            f'<pic:blipFill><a:blip r:embed="{rid}"/>'
            '<a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
            '<pic:spPr><a:xfrm><a:off x="0" y="0"/>'
            f'<a:ext cx="{cx}" cy="{cy}"/></a:xfrm>'
            '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
            '</pic:pic></a:graphicData></a:graphic></wp:inline>'
            '</w:drawing></w:r>')
        self.blocks.append('<w:p><w:pPr><w:pStyle w:val="Fig"/>'
                           '<w:keepNext/></w:pPr>'
                           f'{drawing}</w:p>')
        if caption:
            self.cap(caption)

    # -- 三线表 --------------------------------------------------------
    def table(self, caption, header, rows, widths, note=None):
        if caption:
            self.blocks.append(
                '<w:p><w:pPr><w:pStyle w:val="Cap"/><w:keepNext/></w:pPr>'
                f'{self._run(caption, bold=True)}</w:p>')
        self._tbl_id += 1
        total = sum(widths)
        grid = ''.join(f'<w:gridCol w:w="{w}"/>' for w in widths)
        # 顶线与底线用 1.5 磅，表头线用 0.75 磅，竖线与内部横线不画
        bd = ('<w:tblBorders>'
              '<w:top w:val="single" w:sz="12" w:color="000000"/>'
              '<w:left w:val="none" w:sz="0" w:color="auto"/>'
              '<w:bottom w:val="single" w:sz="12" w:color="000000"/>'
              '<w:right w:val="none" w:sz="0" w:color="auto"/>'
              '<w:insideH w:val="none" w:sz="0" w:color="auto"/>'
              '<w:insideV w:val="none" w:sz="0" w:color="auto"/>'
              '</w:tblBorders>')

        def row_xml(cells, is_head=False, keep=False):
            cells_xml = []
            for k, c in enumerate(cells):
                w = widths[k] if k < len(widths) else widths[-1]
                b = ('<w:tcBorders><w:bottom w:val="single" w:sz="6" '
                     'w:color="000000"/></w:tcBorders>') if is_head else ''
                sty = 'Txt' if is_head else ('TxtL' if k == 0 and
                                             len(str(c)) > 14 else 'Txt')
                kp = '<w:keepNext/>' if keep else ''
                cells_xml.append(
                    f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/>{b}'
                    f'<w:vAlign w:val="center"/></w:tcPr>'
                    f'<w:p><w:pPr><w:pStyle w:val="{sty}"/>{kp}</w:pPr>'
                    f'{self._run(c, bold=is_head)}</w:p></w:tc>')
            trpr = ('<w:trPr><w:cantSplit/>'
                    + ('<w:tblHeader/>' if is_head else '') + '</w:trPr>')
            return f'<w:tr>{trpr}{"".join(cells_xml)}</w:tr>'

        body = row_xml(header, True, keep=True) + ''.join(
            row_xml(r, keep=(i < len(rows) - 1)) for i, r in enumerate(rows))
        self.blocks.append(
            f'<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/>'
            f'<w:tblW w:w="{total}" w:type="dxa"/>'
            f'<w:jc w:val="center"/>{bd}'
            '<w:tblLayout w:type="fixed"/></w:tblPr>'
            f'<w:tblGrid>{grid}</w:tblGrid>{body}</w:tbl>')
        if note:
            self.note(note)

    # -- 打包 ----------------------------------------------------------
    def save(self, path):
        body = ''.join(self.blocks)
        sect = ('<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
                '<w:pgMar w:top="1440" w:right="1418" w:bottom="1440" '
                'w:left="1418" w:header="851" w:footer="992" w:gutter="0"/>'
                '<w:cols w:space="425"/><w:docGrid w:type="lines" '
                'w:linePitch="312"/></w:sectPr>')
        doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               f'<w:document {NS}><w:body>{body}{sect}</w:body></w:document>')
        ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
              'content-types">'
              '<Default Extension="rels" ContentType="application/'
              'vnd.openxmlformats-package.relationships+xml"/>'
              '<Default Extension="xml" ContentType="application/xml"/>'
              '<Default Extension="png" ContentType="image/png"/>'
              '<Override PartName="/word/document.xml" ContentType='
              '"application/vnd.openxmlformats-officedocument.'
              'wordprocessingml.document.main+xml"/>'
              '<Override PartName="/word/styles.xml" ContentType='
              '"application/vnd.openxmlformats-officedocument.'
              'wordprocessingml.styles+xml"/>'
              '<Override PartName="/docProps/core.xml" ContentType='
              '"application/vnd.openxmlformats-package.core-properties+xml"/>'
              '<Override PartName="/docProps/app.xml" ContentType='
              '"application/vnd.openxmlformats-officedocument.'
              'extended-properties+xml"/>'
              '</Types>')
        rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/'
                'package/2006/relationships">'
                '<Relationship Id="rId1" Type="http://schemas.openxmlformats'
                '.org/officeDocument/2006/relationships/officeDocument" '
                'Target="word/document.xml"/>'
                '<Relationship Id="rId2" Type="http://schemas.openxmlformats'
                '.org/package/2006/relationships/metadata/core-properties" '
                'Target="docProps/core.xml"/>'
                '<Relationship Id="rId3" Type="http://schemas.openxmlformats'
                '.org/officeDocument/2006/relationships/extended-properties" '
                'Target="docProps/app.xml"/>'
                '</Relationships>')
        drels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                 '<Relationships xmlns="http://schemas.openxmlformats.org/'
                 'package/2006/relationships">'
                 '<Relationship Id="rId1" Type="http://schemas.openxmlformats'
                 '.org/officeDocument/2006/relationships/styles" '
                 'Target="styles.xml"/>'
                 + ''.join(
                     f'<Relationship Id="rIdImg{i}" Type="http://schemas.'
                     'openxmlformats.org/officeDocument/2006/relationships/'
                     f'image" Target="media/{name}"/>'
                     for i, (name, _) in enumerate(self.media, 1))
                 + '</Relationships>')
        core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats'
                '.org/package/2006/metadata/core-properties" '
                'xmlns:dc="http://purl.org/dc/elements/1.1/">'
                '<dc:title>基于关键字段识别与辅助的网络协议字段边界推断方法'
                '</dc:title><dc:creator>KFSI</dc:creator></cp:coreProperties>')
        app = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<Properties xmlns="http://schemas.openxmlformats.org/'
               'officeDocument/2006/extended-properties"><Application>'
               'KFSI</Application></Properties>')

        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('[Content_Types].xml', ct)
            z.writestr('_rels/.rels', rels)
            z.writestr('word/document.xml', doc)
            z.writestr('word/styles.xml', build_styles())
            z.writestr('word/_rels/document.xml.rels', drels)
            z.writestr('docProps/core.xml', core)
            z.writestr('docProps/app.xml', app)
            for name, data in self.media:
                z.writestr(f'word/media/{name}', data)
        return path
