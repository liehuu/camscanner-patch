# -*- coding: utf-8 -*-
"""OOXML (WordprocessingML) 结构校验器。

写这个脚本的起因（2026-10-28）：
    v17/v18/v19 三轮都栽在「导出的 docx 打不开 / 丢格式」，
    而每次我的检查器都只查了 ZIP 完整性和 XML well-formed，
    这两项全绿 —— 因为缺陷在**语义层**（元素顺序、必需属性、必需容器），
    而我的检查器根本不看这一维度。
    教训：检查维度缺失 = 在该维度永远通过。

本脚本硬编码 ECMA-376 里几条最能致命的约束：
  CT_Body   : (EG_BlockLevelElts)*, sectPr?
  CT_P      : pPr?, EG_PContent*
  CT_PPr    : 有序 sequence，顺序错 Word 就拒
  CT_RPr    : 有序 sequence，顺序错 Word 报「无法读取的内容」
  CT_SectPr : 有序 sequence
  CT_PageMar: top/right/bottom/left/header/footer/gutter 全部 required
  CT_PgSz   : w/h required
  w:sz      : 1..3276（半磅）
  w:jc      : 枚举，不存在 justify

用法:
    python docx_validate.py <file.docx>
退出码 0 = 全绿；1 = 有问题。
"""
import sys, io, re, zipfile

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

# ── CT_PPr 合法子元素顺序（ECMA-376 Part 1, 17.3.1.26） ──
PPR_ORDER = [
    "pStyle", "keepNext", "keepLines", "pageBreakBefore", "framePr",
    "widowControl", "numPr", "suppressLineNumbers", "pBdr", "shd", "tabs",
    "suppressAutoHyphens", "kinsoku", "wordWrap", "overflowPunct",
    "topLinePunct", "autoSpaceDE", "autoSpaceDN", "bidi", "adjustRightInd",
    "snapToGrid", "spacing", "ind", "contextualSpacing", "mirrorIndents",
    "suppressOverlap", "jc", "textDirection", "textAlignment",
    "textboxTightWrap", "outlineLvl", "divId", "cnfStyle", "rPr", "sectPr",
    "pPrChange",
]

# ── CT_RPr 合法子元素顺序（17.3.2.28） ──
RPR_ORDER = [
    "rStyle", "rFonts", "b", "bCs", "i", "iCs", "caps", "smallCaps", "strike",
    "dstrike", "outline", "shadow", "emboss", "imprint", "noProof",
    "snapToGrid", "vanish", "webHidden", "color", "spacing", "w", "kern",
    "position", "sz", "szCs", "highlight", "u", "effect", "bdr", "shd",
    "fitText", "vertAlign", "rtl", "cs", "em", "lang", "eastAsianLayout",
    "specVanish", "oMath",
]

# ── CT_SectPr 合法子元素顺序（17.6.17） ──
SECTPR_ORDER = [
    "headerReference", "footerReference", "footnotePr", "endnotePr", "type",
    "pgSz", "pgMar", "paperSrc", "pgBorders", "lnNumType", "pgNumType",
    "cols", "formProt", "vAlign", "noEndnote", "titlePg", "textDirection",
    "bidi", "rtlGutter", "docGrid", "printerSettings", "sectPrChange",
]

# body 允许的块级元素
BODY_BLOCKS = {
    "p", "tbl", "sdt", "altChunk", "bookmarkStart", "bookmarkEnd",
    "commentRangeStart", "commentRangeEnd", "customXml", "ins", "del",
    "moveFrom", "moveTo", "proofErr", "permStart", "permEnd",
}

PAGE_MAR_REQUIRED = ["top", "right", "bottom", "left", "header", "footer", "gutter"]

JC_ALLOWED = {
    "start", "center", "end", "both", "mediumKashida", "distribute",
    "numTab", "highKashida", "lowKashida", "thaiDistribute", "left", "right",
}


def local(tag):
    if tag.startswith(W):
        return tag[len(W):]
    return None      # 非 w 命名空间


def tag_of(e):
    return local(e.tag) if isinstance(e.tag, str) else None


class Checker(object):
    def __init__(self):
        self.errors = []
        self.embeds = []        # [(where, rId)] 正文里的 r:embed 引用
        self.doc_pr_ids = []    # wp:docPr 的 id，整篇必须唯一

    def err(self, where, msg):
        self.errors.append("%s: %s" % (where, msg))

    def ordered(self, elem, order, where, label):
        """检查 elem 的子元素是否按 order 排列（允许缺项，禁止乱序/重复）。"""
        idx = -1
        seen = set()
        for ch in elem:
            t = tag_of(ch)
            if t is None:
                continue          # 非 w 命名空间，跳过
            if t not in order:
                self.err(where, "<%s> 内出现非法子元素 <%s>（%s 不允许它）"
                         % (label, t, label))
                continue
            i = order.index(t)
            if i == idx:
                self.err(where, "<%s> 内 <%s> 重复出现" % (label, t))
            elif i < idx:
                prev = order[idx] if idx >= 0 else "?"
                self.err(where, "<%s> 内 <%s> 顺序错误：应排在 <%s> 之前"
                         % (label, t, prev))
            else:
                idx = i
            seen.add(t)

    def check_body(self, body, where):
        # CT_Body: (块级元素)*, sectPr?
        sect_seen = False
        for ch in body:
            t = tag_of(ch)
            if t is None:
                continue
            if t == "sectPr":
                if sect_seen:
                    self.err(where, "<w:body> 内有多个 <w:sectPr>")
                sect_seen = True
                continue
            if sect_seen:
                self.err(where, "<w:body> 内 <%s> 出现在 <w:sectPr> 之后（sectPr 必须是最后一个）" % t)
            if t == "pPr":
                self.err(where, "<w:body> 直接子元素出现裸 <w:pPr>"
                                " —— 段落属性必须在 <w:p> 内部，说明漏了段落容器")
            elif t not in BODY_BLOCKS:
                self.err(where, "<w:body> 内出现非法块级元素 <%s>" % t)
        if not sect_seen:
            self.err(where, "<w:body> 缺少 <w:sectPr>")

    def check_p(self, p, where, path):
        # CT_P: pPr?, EG_PContent*
        ppr_count = 0
        first = True
        for ch in p:
            t = tag_of(ch)
            if t is None:
                continue
            if t == "pPr":
                ppr_count += 1
                if ppr_count > 1:
                    self.err(where, "<w:p> 内有多个 <w:pPr>（maxOccurs=1）")
                if not first:
                    self.err(where, "<w:pPr> 不是 <w:p> 的第一个子元素")
                self.ordered(ch, PPR_ORDER, where, "w:pPr")
                for sub in ch:
                    st = tag_of(sub)
                    if st == "jc":
                        v = sub.get(W + "val")
                        if v is not None and v not in JC_ALLOWED:
                            self.err(where, "<w:jc w:val=\"%s\"> 非法（合法值：%s）"
                                     % (v, ", ".join(sorted(JC_ALLOWED))))
            elif t in ("r", "hyperlink", "fldSimple", "subDoc", "smartTag",
                       "ins", "del", "bookmarkStart", "bookmarkEnd", "sdt",
                       "proofErr", "commentRangeStart", "commentRangeEnd",
                       "moveFrom", "moveTo", "permalink", "customXml"):
                if t == "r":
                    self.check_r(ch, where)
            else:
                self.err(where, "<w:p> 内出现非法子元素 <%s>" % t)
            first = False

    def check_r(self, r, where):
        # CT_R: rPr?, EG_RunInnerContent*
        first = True
        for ch in r:
            t = tag_of(ch)
            if t is None:
                continue
            if t == "rPr":
                if not first:
                    self.err(where, "<w:rPr> 不是 <w:r> 的第一个子元素")
                self.ordered(ch, RPR_ORDER, where, "w:rPr")
                for sub in ch:
                    st = tag_of(sub)
                    if st == "sz" or st == "szCs":
                        v = sub.get(W + "val")
                        try:
                            n = int(v)
                        except Exception:
                            self.err(where, "<w:%s w:val=\"%s\"> 不是整数" % (st, v))
                            continue
                        if n < 1 or n > 3276:
                            self.err(where, "<w:%s w:val=%d> 越界（半磅，合法 1..3276）" % (st, n))
                    if st == "color":
                        v = sub.get(W + "val") or ""
                        if v != "auto" and not (len(v) == 6 and all(c in "0123456789ABCDEFabcdef" for c in v)):
                            self.err(where, "<w:color w:val=\"%s\"> 非法（要 6 位十六进制或 auto）" % v)
            elif t == "drawing":
                self.check_drawing(ch, where)
            else:
                # CT_R 里允许 t / br / tab / sym / instrText / lastRenderedPageBreak 等；
                # 这里只报明显不该出现的块级元素，避免过度误报
                if t in ("p", "pPr", "tbl", "sectPr", "body"):
                    self.err(where, "<w:r> 内出现块级元素 <%s>" % t)
            first = False

    def check_sectpr(self, s, where):
        self.ordered(s, SECTPR_ORDER, where, "w:sectPr")
        for ch in s:
            t = tag_of(ch)
            if t == "pgSz":
                for a in ("w", "h"):
                    if ch.get(W + a) is None:
                        self.err(where, "<w:pgSz> 缺少必需属性 %s" % a)
            elif t == "pgMar":
                for a in PAGE_MAR_REQUIRED:
                    if ch.get(W + a) is None:
                        self.err(where, "<w:pgMar> 缺少必需属性 %s（ECMA-376 标记 required）" % a)

    def check_drawing(self, draw, where):
        """v21：图片结构。
        <w:drawing> 里 wp/a/pic 三个前缀都要有命名空间声明，
        内联图必须有 extent 与 docPr，blip 的 r:embed 要能对上关系。
        """
        R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
        WP = "{http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing}"
        A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
        PIC = "{http://schemas.openxmlformats.org/drawingml/2006/picture}"

        inlines = draw.findall(WP + "inline")
        anchors = draw.findall(WP + "anchor")
        if not inlines and not anchors:
            self.err(where, "<w:drawing> 下没有 <wp:inline> 也没有 <wp:anchor>")
            return
        for inl in inlines:
            ext = inl.find(WP + "extent")
            if ext is None:
                self.err(where, "<wp:inline> 缺少 <wp:extent>")
            else:
                for a in ("cx", "cy"):
                    # ⚠ 无前缀属性不属于任何命名空间，必须用裸名字取。
                    #   写成 ext.get(WP + a) 会永远拿不到值（报 "None 不是整数"），
                    #   而真正的问题被这条假报淹掉 —— 这正是「检查器自己出错」的典型。
                    v = ext.get(a)
                    try:
                        n = int(v)
                    except Exception:
                        self.err(where, "<wp:extent %s=\"%s\"> 不是整数" % (a, v))
                        continue
                    if n <= 0:
                        self.err(where, "<wp:extent %s=%d> 必须为正" % (a, n))
            docpr = inl.find(WP + "docPr")
            if docpr is None:
                self.err(where, "<wp:inline> 缺少 <wp:docPr>")
            else:
                if docpr.get("id") is None:
                    self.err(where, "<wp:docPr> 缺少 id 属性")
                if docpr.get("name") is None:
                    self.err(where, "<wp:docPr> 缺少 name 属性")
            # blip 引用
            blips = inl.findall(".//" + A + "blip")
            if not blips:
                self.err(where, "<wp:inline> 里没有 <a:blip>，图片没有引用目标")
            for b in blips:
                rid = b.get(R + "embed")
                if not rid:
                    self.err(where, "<a:blip> 缺少 r:embed")
                else:
                    self.embeds.append((where, rid))
            # pic 结构
            pics = inl.findall(".//" + PIC + "pic")
            if not pics:
                self.err(where, "<wp:inline> 里没有 <pic:pic>")
            for p in pics:
                for sub in ("nvPicPr", "blipFill", "spPr"):
                    if p.find(PIC + sub) is None:
                        self.err(where, "<pic:pic> 缺少 <pic:%s>" % sub)



def main():
    path = sys.argv[1]
    zf = zipfile.ZipFile(path)
    names = set(zf.namelist())
    ck = Checker()

    # 1) 必需部件
    for n in ("[Content_Types].xml", "_rels/.rels", "word/document.xml"):
        if n not in names:
            ck.err("package", "缺少必需部件 %s" % n)

    # 2) 关系目标存在性
    rel_by_id = {}
    if "word/_rels/document.xml.rels" in names:
        import xml.etree.ElementTree as ET
        rels = ET.fromstring(zf.read("word/_rels/document.xml.rels"))
        for rel in rels:
            tgt = rel.get("Target") or ""
            if rel.get("TargetMode") == "External":
                continue
            full = "word/" + tgt.lstrip("/") if not tgt.startswith("/") else tgt.lstrip("/")
            rel_by_id[rel.get("Id")] = (rel.get("Type") or "", full)
            if full not in names:
                ck.err("rels", "关系指向不存在的部件: %s -> %s" % (rel.get("Id"), full))

    # 3) 结构
    if "word/document.xml" in names:
        import xml.etree.ElementTree as ET
        raw_doc = zf.read("word/document.xml")
        try:
            root = ET.fromstring(raw_doc)
        except Exception as e:
            # 命名空间缺失 / 标签不配对时 ET 直接抛。这属于最严重的一类，
            # 必须报出来而不是让脚本带着 traceback 崩掉（崩了同样算失败，
            # 但看不出根因，也没法和其他问题一起列）。
            print("❌ document.xml 不是 well-formed XML：%s" % e)
            pos = 0
            m = re.search(r"column (\d+)", str(e))
            if m:
                pos = max(0, int(m.group(1)) - 60)
            print("   附近内容：%r" % raw_doc[max(0, pos):pos + 160].decode("utf-8", "replace"))
            sys.exit(1)
        if tag_of(root) != "document":
            ck.err("document.xml", "根元素不是 w:document")
        bodies = [c for c in root if tag_of(c) == "body"]
        if not bodies:
            ck.err("document.xml", "缺少 w:body")
        for b in bodies:
            ck.check_body(b, "document.xml/body")
            pi = 0
            for ch in b:
                t = tag_of(ch)
                if t == "p":
                    pi += 1
                    ck.check_p(ch, "document.xml/body/p[%d]" % pi, "")
                elif t == "sectPr":
                    ck.check_sectpr(ch, "document.xml/body/sectPr")

    # 4) v21：图片四处联动。
    #    正文 r:embed → document.xml.rels 的 Id → Target 的 media 部件
    #    → [Content_Types] 的 Default Extension。
    #    缺任意一环，Word 打开时就会报「无法读取的内容」。
    if ck.embeds:
        seen = {}
        for where, rid in ck.embeds:
            if rid in seen:
                ck.err(where, "同一 rId=%s 被重复引用（%s 与 %s）" % (rid, seen[rid], where))
            seen[rid] = where
            if rid not in rel_by_id:
                ck.err(where, "r:embed=\"%s\" 在 document.xml.rels 里不存在" % rid)
                continue
            rtype, target = rel_by_id[rid]
            if not rtype.endswith("/image"):
                ck.err(where, "rId=%s 的关系类型是 %s，不是 image" % (rid, rtype))
            ext = target.rsplit(".", 1)[-1].lower() if "." in target else ""
            ct = zf.read("[Content_Types].xml").decode("utf-8")
            if ext and ('Extension="%s"' % ext) not in ct:
                ck.err("Content_Types", "正文引用了 .%s 图片，但 [Content_Types].xml 里"
                                        "没有对应的 Default Extension 声明" % ext)
        # 孤儿关系（有 media 但正文没引用）不算错，但值得提示
        for rid, (rtype, target) in rel_by_id.items():
            if rtype.endswith("/image") and rid not in seen:
                print("  [提示] rels 里的 %s -> %s 未被正文引用（孤儿图片）" % (rid, target))

    # 5) 统计
    import xml.etree.ElementTree as ET
    if "word/document.xml" in names:
        d = zf.read("word/document.xml").decode("utf-8")
        print("段落数 <w:p></w:p> :", d.count("<w:p>") + d.count("<w:p "))
        nimg = d.count("<w:drawing>")
        if nimg:
            print("图片 <w:drawing> :", nimg)
            media = [n for n in names if n.startswith("word/media/")]
            print("media 部件       :", len(media), media)

    print()
    if ck.errors:
        print("❌ 发现 %d 处结构违规：" % len(ck.errors))
        for i, e in enumerate(ck.errors, 1):
            print("  [%02d] %s" % (i, e))
        sys.exit(1)
    print("✅ OOXML 结构校验通过（body / p / pPr / rPr / sectPr / pgMar / sz / jc / drawing）")


if __name__ == "__main__":
    main()
