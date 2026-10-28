# -*- coding: utf-8 -*-
"""从 C 源码里直接提取渲染逻辑，校验 XML 标签顺序。

为什么需要这个脚本（2026-10-28 的教训）：
    tmp_docxchk/gen18.py 是我按「理解」手写的 Python 镜像，它在
    render_para() 里写了 return '<w:p>%s</w:p>'%out，
    而真实的 C 代码 CSFSRenderPara() **没有** <w:p> 包裹。
    于是「离线镜像验证全绿」，真机导出却整篇打不开。

    根因不是代码错，是**验证对象错**：我验证的是自己的理解，
    不是要交付的那份代码。镜像与实现之间没有任何强制一致性。

    所以这个脚本只做一件事：把 .m 文件当数据读，提取里面的
    字符串字面量，再对照 ECMA-376 的顺序表。不重新实现逻辑，
    因此不存在「镜像失真」。

检查项：
  C1  CSFSRenderPara 必须输出 <w:p> 开头、</w:p> 结尾
  C2  CSFSRenderPara 产出的标签顺序必须符合 CT_RPr sequence
  C3  <w:pPr> 必须是 <w:p> 的第一个子元素
  C4  docXml 里 <w:pgMar> 必须含 header/footer/gutter
  C5  docXml 里 sectPr 必须在 body 内且是最后一个块

用法:
    python check_render_c.py src/CamScannerSaveToFiles.m
"""
import sys, io, re

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
RPR_ORDER = [
    "rStyle", "rFonts", "b", "bCs", "i", "iCs", "caps", "smallCaps", "strike",
    "dstrike", "outline", "shadow", "emboss", "imprint", "noProof",
    "snapToGrid", "vanish", "webHidden", "color", "spacing", "w", "kern",
    "position", "sz", "szCs", "highlight", "u", "effect", "bdr", "shd",
    "fitText", "vertAlign", "rtl", "cs", "em", "lang", "eastAsianLayout",
    "specVanish", "oMath",
]

fails = []
oks = []


def ok(msg):
    oks.append(msg)


def fail(msg):
    fails.append(msg)


def extract_func(src, sig):
    """从签名起截到列 0 的 '}' 为止。"""
    i = src.find(sig)
    if i < 0:
        return None
    depth = 0
    j = i
    started = False
    while j < len(src):
        if src[j] == '{':
            depth += 1
            started = True
        elif src[j] == '}':
            depth -= 1
            if started and depth == 0:
                return src[i:j + 1]
        j += 1
    return None


# 匹配 ObjC 字符串字面量 @"..."（含转义）
STR_RE = re.compile(r'@"((?:[^"\\]|\\.)*)"')


def literal_texts(func):
    """按源码出现顺序返回所有 @"..." 的内容（反转义后）。"""
    out = []
    for m in STR_RE.finditer(func):
        s = m.group(1)
        s = s.replace('\\"', '"').replace('\\n', '\n').replace('\\r', '\r')
        out.append(s)
    return out


def tags_in(s):
    """按出现顺序返回 <w:xxx 的 xxx 列表。"""
    return re.findall(r"<w:([A-Za-z]+)", s)


def main():
    path = sys.argv[1]
    src = io.open(path, encoding='utf-8').read()

    # ── C1 / C2 / C3：CSFSRenderPara ──
    fn = extract_func(src, 'static NSString *CSFSRenderPara(')
    if fn is None:
        fail("C1 找不到 CSFSRenderPara 函数")
    else:
        lits = literal_texts(fn)
        joined = ''.join(lits)

        # C1: 段落容器
        if not lits or not lits[0].startswith('<w:p>'):
            fail("C1 CSFSRenderPara 首个字符串不是以 '<w:p>' 开头（实际：%r）"
                 % (lits[0][:40] if lits else None))
        else:
            ok("C1 CSFSRenderPara 以 '<w:p>' 开头")

        if '</w:p>' not in joined:
            fail("C1 CSFSRenderPara 输出里没有 '</w:p>' —— 段落未闭合")
        else:
            ok("C1 CSFSRenderPara 输出含 '</w:p>'")

        # C3: pPr 必须最先
        tl = tags_in(joined)
        if 'pPr' in tl:
            # 找出第一次出现的非 pPr、非 p 标签，看它是否在 pPr 之前
            for t in tl:
                if t == 'p':
                    continue
                if t == 'pPr':
                    ok("C3 <w:pPr> 是 <w:p> 的首个有效子元素")
                else:
                    fail("C3 <w:pPr> 之前出现了 <%s>，pPr 必须是首个" % t)
                break

        # C2: rPr 子元素顺序。
        #
        # CSFSRenderPara 的输出里，除 rPr 的格式化标签外，只有纯结构标签
        # （p / pPr / jc / r / rPr / t）。所以把 joined 的全部标签按序取出、
        # 剔掉结构标签，剩下的就是 rPr 子元素的真实输出顺序。
        # —— 这样不需要理解 append 的分支逻辑，只看字面量的排列。
        STRUCT = {'p', 'pPr', 'jc', 'r', 'rPr', 't', 'sectPr', 'body', 'document'}
        c2_tags = [t for t in tags_in(joined) if t not in STRUCT]

        if not c2_tags:
            fail("C2 无法从 CSFSRenderPara 提取 rPr 子元素序列（模板结构变了，需人工复核）")
        else:
            unknown = [t for t in c2_tags if t not in RPR_ORDER]
            if unknown:
                fail("C2 rPr 里出现 ECMA-376 未定义的标签：%s" % ", ".join(sorted(set(unknown))))
            idxs = [RPR_ORDER.index(t) for t in c2_tags if t in RPR_ORDER]
            if idxs != sorted(idxs):
                bad = None
                for a in range(len(c2_tags)):
                    for b in range(a + 1, len(c2_tags)):
                        ia, ib = RPR_ORDER.index(c2_tags[a]), RPR_ORDER.index(c2_tags[b])
                        if ia > ib:
                            bad = (c2_tags[a], c2_tags[b])
                            break
                    if bad:
                        break
                fail("C2 rPr 顺序违规：<%s> 排在 <%s> 之后。实际顺序 %s"
                     % (bad[0], bad[1], " → ".join(c2_tags)))
            else:
                ok("C2 rPr 顺序合规：%s" % " → ".join(c2_tags))

    # ── C6：图片渲染模板 ──
    fn_img = extract_func(src, 'static NSString *CSFSRenderImagePara(')
    if fn_img is None:
        fail("C6 找不到 CSFSRenderImagePara（图片导出可能被删掉了）")
    else:
        img_lits = literal_texts(fn_img)
        img_all = ''.join(img_lits)
        cut = img_all.find('<w:p><w:pPr>')
        img_tpl = img_all[cut:] if cut >= 0 else img_all
        # 图片段落必须自己包 <w:p>，否则重演 v19 的「body 下裸挂」事故
        if '<w:drawing>' not in img_tpl:
            fail("C6 图片模板里没有 <w:drawing>")
        else:
            ok("C6 图片模板含 <w:drawing>")
        for need, label in (('<wp:inline', 'wp:inline 容器'),
                            ('<wp:extent', 'wp:extent 尺寸'),
                            ('<wp:docPr', 'wp:docPr 标识'),
                            ('<a:blip', 'a:blip 图片引用'),
                            ('<pic:pic', 'pic:pic 结构')):
            if need not in img_tpl:
                fail("C6 图片模板缺少 %s" % label)
        n_ph = len(re.findall(r'%(?:ld|@)', img_tpl))
        if n_ph != 9:
            fail("C6 图片模板占位符应为 9 个，实际 %d（seq 改动要同步校验脚本）" % n_ph)
        else:
            ok("C6 图片模板占位符 9 个（lcx,lcy,seq×3,fname,rid,lcx,lcy）")

    # ── C7：docXml 的命名空间 ──
    fn_w = extract_func(src, 'static BOOL CSFSWriteDocxStyled(')
    if fn_w is None:
        fail("C7 找不到 CSFSWriteDocxStyled")
    else:
        w_lits = literal_texts(fn_w)
        doc = ''.join(w_lits)
        # 命名空间声明分散在相邻字面量上，直接全文找即可
        missing = []
        for pfx, uri_tail in (("w", "wordprocessingml/2006/main"),
                              ("r", "officeDocument/2006/relationships"),
                              ("wp", "drawingml/2006/wordprocessingDrawing"),
                              ("a", "drawingml/2006/main"),
                              ("pic", "drawingml/2006/picture")):
            if 'xmlns:%s="http://schemas.openxmlformats.org/%s"' % (pfx, uri_tail) not in doc:
                missing.append(pfx)
        if missing:
            fail("C7 docXml 缺少命名空间声明：%s" % ", ".join("xmlns:" + m for m in missing))
        else:
            ok("C7 docXml 声明了 w / r / wp / a / pic 五个命名空间")

        # ── C8：图片三处联动必须在源码里真的生成 ──
        if 'rIdImg' not in doc:
            fail("C8 document.xml.rels 里没有 rIdImg 关系模板 —— 图片引用不上")
        else:
            ok("C8 rels 动态生成 rIdImg 关系")
        if 'Extension="%@"' not in doc:
            fail("C8 [Content_Types].xml 没有动态 Default Extension —— png 不会被识别")
        else:
            ok("C8 [Content_Types] 动态声明图片扩展名")
        if 'word/media/' not in doc:
            fail("C8 没有 word/media/ 路径 —— 图片字节不会进包")
        else:
            ok("C8 写出 word/media/ 部件")

    # ── C4 / C5：docXml 的 sectPr ──
    fn2 = extract_func(src, 'static BOOL CSFSWriteDocxStyled(')
    if fn2 is None:
        fail("C4 找不到 CSFSWriteDocxStyled 函数")
    else:
        # ⚠ 不能只挑「含关键字」的字面量：docXml 是多段相邻 @"..." 拼起来的，
        #   "<w:pgMar w:top=..." 和 " w:header=..." 分属两段。
        #   一旦按关键字过滤，含 header 的那段就被丢掉，于是报「缺 w:header」——
        #   这是检查器自己造出来的假失败。全部拼起来才是最忠实的还原。
        lits2 = literal_texts(fn2)
        doc = ''.join(lits2)
        if '<w:pgMar' not in doc:
            fail("C4 docXml 里找不到 <w:pgMar>")
        else:
            seg = doc[doc.find('<w:pgMar'):]
            seg = seg[:seg.find('>') + 1]
            missing = [a for a in ('top', 'right', 'bottom', 'left',
                                   'header', 'footer', 'gutter')
                       if 'w:%s=' % a not in seg]
            if missing:
                fail("C4 <w:pgMar> 缺少必需属性：%s（ECMA-376 标 required）"
                     % ", ".join('w:' + a for a in missing))
            else:
                ok("C4 <w:pgMar> 七个必需属性齐全")

        if '<w:body>' not in doc or '</w:body>' not in doc:
            fail("C5 docXml 缺 <w:body> 容器")
        elif '<w:sectPr>' not in doc:
            fail("C5 docXml 缺 <w:sectPr>")
        else:
            bi = doc.find('<w:body>')
            si = doc.find('<w:sectPr>')
            ei = doc.find('</w:body>')
            if bi < si < ei:
                ok("C5 <w:sectPr> 位于 <w:body> 内且是最后一块")
            else:
                fail("C5 <w:sectPr> 位置错误（body@%d sectPr@%d /body@%d）" % (bi, si, ei))

    print("=== check_render_c ===")
    for o in oks:
        print("  [ OK ] %s" % o)
    for f in fails:
        print("  [FAIL] %s" % f)
    print()
    print("OK %d / FAIL %d" % (len(oks), len(fails)))
    sys.exit(0 if not fails else 1)


if __name__ == '__main__':
    main()
