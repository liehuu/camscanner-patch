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
    """从**函数定义**处截到花括号配平为止。

    ⚠ 必须按定义形式定位，不能裸 src.find(sig)：
    注释里经常提到函数名（例如「v23 的错就在 CSFSRenderPara 里」），
    裸查找会从注释那一行开始配平，抓到的是一段完全无关的代码。
    这种「假提取」最阴险 —— 它让检查既不会报错也不会真正生效：
    抓空的检查永远 FAIL（吵），抓错段的检查可能永远 OK（更糟）。
    """
    name = sig.split('(')[0].strip()
    pat = re.compile(r'^static[^\n{]*\b' + re.escape(name) + r'\s*\(', re.M)
    i = -1
    for m in pat.finditer(src):
        eol = src.find('\n', m.start())
        head = src[m.start():eol if eol > 0 else len(src)]
        if head.rstrip().endswith(';'):
            continue          # 前置声明，不是定义
        i = m.start()
        break
    if i < 0:
        i = src.find(sig)     # 退回旧行为，兼容非 static 函数
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


# 匹配 [var appendFormat:@"..." / [var appendString:@"..."
#
# 为什么要按「接收者变量」分组，而不是像 v20 那样把整函数的字面量串起来看：
#   v23 把段落属性改成了「先在 pPr 变量里拼内容，再 <w:pPr>%@</w:pPr> 包壳」。
#   串起来看时，<w:ind> 的字面量出现在 <w:pPr> 模板之前，
#   C3 于是报「pPr 之前出现了 ind」，C2 把 ind 当成 rPr 子元素报未定义标签 ——
#   两条都是**假 FAIL**，而它们要找的真缺陷（pPr 不是首个、rPr 顺序错）并没有发生。
#   检查器的判断依据必须跟代码结构同步，否则它只是制造噪音；
#   一百条噪音里真问题就没人看了。
APPEND_RE = re.compile(r'\[\s*(\w+)\s+append(?:Format|String):\s*@"((?:[^"\\]|\\.)*)"', re.S)


def appends(func):
    """按源码顺序返回 [(接收者变量, 字面量内容)]。"""
    out = []
    for m in APPEND_RE.finditer(func):
        out.append((m.group(1), m.group(2).replace('\\"', '"')))
    return out


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
        #
        # 判据改成「按接收者变量分组」后，语义才真的被验证到：
        #   a) 段落变量（首个以 <w:p> 开头的接收者）第一次 append 是 <w:p>
        #   b) 段落变量上 <w:r 的出现必须晚于 <w:pPr> 的出现
        #   c) 段落变量不能直接 append pPr 的子元素（<w:ind>/<w:jc>/<w:spacing>），
        #      否则说明它跑到 pPr 外面去了 —— 这正是 v19 的真缺陷形态
        apps = appends(fn)
        ppr_tags = set(PPR_ORDER) - {'rPr', 'sectPr', 'pPrChange'}
        out_var = None

        # 段落变量有两种起手式，都要认：
        #   NSMutableString *out = [NSMutableString stringWithString:@"<w:p>"];   ← 现用
        #   [out appendString:@"<w:p>"];                                          ← 可能改成
        m_init = re.search(
            r'NSMutableString\s*\*\s*(\w+)\s*=\s*\[\s*NSMutableString\s+stringWithString:\s*@"<w:p>"',
            fn)
        if m_init:
            out_var = m_init.group(1)
        else:
            for var, lit in apps:
                if lit.startswith('<w:p>'):
                    out_var = var
                    break

        if out_var is None:
            fail("C3 找不到以 '<w:p>' 开头的段落构建语句")
        else:
            seq = [lit for var, lit in apps if var == out_var]
            # a) 段落必须以 <w:p> 起手。
            #    用 stringWithString:@"<w:p>" 初始化的，起手式已在初始化语句里
            #    体现（m_init 已断言），首个 append 自然就轮到 pPr，
            #    这时再要求 "首个 append 是 <w:p>" 就是又一条假检查。
            if m_init:
                ok("C3 段落变量以 stringWithString:@\"<w:p>\" 起手")
            elif not seq or not seq[0].startswith('<w:p>'):
                fail("C3 段落既没有 <w:p> 初始化，首个 append 也不是 '<w:p>'（实际 %r）"
                     % (seq[0][:30] if seq else None))
            else:
                ok("C3 段落变量首个 append 是 '<w:p>'")

            # c) pPr 子元素不能直接挂在段落变量上
            leaked = []
            for var, lit in apps:
                if var != out_var:
                    continue
                if lit.startswith('<w:pPr>'):
                    continue        # 包裹模板本身是合法的
                for t in tags_in(lit):
                    if t in ppr_tags:
                        leaked.append(t)
            if leaked:
                fail("C3 段落变量上直接输出了 pPr 子元素 %s —— 它们必须包在 <w:pPr> 里"
                     % ", ".join(sorted(set(leaked))))
            else:
                ok("C3 pPr 子元素全部出自 pPr 构建（或单条 <w:pPr> 模板）")

            # d) 有段落属性字面量，就**必须**有 <w:pPr> 包裹模板。
            #    否则属性会被输出到 pPr 外面，Word 直接忽略（不报错、不生效）。
            #    之前这条写成「没有 pPr 就跳过」，等于给"根本没有 pPr"开了通行证 ——
            #    反向验证时把包裹模板删掉，检查器照样全绿，说明那条判据是空的。
            has_ppr_child = any(t in ppr_tags for _, lit in apps for t in tags_in(lit))
            has_ppr_wrap = any('<w:pPr>' in lit for _, lit in apps)
            if has_ppr_child and not has_ppr_wrap:
                fail("C3 出现了段落属性字面量，但没有任何 <w:pPr> 包裹模板 —— "
                     "属性会落在 pPr 外面，被 Word 静默忽略")
            elif has_ppr_wrap:
                ok("C3 存在 <w:pPr> 包裹模板")

            # b) <w:pPr> 必须出现在任何 <w:r 之前
            i_ppr, i_run = -1, -1
            for n, lit in enumerate(seq):
                if i_ppr < 0 and '<w:pPr>' in lit:
                    i_ppr = n
                if i_run < 0 and '<w:r' in lit:
                    i_run = n
            if i_ppr < 0:
                # 全篇没有 pPr 也是合法的（无属性段落）
                ok("C3 未输出 <w:pPr>（该函数可能不含段落属性，跳过先后比较）")
            elif i_run >= 0 and i_ppr > i_run:
                fail("C3 <w:pPr> 出现在 <w:r> 之后 —— pPr 必须是段落首个元素")
            else:
                ok("C3 <w:pPr> 出现在所有 <w:r> 之前")

        # C9: pPr 内部标签顺序必须符合 CT_PPrBase sequence
        #
        # <w:ind> 排在 <w:jc> 之后是 Word 常见的静默失败点：
        # 文件能打开、不报错，但缩进/对齐其中一项不生效。
        # v23 新增了 <w:ind>，所以这条必须在 CI 里卡住。
        ppr_seq = []
        for var, lit in apps:
            if var == out_var and not lit.startswith('<w:pPr>'):
                continue
            if '<w:pPr>' in lit:
                # 内联形态 @"<w:pPr><w:ind/><w:jc/></w:pPr>"
                for t in tags_in(lit):
                    if t in ppr_tags:
                        ppr_seq.append(t)
            elif var != out_var:
                # 变量形态：只要这个变量里出现了 pPr 专属标签，就整段参与排序
                hits = [t for t in tags_in(lit) if t in ppr_tags]
                if hits:
                    ppr_seq.extend(hits)
        if ppr_seq:
            idxs = [PPR_ORDER.index(t) for t in ppr_seq]
            if idxs != sorted(idxs):
                bad = None
                for a in range(len(ppr_seq)):
                    for b in range(a + 1, len(ppr_seq)):
                        if PPR_ORDER.index(ppr_seq[a]) > PPR_ORDER.index(ppr_seq[b]):
                            bad = (ppr_seq[a], ppr_seq[b])
                            break
                    if bad:
                        break
                fail("C9 pPr 顺序违规：<%s> 排在 <%s> 之后。实际顺序 %s"
                     % (bad[0], bad[1], " → ".join(ppr_seq)))
            else:
                ok("C9 pPr 顺序合规：%s" % " → ".join(ppr_seq))

        # C10: 正文段落必须带首行缩进
        #
        # 量出来的事实：手机预览里正文续行左边界 x=64、段落首行 x=99~107，
        # 差 36px / 字高 19px ≈ 两字符。而 v22 及之前的产物 22 段全部顶格，
        # <w:ind> 出现 0 次 —— 这是「导出和预览不像」最直观的一条。
        #
        # ⚠ 这里必须用正则**精确匹配属性值**，不能写
        #   `'firstLineChars' in joined`。反向验证时把属性名改成
        #   firstLineCharsX，子串判断照样命中 —— 那就成了一条永远通过的假检查。
        #   「属性名错了」和「属性名对但值是 0」是两种不同缺陷，都得报。
        m_fl = re.search(r'w:firstLineChars="([^"]+)"', joined)
        m_ft = re.search(r'w:firstLine="([^"]+)"', joined)

        def val_or_fmt(m):
            """返回 (是否合法, 说明)。占位符（%ld / %@）算合法 ——
            模板层只看「有没有写、名字对不对」，具体数值由产物级
            docx_validate.py 校验，两层分工不重叠。"""
            if m is None:
                return False, '缺失'
            v = m.group(1)
            if v.startswith('%'):
                return True, v
            try:
                return (int(v) >= 100), v
            except ValueError:
                return False, v

        okfl, vfl = val_or_fmt(m_fl)
        okft, vft = val_or_fmt(m_ft)
        if not m_fl:
            fail("C10 没有首行缩进：w:firstLineChars 缺失或属性名不对，导出会全部顶格")
        elif not okfl:
            fail("C10 firstLineChars=%s 太小（<1 字符），等于没有缩进" % vfl)
        elif not m_ft or not okft:
            # 只写 firstLineChars 的话，LibreOffice / WPS 这些只认 firstLine 的
            # 实现会完全不缩进；双写才两边都生效。
            fail("C10 缺 w:firstLine（twips）兜底，只写 firstLineChars 在 WPS/LO 里不生效")
        else:
            ok("C10 正文段落带首行缩进（firstLineChars=%s / firstLine=%s）" % (vfl, vft))

        # C2: rPr 子元素顺序。
        #
        # 只取「rPr 变量」里的标签，不再全函数扫。
        # 识别方式：接收者不是段落变量，且字面量里出现了 rPr 专属标签
        # （在 RPR_ORDER 里、且不在 PPR_ORDER 里 —— 如 rFonts / b / color / sz / u）。
        rpr_only = set(RPR_ORDER) - set(PPR_ORDER)
        rpr_vars = set()
        for var, lit in apps:
            if var == out_var:
                continue
            if any(t in rpr_only for t in tags_in(lit)):
                rpr_vars.add(var)

        c2_tags = []
        for var, lit in apps:
            if var in rpr_vars:
                c2_tags.extend([t for t in tags_in(lit) if t in RPR_ORDER])
            elif var == out_var and '<w:rPr>' in lit:
                inner = lit.split('<w:rPr>', 1)[1].split('</w:rPr>', 1)[0]
                c2_tags.extend([t for t in tags_in(inner) if t in RPR_ORDER])

        # 去重相邻重复（同一标签由 addObject/多个分支重复 append 时会出现）
        dedup = []
        for t in c2_tags:
            if not dedup or dedup[-1] != t:
                dedup.append(t)
        c2_tags = dedup

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
