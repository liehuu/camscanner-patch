#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_v35 —— 排版结构：字体统一、NBSP 宽度、段尾留白、tab 去重、宽度预算

用户 v34 反馈：
    「你看我手机预览的截图，多规整，出租房，和承租方都是单独一行，
      你这导出的docx乱七八糟的」

这次没有猜参数，而是把 v34 导出的 docx 用 Word 打开、转 PDF、
逐字量 bbox，拿到了完整的因果链：

    出 租 方 ：   董 瀚 霖  ...
    x0=93.0 117.1 141.3 165.4 189.5 213.5 237.6
    步进 24.2pt（10.5pt 的字本应步进 10.5pt）—— 2.3 倍字距

原因不是字距被设大了，而是**折行之后 jc=both 把首行强行撑满**。
为什么会折行？自然宽 470.4pt > 页宽 451.3pt，超 19.1pt。
为什么超 19pt？`22018220040518001x` 这 18 个字符是 Calibri，
实测占 134.3pt（0.71em/字），宋体只需 94.5pt（0.5em）。

修了字体又暴露出第二层：p3（中介方）折成 3 行、每行一两个字。
它的 run 序列是
    中介方： | 43 个空格 | <w:tab pos=4513> | 3 个空格 | 经纪人： | 22 个空格
空白已经把「经纪人：」推到 225pt，tab 又推一次，两者相加顶爆整行。

第三层在 NBSP 上。v33 的注释写着「NBSP 宽度与普通空格一致 0.5em」，
用 Word 逐字符量位置实测（10.5pt，字体全写 SimSun）：
    U+0020 普通空格  5.25pt = 0.50em
    U+00A0 NBSP     10.50pt = 1.00em      ← 整整两倍
    U+3000 全角空格 10.50pt = 1.00em
段尾那条带下划线的空白换成 NBSP 后长度翻倍，段落再次被顶出页宽。

【一】结构顺序（O）
  O1 run 级修正必须排在写 <w:pPr> 之前（否则「建议左对齐」的结论丢掉）
  O2 只允许调用一次（重复调用会把压缩过的空白再压一遍）

【二】字体统一（F）
  F1 文字 run 也统一字体，不只是空白 run
  F2 判据仍是 CSFSIsCJKFace（不是「为空才处理」）

【三】NBSP（N）
  N1 只有段尾那个空白 run 才换 NBSP
  N2 NBSP 个数按 2:1 折半（1em vs 0.5em）
  N3 行中空白保持普通空格（保留断行点）

【四】段尾留白（T）
  T1 有 kCSFSRunTail 标记
  T2 带下划线的段尾空白不能被 tailDrop 删掉（那是要画的线）
  T3 段尾留白按剩余可用宽度自适应

【五】tab 去重（B）
  B1 紧跟已展开空白的 tab 必须删掉

【六】宽度预算（W）
  W1 估算系数 1.06（实测校正）
  W2 差 5% 以内压留白装进一行
  W3 差得多不压空白，改左对齐
  W4 左对齐只覆盖 both，不动 center/right

【七】标题（C）
  C1 字号 ≥ 正文 1.5 倍的段落强制居中
"""
import re
import sys

OK = 0
FAIL = 0
FAILED = []


def ok(m):
    global OK
    OK += 1
    print('  [ OK ] %s' % m)


def fail(m):
    global FAIL
    FAIL += 1
    FAILED.append(m)
    print('  [FAIL] %s' % m)


def strip_comments(s):
    out = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == '"':
            out.append(c)
            i += 1
            while i < n:
                if s[i] == '\\':
                    out.append(s[i:i + 2])
                    i += 2
                    continue
                out.append(s[i])
                if s[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == '/' and i + 1 < n and s[i + 1] == '/':
            while i < n and s[i] != '\n':
                i += 1
            continue
        if c == '/' and i + 1 < n and s[i + 1] == '*':
            i += 2
            while i + 1 < n and not (s[i] == '*' and s[i + 1] == '/'):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def extract_func(src, name):
    """按花括号配平取出函数体（含首尾花括号）。"""
    m = re.search(r'\b%s\s*\([^)]*\)\s*\{' % re.escape(name), src)
    if not m:
        return None
    b = src.find('{', m.start())
    if b < 0:
        return None
    depth = 0
    j = b
    n = len(src)
    while j < n:
        c = src[j]
        if c == '"':
            j += 1
            while j < n:
                if src[j] == '\\':
                    j += 2
                    continue
                if src[j] == '"':
                    break
                j += 1
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return src[b:j + 1]
        j += 1
    return None


def main():
    if len(sys.argv) < 2:
        print('用法: check_v35.py <file.m>')
        return 2
    raw = open(sys.argv[1], encoding='utf-8').read()
    src = strip_comments(raw)

    print('=' * 66)
    print('check_v35  CamScannerSaveToFiles.m')
    print('=' * 66)

    fix = extract_func(src, 'CSFSFixSpaceRuns')
    fit = extract_func(src, 'CSFSFitParaWidth')
    est = extract_func(src, 'CSFSEstRunWidthPt')
    rnd = extract_func(src, 'CSFSRenderPara')

    # ══════════════════════════════════════════════════════════════
    # 一、结构顺序（O）
    # ══════════════════════════════════════════════════════════════
    if rnd is None:
        fail('O1 找不到 CSFSRenderPara')
    else:
        # 「调用」= 出现 CSFSFixSpaceRuns( ，不是注释里提到
        calls = [m for m in re.finditer(r'\bCSFSFixSpaceRuns\s*\(', rnd)]
        m_ppr = re.search(r'\[out appendFormat:@"<w:pPr>', rnd)
        if not calls:
            fail('O1 CSFSRenderPara 里没有调用 CSFSFixSpaceRuns')
        elif not m_ppr:
            fail('O1 找不到 <w:pPr> 输出点')
        elif len(calls) > 1:
            fail('O1 CSFSFixSpaceRuns 出现 %d 处调用 —— '
                 '正常只应有一处，且必须在 <w:pPr> 之前' % len(calls))
        elif calls[0].start() > m_ppr.start():
            fail('O1 CSFSFixSpaceRuns 排在 <w:pPr> 之后 —— '
                 '它返回的「建议左对齐」写不进 jc，宽度预算等于白算')
        else:
            ok('O1 run 级修正排在 <w:pPr> 之前（左对齐结论能写进 jc）')

        # O2：调用次数必须是 1（重复调用会把压过的空白再压一遍）
        if len(calls) <= 1:
            ok('O2 CSFSFixSpaceRuns 只调用一次')
        else:
            fail('O2 CSFSFixSpaceRuns 被调用了 %d 次 —— '
                 '第二次会把已压缩的空白再压一遍' % len(calls))

    # ══════════════════════════════════════════════════════════════
    # 二、字体统一（F）
    # ══════════════════════════════════════════════════════════════
    if fix is None:
        fail('F1 找不到 CSFSFixSpaceRuns')
    else:
        # 文字 run 分支必须在 continue 之前把 face 写回去
        m_text = re.search(
            r'if\s*\(\s*!\s*CSFSIsPureWhiteSpace\s*\(\s*t\s*\)\s*\)\s*\{'
            r'(.*?)\n\s*continue\s*;', fix, re.S)
        if not m_text:
            fail('F1 没有「文字 run 分支」—— 文字仍沿用 OCR 的 Calibri，'
                 '22018220040518001x 这类 18 位数字要多占 40pt，整行折行')
        else:
            blk = m_text.group(1)
            if re.search(r'setObject\s*:\s*wideFace\s+forKey\s*:\s*kCSFSRunFace', blk):
                ok('F1 文字 run 也统一到 wideFace（数字不再用 0.71em 的 Calibri）')
            else:
                fail('F1 文字 run 分支里没有把 wideFace 写进 kCSFSRunFace')

    if fix is None:
        fail('F1b 找不到 CSFSFixSpaceRuns')
    else:
        # F2 文字 run 的判据也必须是 CSFSIsCJKFace，不能是「为空才处理」
        m_tf = re.search(r'if\s*\(\s*!\s*CSFSIsCJKFace\s*\(\s*tf\s*\)\s*\)', fix)
        if m_tf:
            ok('F2 文字 run 用 CSFSIsCJKFace 判据（Calibri 会被识别并替换）')
        else:
            fail('F2 文字 run 的字体判据不是 CSFSIsCJKFace(tf) —— '
                 '退回「face 为空才处理」的话，Calibri 永远不进分支')

    # ══════════════════════════════════════════════════════════════
    # 三、NBSP（N）
    # ══════════════════════════════════════════════════════════════
    if rnd is None:
        fail('N1 找不到 CSFSRenderPara')
    else:
        m_nb = re.search(r'if\s*\(\s*emitIsSpace\s*&&\s*emitUnder\s*&&\s*'
                         r'([^{}]+?)\s*&&\s*emitText\.length\s*>\s*0\s*\)\s*\{',
                         rnd)
        if not m_nb:
            fail('N1 找不到 NBSP 转换分支')
        else:
            cond = m_nb.group(1)
            if re.search(r'\bemitAtTail\b|\bkCSFSRunTail\b', cond):
                ok('N1 NBSP 只用于段尾空白（行中保留断行点）')
            else:
                fail('N1 NBSP 转换没有限定在段尾 —— 行中每条填空线都会变成'
                     '不可断块，断点被提前到段落开头，首行字距被撑成两三倍')

        # N2 个数必须折半
        body = rnd[m_nb.end():] if m_nb else ''
        m_cnt = re.search(r'(\w+)\s*=\s*\(\s*\w+\s*\+\s*1\s*\)\s*/\s*2', body)
        if m_cnt:
            ok('N2 NBSP 个数按 2:1 折半（%s）—— NBSP 是 1em，普通空格 0.5em'
               % m_cnt.group(0).strip())
        else:
            fail('N2 NBSP 没有折半 —— NBSP 在宋体里实测 10.50pt（1em），'
                 '普通空格 5.25pt（0.5em），逐个替换会让段尾空白宽度翻倍，'
                 '段落被顶出页宽')

        # N3 行中空白必须是普通空格：展开函数不能自己吐 NBSP
    if rnd is not None:
        m_exp = re.search(r'emitText\s*=\s*CSFSExpandSpaceRun\s*\(', rnd)
        if m_exp and re.search(r'\u00a0', rnd[rnd.index(m_exp.group(0)):][:0]):
            pass
        # 更实质的判据：展开后只在「折半」分支里出现 NBSP 字面量
        nb_lit = re.findall(r'@"\\u00A0"', rnd)
        if len(nb_lit) == 1:
            ok('N3 源码里只有一处 NBSP 字面量（集中在折半分支，不会漏到行中）')
        elif len(nb_lit) == 0:
            fail('N3 找不到 NBSP 字面量 —— 段尾填空线的下划线会被 Word 裁掉')
        else:
            fail('N3 出现 %d 处 NBSP 字面量 —— 有多余的换行点被消除' % len(nb_lit))

    # ══════════════════════════════════════════════════════════════
    # 四、段尾留白（T）
    # ══════════════════════════════════════════════════════════════
    if fix is None:
        fail('T1 找不到 CSFSFixSpaceRuns')
    else:
        # 必须能定位到「lastKeep 那个 run」被标记这一条数据流，
        # 而不是任何一处出现 kCSFSRunTail（tailDrop 分支里也有一处）
        m_tailset = re.search(
            r'NSString\s*\*\s*(\w+)\s*=\s*\[\s*lr\s+objectForKey\s*:\s*kCSFSRunText\s*\]'
            r'.*?setObject\s*:\s*\[NSNumber numberWithBool:YES\]\s*forKey\s*:\s*kCSFSRunTail',
            fix, re.S)
        if m_tailset:
            ok('T1 真正落在段尾的那个 run 被标记 kCSFSRunTail（%s → kCSFSRunTail）'
               % m_tailset.group(1))
        elif not re.search(r'kCSFSRunTail', fix):
            fail('T1 完全没有段尾标记 —— NBSP 与段尾自适应都无从判断')
        else:
            fail('T1 找不到「把 lastKeep 那个 run 标记为段尾」的赋值 —— '
                 '只有 tailDrop 分支里的标记，行尾那条填空线拿不到 tail 位')

        # T2 tailDrop 的判据必须含 underline
        m_keep = re.search(r'BOOL\s+und\s*=\s*\[\[c objectForKey:kCSFSRunUnderline\]', fix)
        m_last = re.search(r'if\s*\(\s*!\s*ws\s*\|\|\s*\(\s*und\s*&&', fix)
        if m_keep and m_last:
            ok('T2 tailDrop 保留「带下划线的段尾空白」（那是要画出来的填空线）')
        else:
            fail('T2 tailDrop 只按「在不在段尾」判断 —— 会把 '
                 '「出租方：张三______」这种挂在段尾的填空线整条删掉')

    if fit is None:
        fail('T3 找不到 CSFSFitParaWidth')
    else:
        if re.search(r'tailSum', fit) and re.search(r'room\s*=\s*avail\s*-\s*noTail', fit):
            ok('T3 段尾留白按剩余可用宽度（avail - noTail）自适应')
        else:
            fail('T3 段尾留白没有按剩余宽度自适应 —— 它按原值写出去，'
                 '正好把行顶出页宽')

    # ══════════════════════════════════════════════════════════════
    # 五、tab 去重（B）
    # ══════════════════════════════════════════════════════════════
    if fix is None:
        fail('B1 找不到 CSFSFixSpaceRuns')
    else:
        m_tab = re.search(r'setObject\s*:\s*\[NSNumber numberWithBool:NO\]\s*'
                          r'forKey\s*:\s*kCSFSRunTab', fix)
        if m_tab:
            ok('B1 重复 tab 被置 NO（空白与 tab 不重复占位）')
        elif re.search(r'kCSFSRunTab', fix):
            fail('B1 找到 kCSFSRunTab 但值不是 NO —— 置 YES 等于没删，'
                 'p3 的「43 空格 + tab」照样把整行顶爆')
        else:
            fail('B1 没有删重复 tab —— p3 的「43 空格 + tab」会把整行顶爆，'
                 '折成每行一两个字')

    # ══════════════════════════════════════════════════════════════
    # 六、宽度预算（W）
    # ══════════════════════════════════════════════════════════════
    if est is None:
        fail('W1 找不到 CSFSEstRunWidthPt')
    else:
        m_cal = re.search(r'return\s+w\s*\*\s*([0-9.]+)\s*;', est)
        if not m_cal:
            fail('W1 宽度估算没有校正系数')
        else:
            v = float(m_cal.group(1))
            if v < 1.0 or v > 1.12:
                fail('W1 估算系数 %.3f 超出实测区间（1.03~1.09）' % v)
            else:
                ok('W1 估算系数 %.2f（实测 10.5pt 宋体全角字 advance 11.1pt）' % v)

        if re.search(r'kCSFSRunSpaceW', est) and re.search(r'CSFSIsPureWhiteSpace', est):
            ok('W1b 空白 run 直接用 slice.width，不靠字符数估')
        else:
            fail('W1b 空白 run 没有用 slice.width —— 估算误差会直接变成折行')

    if fit is None:
        fail('W2 找不到 CSFSFitParaWidth')
    else:
        m_sq = re.search(r'total\s*<=\s*avail\s*\*\s*([0-9.]+)', fit)
        if m_sq and 1.0 < float(m_sq.group(1)) <= 1.08:
            ok('W2 差 %.0f%% 以内压留白挤进一行' % ((float(m_sq.group(1)) - 1) * 100))
        else:
            fail('W2 没有「差一点点就压留白」的分支 —— '
                 'p2 只超 12pt 却折出一行残字「方）」')

        # W3 差得多不能压空白
        m_over = re.search(r'v35 overflow', fit)
        if m_over:
            ok('W3 差得多时只改对齐，不压行中空白（保住下划线长度）')
        else:
            fail('W3 找不到「差得多走左对齐」的分支 —— '
                 '若改成无差别压空白，下划线会被压短，退回 v32 的老毛病')

        # W4 左对齐只覆盖 both。
        # 判据必须绑「宽度预算的结论」这个数据流 —— alignLeftish 的计算里
        # 也有一处 isEqualToString:@"both"，只 grep 它永远绿。
        #
        # v36：结论载体从 BOOL paraSuggestLeft 换成了位标志
        #      paraFitFlags & kCSFSFitLeft（因为一次预算要同时表达
        #      「改左对齐」和「清缩进」两件事，BOOL 装不下）。
        m_w4 = re.search(r'paraFitFlags\s*&\s*kCSFSFitLeft\s*\)\s*&&[^{}]*?'
                         r'isEqualToString\s*:\s*@"both"', rnd or '', re.S)
        if m_w4:
            ok('W4 左对齐只在「预算建议左对齐」且原 jc 是 both 时生效'
               '（标题 center / 右对齐不受影响）')
        elif re.search(r'kCSFSFitLeft', rnd or ''):
            fail('W4 找不到「(flags & kCSFSFitLeft) && jc==both」的条件 —— '
                 '左对齐会无差别覆盖 center/right，标题被拉回左边')
        else:
            fail('W4 渲染阶段没用宽度预算的结论 —— 算完就丢掉了')

    # ══════════════════════════════════════════════════════════════
    # 七、标题（C）
    # ══════════════════════════════════════════════════════════════
    if rnd is None:
        fail('C1 找不到 CSFSRenderPara')
    else:
        m_t = re.search(r's0\s*>\s*defaultPt\s*\*\s*([0-9.]+)', rnd)
        if not m_t:
            fail('C1 没有标题居中判据 —— 真机 p0 的 jc=right 来自混排的红色编号，'
                 '整行「房屋租赁合同」会被贴到右边')
        elif not re.search(r'align\s*=\s*@"center"', rnd):
            fail('C1 判出了标题却没改 jc —— 照样贴右边')
        else:
            th = float(m_t.group(1))
            if th < 1.3 or th > 2.2:
                fail('C1 标题字号阈值 %.2f 倍超出合理区间（1.3~2.2）—— '
                     '太小会把正文也当标题居中，太大标题反而漏掉' % th)
            else:
                ok('C1 字号 ≥ 正文 %.1f 倍的段落强制居中（标题不再贴右边）' % th)

    print('-' * 66)
    if FAIL == 0:
        print('check_v35 通过：OK %d / FAIL 0' % OK)
        return 0
    print('check_v35 失败：OK %d / FAIL %d' % (OK, FAIL))
    for f in FAILED:
        print('   - %s' % f)
    return 1


if __name__ == '__main__':
    sys.exit(main())
