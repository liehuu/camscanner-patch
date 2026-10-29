#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_v33 —— CamScanner SaveToFiles 静态门禁（v33）

真机反馈（用户原话）：
  「去除手写和去除印章都生效了，但是空格下划线长度不对，
   甚至有的空格应该有下划线，却没有」

手写/印章两条已验收通过，本版只打「空格下划线」这一类，
但它其实是三个独立缺陷叠在一起。

════════════════════════════════════════════════════════════════════
【一】下划线「明显不够长」 —— width 的单位被乘错了 2.8 倍
════════════════════════════════════════════════════════════════════
v32 真机日志三条样本（每条都带 OCR 自己给的空格数）：

    w=56.0 pt=10.5 → 11 个空格 (原 11)
    w=12.0 pt=10.5 →  2 个空格 (原 2)
    w=36.0 pt=10.5 →  7 个空格 (原 7)

    56 / (0.5×10.5) = 10.67 → 11   ✓
    12 / 5.25       =  2.29 →  2   ✓
    36 / 5.25       =  6.86 →  7   ✓

三条独立样本全中，恒等式 y=x 摆在那里：**width 的单位就是 pt**。
而 v32 乘了 200dpi 的 0.3597，算出来 3.8 / 0.8 / 2.5 ——
只因为「不得少于原文字符数」那条兜底，才侥幸没把结果做小。
一旦某个填空线 OCR 只给 1 个空格、width 却很大，兜底就不再救场。

判据：
  W1 换算主路径必须直接用 sliceWidthPx（不许再乘 0.3597）
  W2 必须保留「不得少于原文字符数」的下限
  W3 必须保留上限 clamp（单位若错会撑爆整段）
  W4 width 不可用时必须原样返回，不许空造空格

════════════════════════════════════════════════════════════════════
【二】长度再短一半 —— Word 用 Calibri 渲染了空格
════════════════════════════════════════════════════════════════════
styles.xml 的 docDefaults 是：
    <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="宋体"/>
空格 U+0020 属 ASCII 区 → Word 走 ascii 那一路 → **Calibri**。
Calibri 空格 ≈ 0.226em，宋体 0.5em —— 差一半。
纯空白 run 自己没有 face，于是正好掉进这个坑。

判据：
  F1 必须有 CSFSFixSpaceRuns，且在 CSFSRenderPara 里、
     **写 XML 之前**被调用（run 都齐了才有上下文可继承）
  F2 必须能从相邻非空白 run 继承 face
  F3 继承不到时必须有兜底字体，**绝不允许留空**
  F4 兜底字体必须来自全文统计（gCSFSBodyFace），不能每段各猜一个
  F5 gCSFSBodyFace 必须在批次重置里清零

════════════════════════════════════════════════════════════════════
【三】「本来有下划线的空格，你只有空格」
════════════════════════════════════════════════════════════════════
两条独立成因，都要治：

(a) underline 的取值不是布尔。UIKit 的 NSUnderlineStyle 是
    Single=1 / Thick=2 / Double=9，序列化成 JSON 后可能是
    "single" / "thick" / "double"。而 CSFSBoolValue 只认
    "1"/"true"/"yes" —— "single" 被判成 NO，下划线静默丢弃。

(b) Word 会裁掉**行尾空格**（连它的下划线一起裁）。
    合同填空线有相当一部分正好在行尾、后面紧跟换行，
    于是线一条不剩。xml:space="preserve" 只保证 XML 解析层不丢空白，
    不代表排版时保留行尾空格的下划线。

判据：
  U1 underline 必须走 CSFSUnderlineValue，不许走 CSFSBoolValue
  U2 CSFSUnderlineValue 必须能接受「非 0/1 的肯定写法」（"single" 等）
  U3 必须能识别否定写法（"none"/"false"…），否则所有 run 都会被画线
  U4 带下划线的空白在输出前必须换成不换行空格 U+00A0
  U5 U+00A0 只用于**带下划线**的空白（普通词间空格换 NBSP 会丢断行点）

════════════════════════════════════════════════════════════════════
【四】填空线不许靠「空格个数」猜
════════════════════════════════════════════════════════════════════
数据里没带下划线的宽空白，要判「这是不是一条填空线」，
必须用**版面实测宽度**（width ÷ 字号 ≥ 2em），不能用空格个数 ——
个数是 OCR 给的，可能被截断；width 才是版面真实值。

  T1 补下划线的条件里必须用宽度/字号，不许用 text.length
  T2 阈值不能小到把「两个空格」当成线（1em 以下是词间距）

════════════════════════════════════════════════════════════════════
【五】统计日志的时机
════════════════════════════════════════════════════════════════════
v32 把 spaceExpanded 打在解析后、渲染前，日志里永远是 0，
而紧接着的明细又明明打出来了 —— 自相矛盾，上一轮差点据此误判。
  S1 「space stats」必须出现在 docx 写入之后

用法：python3 tools/check_v33.py src/CamScannerSaveToFiles.m
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


def assigned_vars(body, var):
    """该变量是否被赋了值（整标识符匹配，防前缀子串误判）。"""
    pat = (r'(?<![A-Za-z0-9_])%s\s*(?:=[^=]|\+=\|-=)'
           % re.escape(var))
    return re.search(pat, body) is not None


def main():
    if len(sys.argv) < 2:
        print('用法: check_v33.py <file.m>')
        return 2
    raw = open(sys.argv[1], encoding='utf-8').read()
    src = strip_comments(raw)

    print('=' * 66)
    print('check_v33  CamScannerSaveToFiles.m')
    print('=' * 66)

    # ══════════════════════════════════════════════════════════════
    # 一、宽度单位（W）
    # ══════════════════════════════════════════════════════════════
    exp = extract_func(src, 'CSFSExpandSpaceRun')
    if exp is None:
        fail('W1 找不到 CSFSExpandSpaceRun')
    else:
        # W1：不许再出现 200dpi 折算常量
        if re.search(r'595\.0\s*/\s*1654\.0', exp) or re.search(r'0\.3597', exp):
            fail('W1 CSFSExpandSpaceRun 仍在乘 200dpi 的 0.3597 —— '
                 '真机三条样本 w=56/12/36 对应 11/2/7 个空格，'
                 '证明 width 单位就是 pt；乘 0.3597 会把长度做小 2.8 倍')
        elif not re.search(r'double\s+pt\s*=\s*sliceWidthPx\s*;', exp):
            fail('W1 找不到「pt = sliceWidthPx」这条主路径 —— '
                 'width 若还在被折算，下划线长度不可能对上预览')
        else:
            ok('W1 宽度直接按 pt 用（不再乘 200dpi 系数）')

        # W2：不许比原文短
        if re.search(r'text\.length\s*>\s*n\s*\)\s*n\s*=\s*\(long\)\s*text\.length', exp) or \
           re.search(r'text\.length\s*>\s*n\)\s*n\s*=', exp):
            ok('W2 保留了「不得少于原文字符数」的下限')
        else:
            fail('W2 删掉了「不得少于原文字符数」的下限 —— '
                 '任何一次估算偏小都会让线更短')

        # W3：上限
        if re.search(r'n\s*>\s*\d+\s*\)\s*n\s*=\s*\d+', exp):
            ok('W3 保留了上限 clamp')
        else:
            fail('W3 没有上限 clamp —— width 单位一旦不是 pt 会算出上万空格，'
                 '整篇文档被撑爆')

        # W4：width 不可用时原样返回
        if re.search(r'!\s*\(\s*sliceWidthPx\s*>\s*0\.0\s*\)\s*\)\s*return\s+text', exp):
            ok('W4 width 不可用时原样返回')
        else:
            fail('W4 width 不可用时没有原样返回 —— 会凭空空造空格')

    # ══════════════════════════════════════════════════════════════
    # 二、空白 run 的属性补齐（F）
    # ══════════════════════════════════════════════════════════════
    fix = extract_func(src, 'CSFSFixSpaceRuns')
    if fix is None:
        fail('F1 找不到 CSFSFixSpaceRuns（纯空白 run 的属性补齐）')
    else:
        render = extract_func(src, 'CSFSRenderPara')
        if render is None:
            fail('F1 找不到 CSFSRenderPara')
        else:
            i_call = render.find('CSFSFixSpaceRuns(')
            i_emit = render.find('CSFSXMLEscape(emitText)')
            if i_call < 0:
                fail('F1 CSFSRenderPara 里没有调用 CSFSFixSpaceRuns —— '
                     '空白 run 的字体/下划线永远不会被补上')
            elif i_emit >= 0 and i_call > i_emit:
                fail('F1 CSFSFixSpaceRuns 排在写 XML 之后 —— '
                     '只改了内存里的 run，输出早就生成了')
            else:
                ok('F1 渲染前对整段 runs 做了空白补齐')

        # F2：从邻居继承 face
        #
        # 判据必须绑「sf 是从 src 取的、并且真的写进了 run」这条数据流，
        # 不能只 grep "forKey:kCSFSRunFace" —— 兜底分支里也有一处写 face，
        # 两处混在一起时，删掉继承那条照样能 grep 到（这就是假通过）。
        m_sf = re.search(r'(\w+)\s*=\s*\[\s*src\s+objectForKey\s*:\s*kCSFSRunFace\s*\]', fix)
        if not m_sf:
            fail('F2 没有从相邻文字 run（src）读字体 —— 空白 run 拿不到 face')
        elif not re.search(r'setObject\s*:\s*%s\s+forKey\s*:\s*kCSFSRunFace'
                           % re.escape(m_sf.group(1)), fix):
            fail('F2 读到了邻居字体却没有写进 run（sf 未被 setObject）—— '
                 'Word 仍会用 docDefaults 的 Calibri 渲染空格')
        else:
            ok('F2 会把相邻文字 run 的字体继承给空白 run（%s → kCSFSRunFace）'
               % m_sf.group(1))

        # F3：绝不允许留空
        m_df = re.search(r'NSString\s*\*\s*(\w+)\s*=\s*([^;]+);', fix)
        df_ok = False
        dfname = None
        for mm in re.finditer(r'NSString\s*\*\s*(\w+)\s*=\s*([^;]+);', fix):
            expr = mm.group(2)
            if 'gCSFSBodyFace' in expr and 'SimSun' in expr:
                dfname = mm.group(1)
                if re.search(r'setObject\s*:\s*%s\s+forKey\s*:\s*kCSFSRunFace'
                             % re.escape(dfname), fix):
                    df_ok = True
                break
        if df_ok:
            ok('F3 继承不到时写入兜底字体（gCSFSBodyFace → SimSun），不会留空')
        elif dfname is None:
            fail('F3 继承不到时没有兜底字体 —— 整段都是填空线时 face 仍为空，'
                 '空格掉回 Calibri，长度腰斩')
        else:
            fail('F3 兜底字体算出来了（%s）却没有写进 run —— 等于没兜底' % dfname)

        # F4：兜底字体来自全文统计
        if re.search(r'gCSFSBodyFace\s*=\s*\[', fix):
            ok('F4 兜底字体取自全文第一个有字体的 run（gCSFSBodyFace）')
        else:
            fail('F4 没有记录 gCSFSBodyFace —— 每段各自猜一个字体，'
                 '跨段落会不一致')

        # F5：重置清零
        rst = extract_func(src, 'CSFSResetOptionStateImpl')
        if rst is None:
            fail('F5 找不到 CSFSResetOptionStateImpl')
        else:
            miss = [v for v in ['gCSFSBodyFace', 'gCSFSUnderSpaceRuns']
                    if not assigned_vars(rst, v)]
            if miss:
                fail('F5 批次重置没清 %s —— 第二次导出会混进上一次的字体/计数'
                     % ', '.join(miss))
            else:
                ok('F5 gCSFSBodyFace / gCSFSUnderSpaceRuns 都在批次重置里被清')

    # ══════════════════════════════════════════════════════════════
    # 三、下划线属性（U）
    # ══════════════════════════════════════════════════════════════
    # U1：underline 不许走 CSFSBoolValue
    bad_under = re.search(
        r'CSFSBoolValue\s*\(\s*CSFSValue\s*\(\s*attr\s*,\s*@"underline"\s*\)\s*\)', src)
    if bad_under:
        fail('U1 underline 仍用 CSFSBoolValue 判断 —— 它只认 1/true/yes，'
             '"single"/"thick"/"double" 会被判成「没有下划线」，'
             '这正是「本来有下划线的空格只剩空格」')
    elif not re.search(r'CSFSUnderlineValue\s*\(\s*CSFSValue\s*\(\s*attr\s*,\s*@"underline"\s*\)\s*\)', src):
        fail('U1 找不到用 CSFSUnderlineValue 读取 underline 的写法')
    else:
        ok('U1 underline 走专用判据 CSFSUnderlineValue')

    uv = extract_func(src, 'CSFSUnderlineValue')
    if uv is None:
        fail('U2 找不到 CSFSUnderlineValue')
    else:
        # U2：必须接受非 0/1 的肯定写法
        #     判据按行为：把 "single" 代进去是否返回 YES，
        #     等价于「否定词黑名单 + 其余一律 YES」的结构。
        has_blacklist = bool(re.search(r'isEqualToString\s*:\s*@"none"', uv))
        has_whitelist_only = bool(re.search(
            r'isEqualToString\s*:\s*@"single"', uv)) and not has_blacklist
        if has_blacklist:
            ok('U2 用「否定词黑名单 + 其余视为有下划线」的判据（"single" 能识别）')
        elif has_whitelist_only:
            fail('U2 用白名单列举下划线写法 —— 漏掉 "thick"/"double" 就又丢线了；'
                 '应改用否定词黑名单')
        else:
            fail('U2 CSFSUnderlineValue 既不认黑名单也不认 "single"，'
                 '非 0/1 的写法仍然会被判成没有下划线')

        # U3：否定写法必须能识别
        neg = ['"0"', '"false"', '"no"', '"none"']
        missn = [x for x in neg if x not in uv]
        if missn:
            fail('U3 没有把 %s 判为「无下划线」—— '
                 '这些取值会被当成「有下划线」，所有带 font_attribute 的 run '
                 '都会被画上下划线' % ', '.join(missn)
                 if len(missn) < 4 else
                 'U3 CSFSUnderlineValue 没有任何否定判据 —— '
                 '所有带 font_attribute 的 run 都会被画上下划线')
        else:
            ok('U3 明确的否定写法（0/false/no/none）被判为无下划线')

    # U4/U5：NBSP 替换
    render = extract_func(src, 'CSFSRenderPara')
    if render is None:
        fail('U4 找不到 CSFSRenderPara')
    else:
        has_nbsp = ('00A0' in render)
        # 必须真的把构造结果赋回 emitText —— 只出现 00A0 字面量不算数
        # （构造了却没用上，写出去的还是普通空格，行尾照样被裁）。
        #
        # ⚠ 这里必须绑定「构造 NBSP 的那个变量」，不能只找
        #   `emitText = <任意变量>;`。函数开头有一句 `emitText = text;`，
        #   任何实现都能满足那个正则 —— 删掉 `emitText = nb;` 照样全绿。
        #   这是 rev_check_v33 的 R16 注入抓出来的假通过。
        #
        #   做法：先定位 00A0，再只在这之后的片段里找
        #   `emitText = <var>;`，最后确认 <var> 是由 NSMutableString 构造的
        #   （不能只取第一个 NSMutableString 声明 —— 那往往是 out / rPr）。
        m_back = None
        if has_nbsp:
            tail = render[render.find('00A0'):]
            for mm in re.finditer(r'emitText\s*=\s*(\w+)\s*;', tail):
                v = mm.group(1)
                if re.search(r'NSMutableString\s*\*\s*%s\s*=' % re.escape(v), render):
                    m_back = mm
                    break
        if not has_nbsp:
            fail('U4 没有把带下划线的空白换成不换行空格 U+00A0 —— '
                 'Word 会裁掉行尾空格的下划线，填空线落在行尾就一条都不剩')
        elif not m_back:
            fail('U4 找不到「把 NBSP 结果赋回 emitText」的语句 —— '
                 '构造了却没写出去，等于没改')
        else:
            ok('U4 带下划线的空白输出为 U+00A0（行尾也不会被裁）')

            # U5：必须被 underline 守卫
            i_nbsp = render.find('00A0')
            head = render[:i_nbsp]
            # 往回找最近的 if 条件
            guards = re.findall(r'if\s*\(([^{};]+)\)\s*\{', head)
            near = guards[-1] if guards else ''
            if 'emitUnder' in near or 'Underline' in near or 'emitIsSpace' in near:
                if 'emitUnder' in near or 'Underline' in near:
                    ok('U5 NBSP 替换被「带下划线」守卫（普通空格不受影响）')
                else:
                    fail('U5 NBSP 替换只被「纯空白」守卫、没被「带下划线」守卫 —— '
                         '所有词间空格都会变成不断行的 NBSP，整行排不下时会溢出')
            else:
                fail('U5 NBSP 替换没有任何守卫（条件：%s）—— '
                     '所有空格都会变成 NBSP，Word 失去断行点' % ' '.join(near.split())[:80])

    # ══════════════════════════════════════════════════════════════
    # 四、填空线判据（T）
    # ══════════════════════════════════════════════════════════════
    if fix is None:
        fail('T1 找不到 CSFSFixSpaceRuns，无法检查填空线判据')
    else:
        m_add = re.search(r'if\s*\(\s*!\s*hadUnder\s*&&\s*([^{}]+?)\)\s*\{', fix)
        if not m_add:
            fail('T1 找不到「补下划线」的条件分支')
        else:
            cond = m_add.group(1)
            if re.search(r'\bem\b\s*>=', cond):
                ok('T1 补下划线的条件是「宽度/字号 ≥ 阈值」（版面实测，不靠个数）')
            elif re.search(r'\bt\s*\.\s*length\s*>=', cond) or \
                 re.search(r'\.length\s*>=', cond):
                fail('T1 补下划线用「空格个数」判定 —— 个数是 OCR 给的，'
                     '可能被截断；宽度才是版面真实值')
            else:
                fail('T1 补下划线的条件既不是宽度也不是个数（实际：%s）'
                     % ' '.join(cond.split())[:80])

            # T2：阈值不能太小
            m_th = re.search(r'em\s*>=\s*([0-9.]+)', cond)
            if m_th:
                th = float(m_th.group(1))
                if th < 1.5:
                    fail('T2 填空线阈值 em>=%.2f 太小 —— '
                         '两三个词间空格就会被画成下划线' % th)
                else:
                    ok('T2 填空线阈值 em>=%.2f（词间距不会被误画成线）' % th)
            else:
                fail('T2 找不到 em 阈值常量')

    # ══════════════════════════════════════════════════════════════
    # 五、统计日志时机（S）
    # ══════════════════════════════════════════════════════════════
    i_written = raw.find('v21 docx written=')
    i_space = raw.find('space stats:')
    if i_space < 0:
        fail('S1 没有「space stats」汇总日志 —— '
             '下一轮无法从日志判断空格展开到底走了几次')
    elif i_written < 0:
        fail('S1 找不到 docx 写入日志，无法判断统计时机')
    elif i_space < i_written:
        fail('S1 「space stats」打在 docx 写入**之前** —— '
             '渲染还没发生，计数必然是 0，日志会自相矛盾'
             '（v32 就是这样：spaceExpanded=0 而明细又打出来了）')
    else:
        ok('S1 「space stats」打在渲染完成之后，计数可信')

    print()
    print('=' * 66)
    if FAIL:
        print('check_v33 失败：OK %d / FAIL %d' % (OK, FAIL))
        for m in FAILED:
            print('  - %s' % m.split(' —— ')[0])
        return 1
    print('check_v33 通过：OK %d / FAIL 0' % OK)
    return 0


if __name__ == '__main__':
    sys.exit(main())
