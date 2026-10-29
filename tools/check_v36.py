#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_v36 —— 缩进：删掉「两字符兜底」，改为「顶格才一行」时清缩进

v35 装上后用户回传：
    「出租方已经是一行了，但是后边承租方，以及中介方，经纪人都不对」

日志 + Word 转 PDF 逐行量 bbox 的实测（页宽 451.3pt，右边距 523.3）：

    段落     缩进  内容宽   可用宽   结果
    p1 出租方  21pt  413.7   430.3   一行 ✓
    p2 承租方  21pt  442.0   430.3   折掉「方）」
    p3 中介方  21pt  451.5   430.3   折掉「人：」

而 App 预览截图里这三段**全是顶格的**（「出租方：」与下方
「根据《中华人民共和国民法典》」左边缘对齐）。

把这三段的 <w:ind> 删掉、其余一字不动，重新转 PDF：

    p1 485.7 / p2 516.4 / p3 516.8 —— 三段全部一行，都在 523.3 内

所以折行的原因是 21pt 缩进，不是空白长。这 21pt 从哪来？

v30 在「indent_first_line 为 0 或缺失」时兜底写了 2 字符缩进
（paraPt * 40 twips = 21pt），日志里 `fallback-2chars` 恰好出现 3 次。
但反汇编原文是 `cbz x0 → 跳过`：**fl 为 0 就该顶格，不是数据缺失**。
兜底把「明确的顶格」当成了「没数据」，给每一段都补了 21pt。
这是本项目第三次栽在兜底上（前两次：字体兜底、indent 兜底）。

v36 两处改动：

  ① 删掉兜底。fl==0 → 顶格，一个 twip 都不写。
  ② 保留一个兜底式的**救场**，但方向相反：只有当「加了缩进会折行、
     去掉缩进正好一行」时才清缩进。判据是宽度预算算出来的，
     不是拍脑袋给的默认值。

同时修掉 v35 一个「算了不用」形态的缺陷：
    日志报 `v35 tailfit: ratio=0.836`，XML 里那个 run 仍是 22 个空格。
    因为压空白只改了 kCSFSRunSpaceW（只参与估算），而写 XML 走的是
    text.length —— **估算是按压过的算、实际按没压的排**，两头都不对。

【一】删兜底（I）
  I1 源码里不再有 fallback-2chars
  I2 不再有 paraPt * 40.0 这种「两字符」算式
  I3 fl<=0 时 indFirst 保持 0，缩进语句被 indFirst > 0 守卫

【二】位标志（F）
  F1 kCSFSFitLeft 存在（jc → left）
  F2 kCSFSFitNoIndent 存在（清首行缩进）
  F3 CSFSFitParaWidth 返回 int（一个 BOOL 装不下两个结论）
  F4 CSFSFixSpaceRuns 把 fitFlags 原样返回

【三】清缩进的四条判据（D）
  D1 有缩进才谈得上去掉（indentPt > 1.0）
  D2 加了缩进确实装不下（total > avail）
  D3 顶格确实装得下（total <= lineW * 1.06，留估算容差）
  D4 不是极短段落（total > avail * 0.6）
  D5 清缩进后直接返回 —— 不能再落到「压空白」分支
  D6 *outDropIndent 与位标志同时置位（调用方才知道）

【四】空白必须真改（S）
  S1 CSFSScaleSpaceRuns 同时改 kCSFSRunSpaceW 与 kCSFSRunText
  S2 字符数按 ratio 折算且至少留 1 个
  S3 段尾自适应走 CSFSScaleSpaceRuns(runs, YES, ...)
  S4 挤进一行走 CSFSScaleSpaceRuns(runs, NO, ...)
  S5 CSFSFitParaWidth 里不再直接写 kCSFSRunSpaceW（防回退）

【五】渲染端落笔（R）
  R1 NoIndent → indFirst = 0，且发生在写 pPr 之前
  R2 清缩进后 indFirst==0，走「留 1pt 右边距」的临界垫
  R3 左对齐结论绑 paraFitFlags（不是无差别覆盖 jc）
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


def norm(s):
    """压掉空白，便于跨行比较表达式结构。"""
    return re.sub(r'\s+', ' ', s)


def main():
    if len(sys.argv) < 2:
        print('用法: check_v36.py <file.m>')
        return 2
    raw = open(sys.argv[1], encoding='utf-8').read()
    src = strip_comments(raw)

    print('=' * 66)
    print('check_v36  CamScannerSaveToFiles.m')
    print('=' * 66)

    fit = extract_func(src, 'CSFSFitParaWidth')
    scl = extract_func(src, 'CSFSScaleSpaceRuns')
    fix = extract_func(src, 'CSFSFixSpaceRuns')
    rnd = extract_func(src, 'CSFSRenderPara')

    # ══════════════════════════════════════════════════════════════
    # 一、删兜底（I）
    # ══════════════════════════════════════════════════════════════
    # I1：兜底日志串必须彻底消失。留着它就是留着兜底。
    if 'fallback-2chars' in src:
        fail('I1 源码里还有 fallback-2chars —— 两字符兜底没删干净，'
             '每段都会被补 21pt 缩进')
    else:
        ok('I1 已删掉「fl 为 0 → 兜底两字符缩进」')

    # I2：兜底的算式 paraPt * 40.0（2 字符 × 20 twips/pt）
    m_i2 = re.search(r'indFirst\s*=\s*\(long\)\(paraPt\s*\*\s*40\.0', norm(src))
    if m_i2:
        fail('I2 还留着 paraPt * 40.0 的两字符算式 —— 顶格会被改写')
    else:
        ok('I2 不再有「两字符 × 字号」的缩进算式')

    # I3：缩进落笔必须被 indFirst > 0 守卫（fl<=0 就不写 firstLine）
    if rnd is None:
        fail('I3 找不到 CSFSRenderPara')
    else:
        guard = re.search(
            r'else\s+if\s*\(\s*indFirst\s*>\s*0\s*\)\s*\{[^{}]*?'
            r'w:firstLineChars=', rnd, re.S)
        if guard:
            ok('I3 首行缩进被 indFirst > 0 守卫（fl 为 0 就顶格）')
        elif 'w:firstLineChars=' in rnd:
            fail('I3 写了 firstLineChars 但没被 indFirst > 0 守卫 —— '
                 '顶格段落照样会被加缩进')
        else:
            fail('I3 找不到首行缩进的落笔点')

    # ══════════════════════════════════════════════════════════════
    # 二、位标志（F）
    # ══════════════════════════════════════════════════════════════
    for tag, name, desc in (
            ('F1', 'kCSFSFitLeft', 'jc → left'),
            ('F2', 'kCSFSFitNoIndent', '清首行缩进')):
        if re.search(r'#define\s+%s\s+\d' % name, src):
            ok('%s %s 位标志存在（%s）' % (tag, name, desc))
        else:
            fail('%s 缺少 #define %s —— 宽度预算的结论没地方放' % (tag, name))

    # F3：返回类型必须是 int（BOOL 只能装一个结论）
    m_f3 = re.search(r'static\s+int\s+CSFSFitParaWidth\s*\(', src)
    if m_f3:
        ok('F3 CSFSFitParaWidth 返回 int（能同时表达左对齐 + 清缩进）')
    elif re.search(r'static\s+BOOL\s+CSFSFitParaWidth\s*\(', src):
        fail('F3 CSFSFitParaWidth 还返回 BOOL —— 两个结论只能二选一，'
             '清缩进和左对齐没法同时生效')
    else:
        fail('F3 找不到 CSFSFitParaWidth 定义')

    # F4：调用方必须把 flags 原样返回（不是丢掉重算）
    if fix is None:
        fail('F4 找不到 CSFSFixSpaceRuns')
    else:
        nfix = norm(fix)
        if re.search(r'int\s+fitFlags\s*=\s*CSFSFitParaWidth\s*\(', nfix) and \
           re.search(r'return\s+fitFlags\s*;', nfix):
            ok('F4 CSFSFixSpaceRuns 把 fitFlags 原样返回给渲染端')
        else:
            fail('F4 CSFSFixSpaceRuns 没把 CSFSFitParaWidth 的 flags 返回 —— '
                 '渲染端永远收不到「清缩进」这个结论')

    # ══════════════════════════════════════════════════════════════
    # 三、清缩进的四条判据（D）
    # ══════════════════════════════════════════════════════════════
    if fit is None:
        fail('D 找不到 CSFSFitParaWidth，后面 6 条无法检查')
        nfit = ''
    else:
        nfit = norm(fit)

        # 定位 NoIndent 那个 if 的条件
        m_d = re.search(r'if\s*\((indentPt\s*>\s*1\.0.*?)\)\s*\{', nfit, re.S)
        cond = m_d.group(1) if m_d else ''

        # D1 有缩进才谈得上去掉
        if re.search(r'indentPt\s*>\s*1\.0', cond):
            ok('D1 有缩进才清（indentPt > 1.0）')
        else:
            fail('D1 清缩进没有「本来有缩进」的前提 —— 顶格段落会被无端处理')

        # D2 加了缩进装不下
        #
        # 边界必须卡死：同一个条件串里还有 `total > avail * 0.6`（D4 的
        # 极短段落下限），裸写 `total > avail` 会被它满足 —— 那样把
        # D2 整条删掉、只留 D4，检查器照样绿。实测这条假绿真实存在过。
        #
        # 注意 `\s*` 能回溯：写成 `avail\s*(?![*\w])` 时，`avail * 0.6`
        # 会让 `\s*` 匹配 0 个空格、先行看到空格而通过 —— 必须把空白
        # 放进先行断言里一起判。
        if re.search(r'\btotal\s*>\s*avail(?!\s*[\*\w])', cond):
            ok('D2 前提是「加了缩进确实装不下」（total > avail，'
               '不把 * 0.6 那条误当成本条）')
        else:
            fail('D2 没有 total > avail 判断 —— 装得下的段落也会被清缩进')

        # D3 顶格装得下（含估算偏差容差）
        #
        # 这条**不跟着源码的具体数字走**，而是要求系数落在
        # [1.10, 1.32] 区间内，两头都有实际依据：
        #
        #   下界 1.10：v35 日志与 Word 实测对照，估算系统性偏大 11.2%
        #     （p1 估算 459.9pt / 真实 413.7pt）。系数小于这个值，
        #     「顶格装得下」的段落会被判成装不下、分支一次都不触发 ——
        #     与 v35 squeeze 一次没跑是同一个坑。
        #   上界 1.32：长段落估算 900~4000pt，而 lineW*1.32 ≈ 596pt，
        #     再往上放宽就可能把"本来要折好几行"的段落也吞进来。
        #
        # 为什么不直接断言 == 1.18：那样这条判据就只是把当前实现抄一遍，
        # 换个等价的 1.17 就误报，而改成 1.00 这种真错误反倒没人管了。
        m_d3 = re.search(r'\btotal\s*<=\s*lineW\s*\*\s*([0-9]+(?:\.[0-9]+)?)', cond)
        if not m_d3:
            fail('D3 没有「顶格装得下」的判断 —— 清掉缩进也还是折行，白改')
        else:
            k = float(m_d3.group(1))
            if 1.10 <= k <= 1.32:
                ok('D3 要求「顶格后装得下」，容差 %.2f（容得住实测 11.2%% '
                   '的估算偏大，又不会吞掉长段落）' % k)
            elif k < 1.10:
                fail('D3 容差只有 %.2f —— 估算系统性偏大 11.2%%，'
                     '这条分支在真机上一次都不会触发（v35 squeeze 就是这样'
                     '一次没跑的）' % k)
            else:
                fail('D3 容差 %.2f 过大 —— lineW*%.2f ≈ %.0fpt，'
                     '会把「本来要折好几行」的段落也判成"顶格就好"'
                     % (k, k, 451.3 * k))

        # D4 排除极短段落
        if re.search(r'\btotal\s*>\s*avail\s*\*\s*0\.6', cond):
            ok('D4 排除极短段落（total > avail * 0.6）')
        else:
            fail('D4 没有极短段落下限 —— 只有几个字的段落也会被改')

        # D5 清缩进后直接返回，不再落到压空白
        body_after = nfit[nfit.find(m_d.group(0)):] if m_d else ''
        if re.search(r'flags\s*\|=\s*kCSFSFitNoIndent', body_after) and \
           re.search(r'return\s+flags\s*;', body_after):
            # return 必须出现在第一个 tailSum 判断之前
            i_ret = body_after.find('return flags;')
            i_tail = body_after.find('tailSum > 0.0')
            if i_tail < 0 or i_ret < i_tail:
                ok('D5 清缩进后立即返回 —— 不会再落到压空白分支'
                   '（估算偏大 11%，压了会误伤下划线长度）')
            else:
                fail('D5 清缩进后继续往下走压空白 —— 估算偏大 11%，'
                     '会把用户要的下划线压短')
        else:
            fail('D5 清缩进分支没有直接 return flags')

        # D6 outDropIndent 与位标志同时置位
        if re.search(r'outDropIndent\s*\)\s*\*outDropIndent\s*=\s*YES', nfit) and \
           re.search(r'flags\s*\|=\s*kCSFSFitNoIndent', nfit):
            ok('D6 *outDropIndent 与 kCSFSFitNoIndent 同时置位')
        else:
            fail('D6 outDropIndent 没和位标志一起置位 —— 调用方拿不到结论')

    # ══════════════════════════════════════════════════════════════
    # 四、空白必须真改（S）—— v35 的「算了不用」形态
    # ══════════════════════════════════════════════════════════════
    if scl is None:
        fail('S1 找不到 CSFSScaleSpaceRuns —— 压空白只改估算不改输出')
        nscl = ''
    else:
        nscl = norm(scl)
        has_w = 'forKey:kCSFSRunSpaceW' in nscl
        has_t = 'forKey:kCSFSRunText' in nscl
        if has_w and has_t:
            ok('S1 CSFSScaleSpaceRuns 同时写回 kCSFSRunSpaceW 与 kCSFSRunText'
               '（估算与输出一致）')
        elif has_w:
            fail('S1 只写回 kCSFSRunSpaceW —— 那是宽度的估算值，'
                 '不进 XML；实际排出来一个空格都没少，v35 就栽在这')
        else:
            fail('S1 CSFSScaleSpaceRuns 没有写回任何宽度字段')

        if re.search(r'nn\s*=\s*\(NSUInteger\)\(\(double\)t\.length\s*\*\s*ratio', nscl) \
           and re.search(r'if\s*\(nn\s*<\s*1\)\s*nn\s*=\s*1', nscl):
            ok('S2 字符数按 ratio 折算，且至少保留 1 个（不会压成空串）')
        else:
            fail('S2 字符数没按 ratio 折算，或缺「至少 1 个」的下限')

    # S3 / S4：两条分支都走 CSFSScaleSpaceRuns
    if re.search(r'CSFSScaleSpaceRuns\s*\(\s*runs\s*,\s*YES\s*,', nfit):
        ok('S3 段尾留白自适应走 CSFSScaleSpaceRuns(runs, YES, ...)')
    else:
        fail('S3 段尾自适应没走 CSFSScaleSpaceRuns —— 只改了估算值')

    if re.search(r'CSFSScaleSpaceRuns\s*\(\s*runs\s*,\s*NO\s*,', nfit):
        ok('S4 「差 5% 挤进一行」走 CSFSScaleSpaceRuns(runs, NO, ...)')
    else:
        fail('S4 squeeze 分支没走 CSFSScaleSpaceRuns —— 只改了估算值')

    # S5：CSFSFitParaWidth 里不能再有裸的 setObject:...kCSFSRunSpaceW
    if fit is not None:
        bare = len(re.findall(r'setObject:\[NSNumber numberWithDouble:.*?\]\s*'
                              r'forKey:kCSFSRunSpaceW\]', norm(fit)))
        if bare:
            fail('S5 CSFSFitParaWidth 里还有 %d 处直接写 kCSFSRunSpaceW —— '
                 '这种写法只改估算，必须统一走 CSFSScaleSpaceRuns' % bare)
        else:
            ok('S5 CSFSFitParaWidth 不再直接写宽度字段（统一走 ScaleSpaceRuns）')

    # ══════════════════════════════════════════════════════════════
    # 五、渲染端落笔（R）
    # ══════════════════════════════════════════════════════════════
    if rnd is None:
        fail('R 找不到 CSFSRenderPara，后 3 条无法检查')
    else:
        nrnd = norm(rnd)

        # R1 NoIndent → indFirst = 0，且必须在写 pPr 之前
        # 块内有嵌套的 if (indFirst > 0) { LOG }，不能用 [^{}] 卡，
        # 改成有界跨行匹配，避免把「块外的 indFirst = 0」算进来。
        m_r1 = re.search(r'if\s*\(\s*paraFitFlags\s*&\s*kCSFSFitNoIndent\s*\)\s*\{'
                         r'[\s\S]{0,400}?\bindFirst\s*=\s*0\s*;', nrnd)
        if not m_r1:
            fail('R1 渲染端没有消费 kCSFSFitNoIndent —— 宽度预算说「该清缩进」，'
                 '结果缩进照样写出去')
        else:
            i_call = nrnd.find('CSFSFixSpaceRuns(')
            i_ppr = nrnd.find('[out appendFormat:@"<w:pPr>')
            if i_call >= 0 and i_ppr >= 0 and i_call < i_ppr:
                ok('R1 NoIndent → indFirst = 0，且结论来自 pPr 落笔之前')
            else:
                fail('R1 清缩进的动作排在 pPr 输出之后 —— 改的是内存，'
                     'pPr 已经生成好了')

        # R2 清缩进后走「1pt 临界垫」
        if re.search(r'else\s+if\s*\(\s*paraFitFlags\s*&\s*kCSFSFitNoIndent\s*\)',
                     nrnd) and 'w:ind w:right=\\"-20\\"' in nrnd:
            ok('R2 indFirst 被清成 0 后走「-20tw 右边距」临界垫'
               '（顶格刚好一行的段落留 1pt 余量）')
        else:
            fail('R2 没有临界垫 —— 顶格后差 0.2pt 的段落仍会折掉最后一个字')

        # R3 左对齐必须绑 paraFitFlags
        if re.search(r'paraFitFlags\s*&\s*kCSFSFitLeft', nrnd) and \
           re.search(r'paraFitFlags\s*&\s*kCSFSFitLeft\s*\)\s*&&[^{}]*?'
                     r'isEqualToString\s*:\s*@"both"', nrnd, re.S):
            ok('R3 左对齐只在 paraFitFlags & kCSFSFitLeft 且原 jc 是 both 时生效')
        else:
            fail('R3 左对齐没有绑 paraFitFlags / 没有限定 both —— '
                 '标题的 center 会被无差别覆盖')

    print('-' * 66)
    print('check_v36 通过：OK %d / FAIL %d' % (OK, FAIL))
    if FAIL:
        for m in FAILED:
            print('  - %s' % m)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
