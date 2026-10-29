#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_v34 —— 空白 run 的字体宽度、下划线证据、宽度精度

背景（全部来自真机导出的 document.xml，不是推测）：

用户 v33 反馈：
    「空格处本来不应该有下划线的地方，也出现了下划线，有的空格下划线还不够长」

把 v32 与 v33 导出的同一份文档逐条对齐，两个数字就说明了一切：

    版本   空白 run   带下划线
    v32      47          21
    v33      47          26

多出来的 5 条全部落在合同末尾签字区：
    prev='董瀚霖'      next='乙方：'       len=12
    prev='地址：'      next='地址：'       len=26
    prev='地址：'      next='电话：'       len=25
    prev='9845254499'  next='电话：'       len=5
    prev='5586699161'  next='签订日期：'   len=4
那是把「乙方：」「电话：」推到行右侧的排版留白，宽度必然超过 2em，
被 v33 的 `em >= 2.0 就补下划线` 判成了填空线。

而长度问题在同一份 XML 里也找到了铁证：
    47 个空白 run 里 43 个写着 w:ascii="Calibri"
空格是 U+0020（ASCII），Word 严格按 w:ascii 取字形：
    Calibri 0.226em × 10.5pt = 2.37pt
    宋体    0.500em × 10.5pt = 5.25pt      差 2.2 倍
按 0.5em 算出 11 个空格，Word 里只占 26pt，而 slice.width 是 56pt。

本检查器守的就是这两条修复，外加「余量用字符间距补齐」和
「<w:spacing> 的法定位置」。

【一】字体必须撑得住 0.5em（V）
  V1 CSFSIsCJKFace 存在且被用来判空白 run 的字体
  V2 判据是「能不能撑 0.5em」，不是「有没有字体」（必须能覆盖 Calibri）
  V3 空白 run 的 face 是**覆盖**，不是「空才继承」
  V4 CSFSIsCJKFace 认得出中文名（CJK 码位 + 拼音词干两类都要）
  V5 一个中文字体都找不到时兜底「宋体」

【二】下划线只认数据（H）
  H1 不再有 em 阈值补线
  H2 整个补齐函数不写 kCSFSRunUnderline
  H3 em 不再参与任何格式决策

【三】宽度精度（E）
  E1 展开函数有 outSpTw 出参
  E2 个数用 floor，不用四舍五入
  E3 余量 remPt 真的参与 spTw 计算
  E4 行宽上限用 kCSFSContentTwips

【四】spacing 的输出位置（S）
  S1 <w:spacing> 排在 <w:sz> 之前（CT_RPr sequence）
  S2 只在空白 run 上出现（词间空格不能被拉开）
  S3 spacing 值由 spTw 派生，不是常量

【五】诊断（D）
  D1 明细日志同时有 fs / rem / spTw
  D2 汇总日志报 bodyFace
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
        print('用法: check_v34.py <file.m>')
        return 2
    raw = open(sys.argv[1], encoding='utf-8').read()
    src = strip_comments(raw)

    print('=' * 66)
    print('check_v34  CamScannerSaveToFiles.m')
    print('=' * 66)

    fix = extract_func(src, 'CSFSFixSpaceRuns')
    exp = extract_func(src, 'CSFSExpandSpaceRun')
    rnd = extract_func(src, 'CSFSRenderPara')
    cjk = extract_func(src, 'CSFSIsCJKFace')

    # ══════════════════════════════════════════════════════════════
    # 一、字体必须撑得住 0.5em（V）
    # ══════════════════════════════════════════════════════════════
    if cjk is None:
        fail('V1 没有 CSFSIsCJKFace —— 无法判断字体撑不撑得住 0.5em，'
             '空白 run 会继续沿用 OCR 给的 Calibri（0.226em）')
    else:
        ok('V1 CSFSIsCJKFace 就位')

    if fix is None:
        fail('V2 找不到 CSFSFixSpaceRuns')
    elif re.search(r'if\s*\(\s*!\s*CSFSIsCJKFace\s*\(\s*face0\s*\)\s*\)', fix):
        ok('V2 判据是「这个字体撑不撑得住 0.5em」，Calibri 会被判出来')
    else:
        fail('V2 空白 run 的字体判据不是 CSFSIsCJKFace(face0) —— '
             '若退回「face 为空才处理」，Calibri 永远不进分支，长度照旧差 2.2 倍')

    # V3 必须是「覆盖」而不是「空才继承」。
    #     判据要绑到 setObject 这条数据流上：只 grep CSFSIsCJKFace 出现
    #     不够 —— 上面 V2 那个 if 也含它，删掉覆盖照样绿。
    if fix is not None:
        m_assign = re.search(
            r'setObject\s*:\s*(\w+)\s+forKey\s*:\s*kCSFSRunFace\s*\]', fix)
        if not m_assign:
            fail('V3 空白 run 的 face 没有被写回 —— 判出来是 Calibri 也没用')
        else:
            var = m_assign.group(1)
            # 这个变量必须来自 gCSFSBodyFace（统一出口），不是临时拼的
            if re.search(r'NSString\s*\*\s*%s\s*=\s*gCSFSBodyFace\s*;'
                         % re.escape(var), fix):
                ok('V3 空白 run 的字体被覆盖成统一出口 %s（不是「空才继承」）'
                   % var)
            else:
                fail('V3 写进 run 的 %s 不是从 gCSFSBodyFace 派生的 —— '
                     '各段可能各写一个字体' % var)

    # V4 认得出中文名
    if cjk is None:
        fail('V4 无法检查 CSFSIsCJKFace 的判据内容')
    else:
        has_cjk_range = bool(re.search(r'0x2E80|0x4E00|0x9FFF', cjk))
        has_pinyin = bool(re.search(r'@"song"|@"simsun"|@"sun"', cjk))
        if has_cjk_range and has_pinyin:
            ok('V4 CSFSIsCJKFace 两种写法都认（汉字码位 + 拼音名）')
        elif has_cjk_range:
            fail('V4 CSFSIsCJKFace 只认汉字码位 —— 英文名 "SimSun"/"Songti SC" '
                 '是绝大多数文档的实际取值，会被判成非中文字体')
        elif has_pinyin:
            fail('V4 CSFSIsCJKFace 只认拼音名 —— 中文名「宋体」「仿宋」会被判错')
        else:
            fail('V4 CSFSIsCJKFace 既没认码位也没认拼音名，恒返回 NO')

    # V5 兜底
    if fix is not None and re.search(r'gCSFSBodyFace\s*=\s*@"宋体"', fix):
        ok('V5 全文一个中文字体都没有时兜底「宋体」')
    else:
        fail('V5 没有「宋体」兜底 —— 全文都是 Calibri 时空白 run 仍按 0.226em '
             '渲染，下划线只有该有长度的 45%')

    # ══════════════════════════════════════════════════════════════
    # 二、下划线只认数据（H）
    # ══════════════════════════════════════════════════════════════
    if fix is None:
        fail('H1 找不到 CSFSFixSpaceRuns')
    else:
        if re.search(r'em\s*>=', fix):
            fail('H1 仍有 em 阈值判据 —— 签字区的排版留白（宽度远超 2em）'
                 '会被画上假下划线，这正是用户报的「不该有线的地方有线」')
        else:
            ok('H1 没有任何 em 阈值判据')

        # H2 整个函数不许写 underline。
        #    注意必须查 setObject 而不是查出现次数 ——
        #    只读 `objectForKey:kCSFSRunUnderline` 是合法的（统计用）。
        if re.search(r'setObject\s*:[^\]]*forKey\s*:\s*kCSFSRunUnderline', fix):
            fail('H2 补齐函数仍在写 kCSFSRunUnderline —— 下划线必须只来自 '
                 'slice 自带的 font_attribute.underline')
        else:
            ok('H2 补齐函数不写 kCSFSRunUnderline（只读不写，下划线全来自数据）')

    # H3 em 变量不许残留参与格式决策
    if fix is not None:
        if re.search(r'\bem\b\s*[<>=]', fix):
            fail('H3 仍用 em 做比较 —— 版面宽度只能说明「这儿空着」，'
                 '不能说明「这儿有根线」')
        else:
            ok('H3 em 不再参与任何格式判断')

    # ══════════════════════════════════════════════════════════════
    # 三、宽度精度（E）
    # ══════════════════════════════════════════════════════════════
    if exp is None:
        fail('E1 找不到 CSFSExpandSpaceRun')
    else:
        m_sig = re.search(r'CSFSExpandSpaceRun\s*\(([^)]*)\)', src)
        sig = m_sig.group(1) if m_sig else ''
        if re.search(r'double\s*\*\s*(\w+)', sig):
            ok('E1 展开函数通过出参返回字符间距（%s）'
               % re.search(r'double\s*\*\s*(\w+)', sig).group(1))
        else:
            fail('E1 展开函数没有 outSpTw 出参 —— 余量无处传递，'
                 '只能靠四舍五入，一半偏短')

        # E2 必须是 floor。四舍五入会让「偏短」和「偏长」各占一半，
        #    而用户反复报的就是偏短那一半。
        if re.search(r'floor\s*\(\s*pt\s*/\s*per\s*\)', exp):
            ok('E2 个数用 floor 向下取整（余量交给字符间距补）')
        elif re.search(r'pt\s*/\s*per\s*\+\s*0\.5', exp):
            fail('E2 个数仍在四舍五入 —— 舍去的那一半必然偏短，'
                 '而用户看到的正是偏短')
        else:
            fail('E2 找不到 pt/per 的取整写法')

        # E3 余量真要参与运算，不能算了不用
        m_rem = re.search(r'(\w+)\s*=\s*pt\s*-\s*\(double\)\s*n\s*\*\s*per', exp)
        if not m_rem:
            fail('E3 没有算余量（pt - n*per）—— 取整丢掉的宽度无人补偿')
        else:
            rv = m_rem.group(1)
            if re.search(r'spTw\s*=\s*\([^;]*%s[^;]*\)\s*/\s*\(double\)\s*n'
                         % re.escape(rv), exp) or \
               re.search(r'spTw\s*=[^;]*%s[^;]*/\s*\(double\)\s*n'
                         % re.escape(rv), exp):
                ok('E3 余量 %s 摊到每个字符上参与 spTw 计算' % rv)
            else:
                fail('E3 余量 %s 算出来了但没有摊进 spTw —— 等于没补' % rv)

        # E4 行宽上限
        if re.search(r'kCSFSContentTwips\s*/\s*20', exp):
            ok('E4 展开宽度受内容区上限约束（不会把整段挤到下一行）')
        else:
            fail('E4 没有行宽上限 —— 整段空白（如 18pt×56 空格 = 504pt > 451pt）'
                 '会把段落撑爆')

    # ══════════════════════════════════════════════════════════════
    # 四、spacing 的输出位置（S）
    # ══════════════════════════════════════════════════════════════
    if rnd is None:
        fail('S1 找不到 CSFSRenderPara')
    else:
        i_sp = rnd.find('w:spacing w:val=')
        i_sz = rnd.find('w:sz w:val=')
        if i_sp < 0:
            fail('S1 没有输出 <w:spacing> —— 余量补不进去，个数只能靠取整')
        elif i_sz < 0:
            fail('S1 找不到 <w:sz> 输出，无法核对顺序')
        elif i_sp > i_sz:
            fail('S1 <w:spacing> 排在 <w:sz> 之后 —— CT_RPr 是 xsd:sequence，'
                 '顺序错 Word 静默忽略，余量白算')
        else:
            ok('S1 <w:spacing> 排在 <w:sz> 之前（符合 CT_RPr sequence）')

        # S2 只在空白 run 上出现：spTw 初值必须是 0，且只在空格分支里被赋值
        m_init = re.search(r'double\s+spTw\s*=\s*0\.0\s*;', rnd)
        m_assigns = re.findall(r'spTw\s*=(?!=)', rnd)
        if not m_init:
            fail('S2 spTw 没有初始化为 0 —— 非空白 run 也会带上字符间距，'
                 '整篇文字的字距被拉坏')
        elif len(m_assigns) != 1:
            fail('S2 spTw 有 %d 处赋值（应为 1，即出参那一处）—— '
                 '赋值点越多越容易让非空白 run 吃到间距' % len(m_assigns))
        else:
            ok('S2 spTw 只在展开空白时由出参赋值，非空白 run 恒为 0')

        # S3 值必须来自 spTw。
        #    允许中间过一手（spTw → spInt 取整），但这一手必须是
        #    `spInt = (long)(spTw + 0.5)` 这种纯派生，
        #    否则「写死常量」也能让 S3 绿。
        m_out = re.search(
            r'appendFormat\s*:\s*@"<w:spacing w:val=\\"%ld\\"/>"\s*,\s*(\w+)',
            rnd)
        if not m_out:
            fail('S3 找不到 <w:spacing> 的取值表达式')
        else:
            used = m_out.group(1)
            if used == 'spTw':
                ok('S3 <w:spacing> 的取值直接来自 spTw')
            elif re.search(r'\b%s\s*=\s*\(long\)\s*\(\s*spTw\s*\+' % re.escape(used),
                           rnd):
                ok('S3 <w:spacing> 由 spTw 取整而来（%s），余量真的写进去了'
                   % used)
            else:
                fail('S3 <w:spacing> 的取值 %s 不是由 spTw 派生 —— '
                     '写死常量等于没算' % used)

    # ══════════════════════════════════════════════════════════════
    # 五、诊断（D）
    # ══════════════════════════════════════════════════════════════
    if exp is None:
        fail('D1 找不到 CSFSExpandSpaceRun')
    else:
        # 日志是多行字面量拼接的，不能锚 `";` 结尾；
        # 取 CSFS_LOG 起始位置往后一段看关键字齐不齐。
        i_log = exp.find('CSFS_LOG(@"v34 space:')
        if i_log < 0:
            fail('D1 没有 v34 space 明细日志 —— 下一轮没法判断到底展开成几个')
        else:
            txt = exp[i_log:i_log + 500]
            miss = [k for k in ('fs=', 'rem=', 'spTw=') if k not in txt]
            if miss:
                fail('D1 明细日志缺 %s —— 无法判断「字数够了但宽度不够」'
                     % '/'.join(miss))
            else:
                ok('D1 明细日志含 fs / rem / spTw（能直接看出宽度是否对得上）')

    i_stats = src.find('v34 space stats:')
    if i_stats < 0:
        fail('D2 没有 v34 space stats 汇总日志')
    elif 'bodyFace' not in src[i_stats:i_stats + 400]:
        fail('D2 汇总日志不报 bodyFace —— 无法确认空白 run 最终用的字体')
    else:
        ok('D2 汇总日志报 bodyFace，可直接确认字体是不是中文字体')

    print()
    print('=' * 66)
    if FAIL:
        print('check_v34 失败：OK %d / FAIL %d' % (OK, FAIL))
        for m in FAILED:
            print('  - %s' % m.split(' —— ')[0])
        return 1
    print('check_v34 通过：OK %d / FAIL 0' % OK)
    return 0


if __name__ == '__main__':
    sys.exit(main())
