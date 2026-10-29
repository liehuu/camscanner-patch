#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_v32 —— CamScanner SaveToFiles 静态门禁（v32）

真机反馈（用户原话）：
  「1、去除手写选择了不生效，但是去除印章选择了是生效的。
   2、空格带下划线的长度应该不对，预览时看到虽然没有文字，
      但是下划线很长，你这个明显不够长，甚至有的本来有下划线的空格，
      你只有空格。」

两个问题分别对应两组判据。

════════════════════════════════════════════════════════════════════
【问题一】去除手写不生效 —— v31 把判据废掉了，v32 纠正回来
════════════════════════════════════════════════════════════════════
v31 三次导出的真机数字（决定性证据，三版严丝合缝）：

    v29  runs=123                          （空格被丢，手写保留）
    v30  runs=90  + handSkip=33 = 123
    v31  runs=170 = 123 + spaceSlices47，且 handSkip=0 / handKeep=33

170 = 90 + 47 + 33 —— 那 33 条 `stype=handwritten cat=0` 的 slice
**就是手写内容本身**。v30 删它们是对的，错的只是它「没勾也删」
（OR 合并跨批次残留，v31 已修）。v31 顺手把判据整个废掉，
于是手写开关彻底失效 —— 正是用户这次说的「去除手写选择了不生效」。

判据（都用**行为求值**，不用正则猜写法）：
  H1 勾了去除手写 + stype 含 handwrit + cat≠1 + 有识别文字 → 必须删
     （这条正是 v31 的反例：v31 在这里 KEEP，于是开关失效）
  H2 勾了去除手写 + cat=1（真手写图）→ 必须删
  H3 **没勾** + 同样场景 → 一个都不许删（v27 OR 残留的反例）
  H4 统计日志必须报 handHW，否则下一轮无法从日志判断判据有没有命中

════════════════════════════════════════════════════════════════════
【问题二】带下划线的空格「只有空格，下划线不够长」
════════════════════════════════════════════════════════════════════
空格 slice 的 text 就是一个 " "，但它在预览里可能是横跨十几个字符的
下划线（合同填空线）。v31 把这个 " " 原样写进 Word，Word 就只画一个
空格宽的下划线 —— 用户看到的就是「明显不够长」。

真正的宽度在 slice 自己的 `width` 字段里，而它此前**从来没被读过**。
v32 把它带进 run（kCSFSRunSpaceW），渲染时按
「宽度 pt ÷ 半角空格宽 pt」展开成足够多的空格。

判据：
  P1 CSFSParseSlice 必须读 slice 的 width 并写进 kCSFSRunSpaceW
  P2 这个赋值必须被「纯空白」守卫（不能给文字 run 也记宽度）
  P3 渲染端必须把**展开后**的文本交给 CSFSXMLEscape（不能还是 text）
  P4 展开必须有上限 clamp（width 单位若错会算出上万空格，把文档撑爆）
  P5 展开不许比原有空白更短（少就等于又把它弄短了）
  P6 width 不可用时必须原样返回（不能凭空空造空格）
  P7 计数 gCSFSSpaceExpandRuns 必须在批次重置里清零，且出现在统计日志

用法：python3 tools/check_v32.py src/CamScannerSaveToFiles.m
"""

import re
import sys

oks = []
fails = []


def ok(m):
    oks.append(m)


def fail(m):
    fails.append(m)


def strip_comments(s):
    """去掉 // 与 /* */ 注释，避免注释里的字样被当成代码。"""
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
    """按名字取一个函数体（花括号配平）。取不到返回 None。"""
    m = re.search(r'\n[ \t]*(?:static\s+)?[\w \t\*]+?\b%s\s*\(' % re.escape(name), src)
    if not m:
        return None
    b = src.find('{', m.end())
    if b < 0:
        return None
    depth = 0
    j = b
    while j < len(src):
        c = src[j]
        if c == '"':
            j += 1
            while j < len(src):
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
                return src[m.start():j + 1]
        j += 1
    return None


def block_of(src, cond_regex, start=0):
    """找 `if (<cond>) {` 并按花括号配平取出**整条 if 语句**（含条件）。

    返回 (整条 if 的文本, if 起点)。取整条而不是只取花括号，
    是因为外层条件（如 gCSFSHideWritten）本身也要参与行为求值 ——
    只取块内容会把「没勾时根本进不来」这个事实丢掉，
    于是 H3 会在完全没有被检验的情况下显示通过（假通过）。
    """
    m = re.search(cond_regex, src[start:])
    if not m:
        return None, -1
    p = start + m.start()
    b = src.find('{', start + m.end() - 1)
    if b < 0:
        return None, -1
    depth = 0
    j = b
    while j < len(src):
        c = src[j]
        if c == '"':
            j += 1
            while j < len(src):
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
                return src[p:j + 1], p
        j += 1
    return None, -1


def parse_bool_defs(body):
    """收集函数体里 `BOOL x = <expr>;` 这类定义，供条件求值时展开中间变量。

    为什么必须做：过滤块里真正决定删不删的是 `looksHW`，
    而它的定义在几行之外（`looksHW = (catSaysHW || stypeSaysHW)`）。
    不展开它，条件里就留着一个场景表里没有的名字 → eval 抛异常 → 判为不删，
    于是 H1 会误报「手写删不掉」。这种「因为求值器不完整而误判」，
    和判据本身写错一样有害。
    """
    defs = {}
    for m in re.finditer(r'\bBOOL\s+(\w+)\s*=\s*([^;]+);', body):
        defs[m.group(1)] = m.group(2).strip()
    return defs


def expand_defs(cond, defs, scen, depth=0):
    """把条件里的中间变量按定义递归展开（不碰场景表里已有的名字）。"""
    if depth > 8:
        return cond
    out = cond
    for name, expr in sorted(defs.items(), key=lambda kv: -len(kv[0])):
        if name in scen:
            continue        # 场景表直接给值，优先
        pat = r'\b%s\b' % re.escape(name)
        if re.search(pat, out):
            out = re.sub(pat, '(' + expr + ')', out)
    if out == cond:
        return out
    return expand_defs(out, defs, scen, depth + 1)


# ─────────────────────────────────────────────────────────────────
# 行为求值器：把 ObjC 条件翻成 Python 表达式，**真的算一遍**
# ─────────────────────────────────────────────────────────────────
#
# 为什么不用正则猜写法：本项目已四次栽在「判据绑代码长什么样」上
# （check_v27 绑变量名、check_v29 M5 黑名单、check_v31 的 S1 正则永不匹配
#  与 R4 前缀子串）。一个 continue 会不会执行，是行为问题，就该求值。

def cond_to_py(cond, scen):
    s = cond
    s = re.sub(r'\[[^\[\]]*containsString:\s*@"[^"]*"[^\]\[]*\]', 'HWMSG', s)
    s = re.sub(r'CSFSSliceText\s*\([^()]*\)\s*!=\s*nil', 'HASTEXT', s)
    s = re.sub(r'CSFSSliceText\s*\([^()]*\)\s*==\s*nil', 'not HASTEXT', s)
    s = re.sub(r'\b\w+\.length\s*[><]=?\s*\d+', 'TRUE', s)
    s = s.replace('&&', ' and ').replace('||', ' or ')
    s = re.sub(r'!(?!=)', ' not ', s)
    s = re.sub(r'\bYES\b', 'True', s)
    s = re.sub(r'\bNO\b', 'False', s)
    s = re.sub(r'\bnil\b', 'None', s)
    for k in sorted(scen, key=len, reverse=True):
        s = re.sub(r'\b%s\b' % re.escape(k), repr(scen[k]), s)
    return ' '.join(s.split())


def continues_with_chains(hbody):
    """把 hbody 里每个 continue 所属的 if 条件链（从外到内）取出来。

    返回 [(offset, [cond_outer, cond_inner, ...]), ...]
    """
    res = []
    stack = []          # [(brace_open_pos, cond_text)]
    pending = None      # 刚遇到的 if 条件，等它的 '{'
    i = 0
    n = len(hbody)
    while i < n:
        c = hbody[i]
        if c == '"':
            i += 1
            while i < n:
                if hbody[i] == '\\':
                    i += 2
                    continue
                if hbody[i] == '"':
                    break
                i += 1
            i += 1
            continue
        if hbody.startswith('if', i) and (i == 0 or not (hbody[i - 1].isalnum() or hbody[i - 1] == '_')):
            k = i + 2
            while k < n and hbody[k] in ' \t':
                k += 1
            if k < n and hbody[k] == '(':
                depth = 0
                m = k
                while m < n:
                    if hbody[m] == '(':
                        depth += 1
                    elif hbody[m] == ')':
                        depth -= 1
                        if depth == 0:
                            break
                    m += 1
                pending = hbody[k + 1:m]
                i = m + 1
                continue
        if c == '{':
            stack.append((i, pending))
            pending = None
        elif c == '}':
            if stack:
                stack.pop()
        elif hbody.startswith('continue', i):
            conds = [q for (_p, q) in stack if q]
            res.append((i, conds))
            i += len('continue')
            continue
        i += 1
    return res


def evaluates_true(conds, scen, defs=None):
    """整条条件链在该场景下是否全部为真（即 continue 会执行）。

    defs 传进来后，条件里的中间变量（looksHW 等）会按定义展开，
    这样「换个变量名」不会让判据失明，也不会因为求值器不完整而误报。
    """
    for cond in conds:
        c = expand_defs(cond, defs or {}, scen)
        try:
            py = cond_to_py(c, scen)
            if not bool(eval(py, {'__builtins__': {}}, {})):
                return False
        except Exception:
            # 翻不动就**不能**当作「不会删」—— 那会让 H1 误报、H3 假通过。
            # 显式抛给调用方，由调用方判红并要求人工核对。
            raise
    return True


# 四个场景。键名与源码里的变量一致，求值时逐字替换。
SC_HW_TEXT = {          # 勾了去除手写 + stype 说 handwrit + cat≠1 + 有文字
    'gCSFSHideWritten': True, 'stypeSaysHW': True, 'catSaysHW': False,
    'slCat': 0, 'hasTextHW': True, 'HWMSG': True, 'HASTEXT': True, 'TRUE': True,
}
SC_HW_IMG = {           # 勾了去除手写 + cat=1（真手写图）
    'gCSFSHideWritten': True, 'stypeSaysHW': False, 'catSaysHW': True,
    'slCat': 1, 'hasTextHW': False, 'HWMSG': False, 'HASTEXT': False, 'TRUE': True,
}
SC_OFF = {              # **没勾**：一个都不许删
    'gCSFSHideWritten': False, 'stypeSaysHW': True, 'catSaysHW': True,
    'slCat': 1, 'hasTextHW': True, 'HWMSG': True, 'HASTEXT': True, 'TRUE': True,
}


def main():
    if len(sys.argv) < 2:
        print('用法: check_v32.py <file.m>')
        return 2
    raw = open(sys.argv[1], encoding='utf-8').read()
    src = strip_comments(raw)

    # ══════════════════════════════════════════════════════════════
    # P 组：带下划线的空格，长度得跟预览一致
    # ══════════════════════════════════════════════════════════════
    parse = extract_func(src, 'CSFSParseSlice')
    if parse is None:
        fail('P1 找不到 CSFSParseSlice —— 判据无从下手')
    else:
        # P1：必须读 slice 的 width，并写进 run 的 kCSFSRunSpaceW 键
        has_read = re.search(r'CSFSValue\s*\(\s*sl\s*,\s*@"width"\s*\)', parse) is not None
        has_store = re.search(r'forKey:\s*kCSFSRunSpaceW\b', parse) is not None
        if not has_read:
            fail('P1 CSFSParseSlice 没有读 slice 的 width 字段 —— '
                 '空格 slice 的 text 只有一个 " "，真正的宽度只在这个字段里，'
                 '不读它就永远只能画一个空格宽的下划线（用户：「明显不够长」）')
        elif not has_store:
            fail('P1 读到了 width 但没写进 kCSFSRunSpaceW —— '
                 'run 里留不住这个值，渲染端拿不到，等于没读')
        else:
            ok('P1 CSFSParseSlice 读到 slice.width 并写入 kCSFSRunSpaceW')

        # P2：写这个键必须被「纯空白」守卫
        #
        # 注意要检查**所有**包住这一行的 if，而不是最近的那一个：
        # 真实代码是
        #     if (CSFSIsPureWhiteSpace(t)) {        ← 语义守卫
        #         double sw = ...;
        #         if (sw > 0.0) {                   ← 只是取值有效性检查
        #             [run setObject:... forKey:kCSFSRunSpaceW];
        # 只看最近一层会取到 `sw > 0.0`，然后误报「守卫不是纯空白判断」。
        m_store = re.search(r'forKey:\s*kCSFSRunSpaceW\b', parse)
        if m_store:
            guards = []
            for m in re.finditer(r'if\s*\(([^{};]+)\)\s*\{', parse[:m_store.start()]):
                blk, _ = block_of(parse, re.escape(m.group(0)), m.start())
                if blk and m.start() + len(blk) > m_store.start():
                    guards.append(m.group(1))
            if not guards:
                fail('P2 记 width 没有任何 if 守卫 —— 会给普通文字 run 也记宽度，'
                     '渲染时被硬撑开，字距全坏')
            elif not any('CSFSIsPureWhiteSpace' in g for g in guards):
                fail('P2 记 width 的守卫里没有「纯空白」判断（实际条件：%s）—— '
                     '普通文字 run 的宽度由字体自然决定，不该按 slice.width 展开'
                     % ' / '.join(' '.join(g.split())[:60] for g in guards))
            else:
                ok('P2 只有纯空白 run 才记 width（文字 run 不受影响）')

    # P3：渲染端必须把展开后的文本交给 XML 转义
    rend = extract_func(src, 'CSFSRenderPara')
    if rend is None:
        fail('P3 找不到 CSFSRenderPara —— 渲染端无从下手')
    else:
        if 'CSFSExpandSpaceRun' not in rend:
            fail('P3 渲染端没有调用 CSFSExpandSpaceRun —— '
                 'width 带进来了却没人用，下划线照样只有一个空格长')
        else:
            # 展开结果落在哪个变量上，就从源码里读出来 —— 不写死 emitText，
            # 免得改个变量名就误报。
            m_var = re.search(r'(\w+)\s*=\s*CSFSExpandSpaceRun\s*\(', rend)
            if not m_var:
                fail('P3 展开函数的返回值没有赋给任何变量 —— '
                     '算完了就丢了，<w:t> 里还是原始 text')
            else:
                var = m_var.group(1)
                used = re.search(r'CSFSXMLEscape\s*\(\s*%s\s*\)' % re.escape(var), rend)
                raw_used = re.search(r'CSFSXMLEscape\s*\(\s*text\s*\)', rend)
                if raw_used:
                    # 这一条是 Q4 注入的形状：展开做了，但写出去的还是 text。
                    # 先判它 —— 只判「有没有用到展开变量」会得出「没用上」这个
                    # 较泛的结论，掩盖掉「用了原始 text」这个更具体的缺陷。
                    fail('P3 <w:t> 里写的还是原始 text —— '
                         '展开结果没用上，下划线长度不变')
                elif not used:
                    fail('P3 展开结果 %s 没有交给 CSFSXMLEscape —— '
                         '下划线长度不变' % var)
                else:
                    ok('P3 <w:t> 写入的是展开后的文本（%s）' % var)

    # P4/P5/P6：展开函数自身的三条硬约束
    exp = extract_func(src, 'CSFSExpandSpaceRun')
    if exp is None:
        fail('P4 找不到 CSFSExpandSpaceRun')
    else:
        body = exp
        # P4：上限 clamp
        if not re.search(r'if\s*\(\s*n\s*>\s*\d+\s*\)\s*n\s*=\s*\d+\s*;', body):
            fail('P4 展开没有上限 clamp —— width 的单位若不是像素（比如 1/100pt），'
                 '会算出上万个空格，整篇文档直接被撑爆，比短更糟')
        else:
            ok('P4 展开有上限 clamp（防 width 单位错时撑爆文档）')

        # P5：不许比原有空白更短
        if not re.search(r'text\.length\s*>\s*n', body):
            fail('P5 展开没有「不许比原有空白更短」的保护 —— '
                 '算出来比原来还少，等于又把它弄短了一次')
        else:
            ok('P5 展开保证不会短于原有空白字符数')

        # P6：width 不可用时原样返回
        if not re.search(r'if\s*\(\s*!\s*\(\s*sliceWidthPx\s*>\s*0\.0\s*\)\s*\)\s*return\s+text\s*;', body):
            fail('P6 width 不可用时没有原样返回 —— '
                 '会凭空空造出一堆空格，把本来正常的排版拉散')
        else:
            ok('P6 width 不可用时原样返回（不凭空造空格）')

    # P7：计数要进批次重置，也要进统计日志
    rimpl = extract_func(src, 'CSFSResetOptionStateImpl')
    if rimpl is None:
        fail('P7 找不到 CSFSResetOptionStateImpl')
    else:
        if not re.search(r'gCSFSSpaceExpandRuns\s*=\s*0\s*;', rimpl):
            fail('P7 批次重置没清 gCSFSSpaceExpandRuns —— '
                 '同一进程导出两次时，第二次的统计会混进第一次的计数，'
                 '日志上就分不清「这次有没有展开空格」')
        else:
            ok('P7 空格展开计数在批次重置里被清')
    if not re.search(r'gCSFSSpaceExpandRuns\b', src):
        fail('P7 找不到 gCSFSSpaceExpandRuns 计数变量')
    else:
        # 统计日志里必须出现（日志字符串里带 spaceExpanded= 这个名字）
        if 'spaceExpanded=' not in raw and 'spaceExpanded=' not in src:
            fail('P7 统计日志里没有 spaceExpanded —— '
                 '下一轮真机日志无法确认空格展开有没有走到')
        else:
            ok('P7 统计日志会报 spaceExpanded（便于真机核对）')

    # ══════════════════════════════════════════════════════════════
    # H 组：去除手写 —— 按行为判定「勾了就删、没勾不删」
    # ══════════════════════════════════════════════════════════════
    # 定位手写过滤块。
    #
    # 两条约束同时成立才算定位对：
    #   ① if 条件里出现 gCSFSHideWritten（不写死整串，见下）
    #   ② 块内出现 stypeSaysHW —— 这是**切片级**过滤的独有标记
    #
    # 为什么不能只按「第一个匹配」取：文件里有两处 gCSFSHideWritten 过滤，
    # 5170 行是**块级**（gCSFSHideWritten && catType == 1，整块手写图不插），
    # 5333 行才是**切片级**（逐 slice 判断）。按出现顺序取会拿到块级那个，
    # 于是 H1/H2/H3 全在验错对象 —— 而且它照样全绿，根本看不出来。
    hbody = None
    for m in re.finditer(r'if\s*\([^{};]*\bgCSFSHideWritten\b[^{};]*\)\s*\{', src):
        blk, _ = block_of(src, re.escape(m.group(0)), m.start())
        if blk and 'stypeSaysHW' in blk:
            hbody = blk
            break
    if hbody is None:
        fail('H1 找不到切片级手写过滤块（条件含 gCSFSHideWritten 且块内有 '
             'stypeSaysHW）—— 开关没接到切片过滤上')
    else:
        chains = continues_with_chains(hbody)
        defs = parse_bool_defs(hbody)
        # 求值器完整性自检：先确认「中间变量展开」这条链真的通。
        # 不通就不能出结论 —— 否则 H1/H3 会一红一绿，全都是假的。
        eval_broken = None
        try:
            evaluates_true([c for _p, c in chains][0], SC_OFF, defs) if chains else None
        except Exception as e:
            eval_broken = e

        if not chains:
            fail('H1 手写过滤块里没有任何 continue —— '
                 '勾了「去除手写」也删不掉任何东西（这正是 v31 的表现）')
        elif eval_broken is not None:
            fail('H1 条件求值器无法解析手写过滤块（%r）—— 判据不可信，请人工核对' % eval_broken)
        else:
            # H1：勾了 + stype 说 handwrit + cat≠1 + 有文字 → 必须删
            if any(evaluates_true(c, SC_HW_TEXT, defs) for _p, c in chains):
                ok('H1 勾选后，stype=handwritten 的 slice 会被删（v31 的反例已修复）')
            else:
                fail('H1 勾了「去除手写」，但 stype=handwritten 且有识别文字的 slice '
                     '不会被删 —— 这就是用户说的「去除手写选择了不生效」。'
                     '真机 runs 数字证明那 33 条就是手写内容本身，'
                     'v31 把它们当正文保留是错的')

            # H2：勾了 + cat=1（真手写图）→ 必须删
            if any(evaluates_true(c, SC_HW_IMG, defs) for _p, c in chains):
                ok('H2 勾选后，image_category=1 的真手写图会被删')
            else:
                fail('H2 勾了「去除手写」，image_category=1 的真手写图删不掉')

            # H3：没勾 → 一个都不许删
            bad = [(p, c) for p, c in chains if evaluates_true(c, SC_OFF, defs)]
            if bad:
                p, c = bad[0]
                snippet = hbody[max(0, p - 100):p + 12].replace('\n', ' ')
                fail('H3 没勾「去除手写」时仍有 continue 会执行 —— '
                     '这是 v27 OR 合并跨批次残留那种「选不选都删」的形态。'
                     '位置：…%s…' % snippet[-120:])
            else:
                ok('H3 没勾选时一条都不删（批次清零语义成立）')

    # H4：统计日志要能看出判据有没有命中
    #
    # 注意不能只 grep 名字出现 —— 声明在那里、日志里也打了，但唯独忘了自增，
    # 于是日志永远报 handHW=0，看起来「一段手写都没命中」，
    # 实际却删了一堆。那种「有名字、没计数」的形态必须被抓到。
    if not re.search(r'\bhandHWCount\b', src):
        fail('H4 没有 handHWCount —— 下一轮日志无法区分'
             '「判据没命中任何手写」和「命中了但没删」')
    elif not re.search(r'\bhandHWCount\s*\+\+|\bhandHWCount\s*\+=', src):
        fail('H4 handHWCount 从头到尾没有自增 —— '
             '日志里会永远报 handHW=0，看着像一段手写都没命中，'
             '实际可能删了很多，下一轮无从判断')
    else:
        if 'handHW=' not in raw and 'handHW=' not in src:
            fail('H4 handHWCount 算了却没进统计日志 —— 等于没留证')
        else:
            ok('H4 统计日志会报 handHW（判据命中数，可直接对 skip 数）')

    print('=== check_v32 ===')
    for m in oks:
        print('  [ OK ] ' + m)
    for m in fails:
        print('  [FAIL] ' + m)
    print('\nOK %d / FAIL %d' % (len(oks), len(fails)))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
