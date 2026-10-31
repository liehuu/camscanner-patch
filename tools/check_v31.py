#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_v31.py —— v31「空格/下划线空格丢失 + 开关只在第一次生效」的静态判据。

这一轮两个问题都有真机日志的逐行证据，而且**根因完全不同**，
所以分成两组判据。

────────────────────────────────────────────────────────────────────
【问题一】文字之间的空格、以及带下划线的空格，都没识别出来
────────────────────────────────────────────────────────────────────
真机日志（CSFS.log）关键三行：
    v21 DIAG slice dict(11){…,position,preview_info,text,stype,add_tabstop,width}
    v27 stats: … handSkip=33 … paras=21
    v21 stats: paras=21 runs=90          ← 距上一版 123，正好少 33

根因不是「没渲染空格」，而是**空格所在的 slice 被当成「没文字」丢掉了**。
空格在 OCR 的 JSON 里是一个独立 slice，它的间隔只体现在自身的
position/width 上；丢掉这个 slice 就无法从别处恢复，于是两列文字被粘成一串。

丢它的地方有两处，必须同时修（只修一处仍然丢）：
    ① CSFSSliceText:
           if ([s stringByTrimmingCharactersInSet:ws].length == 0) continue;
       纯空白 → 判为「无文字」→ CSFSParseSlice 直接返回 nil
    ② 段落收集循环:
           if (trimmed.length == 0) continue;
       就算 ① 取到了，到这里仍然进不了 runs

「带下划线的空格」尤其明显：它是 text=" " + font_attribute.underline=1。
两处都丢之后，整条填空横线消失 —— 用户看到的就是「没识别出来」。

判据：
  S1 CSFSSliceText 里不许再出现「trim 后判空 → continue」
     —— 这是纯空白被丢掉的第一处
  S2 CSFSSliceText 必须显式放行纯空白（CSFSIsPureWhiteSpace 分支在 return 之前）
  S3 CSFSIsPureWhiteSpace 必须存在，且覆盖全角空格 U+3000（中文排版缩进常靠它）
  S4 段落收集循环里不许用 trim 判空来丢 run —— 第二处
  S5 纯空白 run 必须把 hasText 置 YES，否则整个段落仍会被丢

────────────────────────────────────────────────────────────────────
【问题二】去除手写 / 去除印章选不选都没用，都是去除状态
────────────────────────────────────────────────────────────────────
真机日志（同一进程两次导出，是决定性证据）：
    11:12（勾了）：  hideWritteImage=有(1) hideStampImage=有(1) | merged w=1 s=1
    11:13（取消了）：hideWritteImage=有(0) hideStampImage=有(0) | merged w=1 s=1
                                                                        ^^^^^^^
Manager 明明给了 0，merged 还是 1。用户看到的就是「选不选都删」。

根因：v27 的 OR 合并语义是跨批次累积的 —— 它是静态全局，没有「批次」概念，
上一批的 1 会一直留到下一批，任何一次勾选都变成永久生效。

注意修法**不是**把 OR 改成「最后写入者」：那会退回 v24～v28 的失败态
（副本同步落后，Manager 的 1 会被盖成 0）。而是在批次边界清零，
批次内照旧 OR。两个语义互不干扰。

判据：
  R1 必须存在 CSFSResetOptionState，且在 exportWordAction 里被调用
  R2 重置必须**早于**读开关（顺序反了等于没清）
  R3 重置必须把 hide*/seen/handToResolved/optSrc 全部清掉
     —— 漏一个就会留下「上一批的结论」
  R4 重置必须同时清 scale / layout —— 换页换文档后分母会变

────────────────────────────────────────────────────────────────────
【问题三】stype=handwritten 的判据 —— 本节已撤销，改由 check_v32.py 负责
────────────────────────────────────────────────────────────────────
v31 曾在这里断言「stype 含 handwrit 但 cat≠1 的必须保留」，
依据是「日志里 33 次跳过全是 cat=0，真手写图应带 image_category=1」。

**这个依据是错的，v32 已纠正。** 真机三点定位（v31 三次导出的 runs）：
    v29 runs=123            （空格被丢，手写保留）
    v30 runs=90 + handSkip=33 = 123
    v31 runs=170 = 123 + spaceSlices47，且 handSkip=0 / handKeep=33
170 = 90 + 47 + 33 三版数字严丝合缝 —— 那 33 条就是**手写内容本身**，
v30 删得对，错的是它「没勾也删」（OR 残留，v31 已修）。
v31 把判据废掉，于是手写开关彻底失效（用户原话「去除手写选择了不生效」）。
另一个决定性事实：日志里 `v21 DIAG slice dict(11)` 的键列表
**根本没有 image_category**，所以 v31 的 `slCat == 1` 是恒假的死条件。

→ 保留一条永远不成立的判据，等于把「开关失效」写成了「合规」。
   本文件因此只保留问题一（空格）与问题二（批次清零）的判据，
   手写判据迁到 check_v32.py，按**行为**判定（见该文件说明）。

用法：python3 tools/check_v31.py src/CamScannerSaveToFiles.m
"""

import re
import sys

fails = []
oks = []


def ok(m):
    oks.append(m)


def fail(m):
    fails.append(m)


def strip_comments(s):
    out = list(s)
    n = len(s)
    i = 0
    while i < n:
        if s[i] == '/' and i + 1 < n and s[i + 1] == '/':
            j = i
            while j < n and s[j] != '\n':
                j += 1
            for k in range(i, j):
                out[k] = ' '
            i = j
            continue
        if s[i] == '/' and i + 1 < n and s[i + 1] == '*':
            j = s.find('*/', i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, min(j, n)):
                if out[k] != '\n':
                    out[k] = ' '
            i = j
            continue
        if s[i] == '"' or s[i] == "'":
            q = s[i]
            j = i + 1
            while j < n:
                if s[j] == '\\':
                    j += 2
                    continue
                if s[j] == q:
                    j += 1
                    break
                if s[j] == '\n':
                    break
                j += 1
            i = j
            continue
        i += 1
    return ''.join(out)


def extract_func(src, name):
    pos = 0
    while True:
        idx = src.find(name + '(', pos)
        if idx < 0:
            return None
        p = src.find('(', idx)
        depth = 0
        i = p
        while i < len(src):
            if src[i] == '(':
                depth += 1
            elif src[i] == ')':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if i >= len(src):
            return None
        j = i + 1
        while j < len(src) and src[j] in ' \t\r\n':
            j += 1
        if j < len(src) and src[j] == ';':
            pos = j
            continue
        brace = src.find('{', i)
        if brace < 0:
            return None
        depth = 0
        i = brace
        while i < len(src):
            c = src[i]
            if c in '"\'':
                q = c
                i += 1
                while i < len(src):
                    if src[i] == '\\':
                        i += 2
                        continue
                    if src[i] == q:
                        break
                    i += 1
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return src[idx:i + 1]
            i += 1
        return None


def trim_vars(body):
    """收集「被赋值为 stringByTrimming 结果」的变量名。

    为什么需要这个：判据不能只认内联形态
        if ([s stringByTrimmingCharactersInSet:ws].length == 0) continue;
    因为同样意思还可以写成两行
        NSString *trimmed = [s stringByTrimmingCharactersInSet:ws];
        if (trimmed.length == 0) continue;
    只认内联形态的检查，遇见两行写法就瞎了。
    """
    vs = set()
    for m in re.finditer(r'(\w+)\s*=\s*\[[^;]*?stringByTrimmingCharactersInSet',
                         body):
        vs.add(m.group(1))
    return vs


def first_trim_guard_pos(body):
    """返回第一条「对 trim 结果判空 → continue」语句的起始偏移，没有则 None。

    ★ 这里刻意**不**用「正则匹配代码长什么样」，而是按语句切分后判语义：
      一条语句里同时出现 continue + trim（内联或经由 trim 变量）——
      不论写成一行还是两行、不论变量叫什么名字，都算。
      v30 及以前踩过三次「判据绑字面形态」的坑，这是第四次的前置规避。
    """
    tv = trim_vars(body)
    off = 0
    for st in body.split(';'):
        if 'continue' in st:
            inline = 'stringByTrimmingCharactersInSet' in st
            varhit = False
            for v in tv:
                if re.search(r'\b%s\b' % re.escape(v), st):
                    varhit = True
                    break
            if inline or varhit:
                return off + (len(st) - len(st.lstrip()))
        off += len(st) + 1
    return None


def parse_if_blocks(body):
    """解析出所有 `if (cond) { ... }` 块：[(cond_text, body_start, body_end)]。"""
    blocks = []
    for m in re.finditer(r'\bif\s*\(', body):
        i = body.index('(', m.end() - 1)
        depth = 0
        j = i
        while j < len(body):
            if body[j] == '(':
                depth += 1
            elif body[j] == ')':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= len(body):
            continue
        cond = body[i + 1:j]
        k = j + 1
        while k < len(body) and body[k] in ' \t\r\n':
            k += 1
        if k >= len(body) or body[k] != '{':
            continue
        depth = 0
        e = k
        while e < len(body):
            if body[e] == '{':
                depth += 1
            elif body[e] == '}':
                depth -= 1
                if depth == 0:
                    break
            e += 1
        blocks.append((cond, k, e))
    return blocks


def split_top_level_or(cond):
    """把 if 条件按**最外层** `||` 切开。

    为什么这么切：一个 OR 分支只要能单独为真，它就足以触发整个条件。
    所以「handwrit 出现在某个最外层 OR 分支里」⇔「仅凭 stype 就能删」。
    这是 H3 的真正语义，跟代码怎么排版、变量叫什么无关。

    反例（v30 真实写法，必须判红）：
        if (gCSFSHideWritten && (slCat == 1 || stLow contains handwrit)) {
            ... continue;
        }
        → 最外层 `||` 分支之二含 handwrit → 单独为真 → 删
    正例（v31，必须判绿）：
        if (stypeSaysHW && !catSaysHW) { ... 只记日志，不 continue }
        → 该块内没有 continue，不进 H3 的考察范围
    """
    parts = []
    depth = 0
    cur = ''
    i = 0
    while i < len(cond):
        c = cond[i]
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        if depth == 0 and cond[i:i + 2] == '||':
            parts.append(cur)
            cur = ''
            i += 2
            continue
        cur += c
        i += 1
    parts.append(cur)
    return parts


def or_branch_lets_alone(cond, needle):
    """条件里是否存在一个最外层 OR 分支，仅凭 needle 即可为真。"""
    for p in split_top_level_or(cond):
        if needle in p:
            return True
    return False


def objc_cond_to_py(cond, assign):
    """把 ObjC 的 if 条件翻译成可 eval 的 Python 表达式，用来**求值**而不是匹配。

    为什么要走这一步：H3 的本质是一个关于行为的问题 ——
    「当 stype 说 handwrit、image_category 不是 1、且**有识别文字**时，
      这个 continue 会不会被执行」。
    用正则去猜条件长什么样，必然在换一种写法后失明（本项目已踩四次）。
    把条件真的算一遍，才不依赖写法。

    返回 (py表达式, 替换后的 assign)。
    """
    a = dict(assign)
    s = cond
    # ObjC 消息表达式整体换成原子：含有 handwrit 的 containsString 一律视为「stype 命中」
    s = re.sub(r'\[[^\[\]]*containsString:\s*@"[^"]*"[^\]\[]*\]', 'HWMSG', s)
    # 文字探测
    s = re.sub(r'CSFSSliceText\s*\([^()]*\)\s*!=\s*nil', 'HASTEXT', s)
    s = re.sub(r'CSFSSliceText\s*\([^()]*\)\s*==\s*nil', 'not HASTEXT', s)
    # 长度判断（stLow.length > 0 之类）恒真：stype 字符串在场景里是存在的
    s = re.sub(r'\b\w+\.length\s*[><]=?\s*\d+', 'TRUE', s)
    # 运算符
    s = s.replace('&&', ' and ').replace('||', ' or ')
    s = re.sub(r'!(?!=)', ' not ', s)
    s = re.sub(r'\bYES\b', 'True', s)
    s = re.sub(r'\bNO\b', 'False', s)
    s = re.sub(r'\bnil\b', 'None', s)
    # 标识符替换（长的先替，避免 catSaysHW 被 cat 先吃掉）
    for k in sorted(a, key=len, reverse=True):
        s = re.sub(r'\b%s\b' % re.escape(k), repr(a[k]), s)
    return ' '.join(s.split()), a


# H3 的「必须不删」场景：进到过滤块里、stype 说是 handwrit、
# image_category 不是 1（=0，空/未知）、而且**有识别文字**。
# 这四条同时成立时，这段 slice 就是正文文字，删掉就是 v30 的 bug。
UNSAFE_SCENARIO = {
    'gCSFSHideWritten': True,
    'stypeSaysHW':      True,
    'catSaysHW':        False,
    'slCat':            0,
    'hasTextHW':        True,
    'HWMSG':            True,
    'HASTEXT':          True,
    'TRUE':             True,
}


def deleting_continues(hbody):
    """找出 hbody 里所有 `continue`，返回 [(continue偏移, [外层 if 条件...])]。

    外层条件按「从内到外」排列 —— 只要每一层在 UNSAFE_SCENARIO 下都为真，
    这个 continue 就会真的执行。这就是判据本身，不用猜写法。
    """
    blocks = parse_if_blocks(hbody)
    out = []
    for m in re.finditer(r'\bcontinue\s*;', hbody):
        pos = m.start()
        chain = [cond for (cond, bs, be) in blocks if bs < pos < be]
        out.append((pos, chain))
    return out


def assigned_vars(body):
    """解析出「被赋过值」的变量集合，键是变量名，值是赋值右式的列表。

    ★ 为什么不能直接用 `'gCSFSPageScale' in body`：
      那是**子串判断**，而 gCSFSPageScale 是 gCSFSPageScaleSrc 的前缀 ——
      删掉 `gCSFSPageScale = 0.0;` 之后 `gCSFSPageScaleSrc = @"-"` 仍在，
      子串照样命中 → 检查永远绿。反向验证 R4 抓的正是这个。
      这是本项目第四次栽在子串匹配上（前三次见 check_v30 / verify_artifact）。
      必须按「整标识符 + 真的有赋值」判断。
    """
    out = {}
    for m in re.finditer(r'^\s*(g\w+)\s*=\s*([^;]*);', body, re.M):
        out.setdefault(m.group(1), []).append(m.group(2).strip())
    return out


def main():
    if len(sys.argv) < 2:
        print('用法: check_v31.py <file.m>')
        return 2
    raw = open(sys.argv[1], encoding='utf-8').read()
    src = strip_comments(raw)

    # ══════════════════════════════════════════════════════════════
    # 问题一：空格
    # ══════════════════════════════════════════════════════════════
    st = extract_func(src, 'CSFSSliceText')
    if st is None:
        fail('S1 找不到 CSFSSliceText —— 空格修复的落点消失')
    else:
        body = strip_comments(st)

        # S1：不许再用 trim 后判空来丢纯空白
        #
        # 原写法：if ([s stringByTrimmingCharactersInSet:ws].length == 0) continue;
        # 这条就是「空格不是内容」的假设。只要它在，空格一定丢。
        # 判据按**语义**（语句里 continue + trim 判空）而不是字面形态：
        # 写成两行、或变量改名成 trimmed / t / x，都必须照样抓到。
        p_guard = first_trim_guard_pos(body)
        if p_guard is not None:
            fail('S1 CSFSSliceText 仍用「trim 后为空 → continue」丢纯空白 —— '
                 '空格 slice 在 OCR JSON 里是独立内容，丢了就无法恢复间隔，'
                 '两列文字会被粘成一串；带下划线的空格（填空横线）也一起消失')
        else:
            ok('S1 CSFSSliceText 不再把纯空白当「无文字」丢掉')

        # S2：必须显式放行纯空白
        #
        # ★ 这里曾经写成 body.find('return s', i_ws) —— 那是**假检查**。
        #   CSFSSliceText 末尾还有一条 `return s;`（循环最后那行），
        #   于是纯空白分支里就算没有 return，find 也会在函数尾部找到一条，
        #   永远判绿。反向验证 D2 就是这么把它抓出来的。
        #   正确做法：只在这个 if 块的**花括号范围内**找 return。
        if 'CSFSIsPureWhiteSpace' not in body:
            fail('S2 CSFSSliceText 没有显式放行纯空白（缺 CSFSIsPureWhiteSpace 分支）—— '
                 '只删掉旧判据不够，必须主动 return 空白串，否则会走到下面的路径判据')
        else:
            i_ws = body.find('CSFSIsPureWhiteSpace')
            br = body.find('{', i_ws)
            ret_found = False
            if br >= 0:
                depth = 0
                k = br
                while k < len(body):
                    if body[k] == '{':
                        depth += 1
                    elif body[k] == '}':
                        depth -= 1
                        if depth == 0:
                            break
                    k += 1
                branch = body[br:k + 1]
                ret_found = re.search(r'\breturn\s+s\s*;', branch) is not None
            if not ret_found:
                fail('S2 CSFSIsPureWhiteSpace 分支里没有 return s —— '
                     '判了出来却没返回，空格照样丢')
            else:
                ok('S2 纯空白被显式放行并原样返回（不 trim，保留首尾空格）')

    # S3：CSFSIsPureWhiteSpace 必须存在且覆盖全角空格
    pw = extract_func(src, 'CSFSIsPureWhiteSpace')
    if pw is None:
        fail('S3 找不到 CSFSIsPureWhiteSpace（纯空白判定函数）')
    else:
        pbody = strip_comments(pw)
        if '0x3000' not in pbody:
            fail('S3 CSFSIsPureWhiteSpace 没覆盖全角空格 U+3000 —— '
                 '中文排版的缩进常靠全角空格，那也是「带下划线的空格」最常见的载体')
        elif '0x00A0' not in pbody:
            fail('S3 CSFSIsPureWhiteSpace 没覆盖不间断空格 U+00A0')
        else:
            ok('S3 CSFSIsPureWhiteSpace 覆盖半角/全角/不间断空格')

    # S4 / S5：段落收集循环
    #
    # 定位方式按实质：找「解析 slice → 立刻取 run 文本」的那个调用点。
    #   · 不绑变量名（本轮变量从 trimmed 改成了 tt），否则改名即失明
    #   · 不绑第二实参：诊断期的 &diagDone 指针已随诊断代码删除，
    #     这里正则吃 `(sl)` 与 `(sl, ...)` 两种形态
    #   · 全文有两处 CSFSParseSlice(sl)（另一处在段落级文字聚合里，
    #     紧跟 `[runs addObject:run]`），必须靠「紧接取 kCSFSRunText」
    #     才认得出段落收集循环这一处 —— 否则窗口会锚到前一处，S5 假红。
    m_parse = None
    for m in re.finditer(r'CSFSParseSlice\s*\(\s*sl\s*[^)]*\)\s*;', src):
        # 窗口给到 600：这段在深层嵌套里，缩进本身就有 68 个空格一行，
        # 200 字符会被 `if (!run) continue;` 一行吃掉，够不到 kCSFSRunText。
        if 'kCSFSRunText' in src[m.end():m.end() + 600]:
            m_parse = m
            break
    if m_parse is None:
        fail('S4 找不到段落收集循环里的 CSFSParseSlice(sl) 调用 —— 结构变了，需人工复核')
    else:
        i_parse = m_parse.start()
        seg = src[i_parse:i_parse + 3000]
        seg_c = strip_comments(seg)
        # 判据同样按语义：本段里不许再有「对 trim 结果判空 → continue」
        if first_trim_guard_pos(seg_c) is not None:
            fail('S4 段落收集循环里仍用「trim 后判空 → continue」丢 run —— '
                 '这是空格被丢的第二处；只修 CSFSSliceText 一处仍然会丢')
        else:
            ok('S4 段落收集循环不再用 trim 判空丢 run')

        # S5：纯空白 run 必须让 hasText=YES
        if 'CSFSIsPureWhiteSpace' not in seg_c:
            fail('S5 段落收集循环里没有识别纯空白 run —— '
                 '空格仍会被当空段落丢掉')
        else:
            i_sp = seg_c.find('CSFSIsPureWhiteSpace')
            after = seg_c[i_sp:i_sp + 700]
            if 'hasText = YES' not in after:
                fail('S5 纯空白 run 没有把 hasText 置 YES —— '
                     '只含空格的段落（填空行）会被 !hasText 整段丢掉')
            elif 'spaceSliceCount' not in after:
                fail('S5 纯空白 run 没有计数（缺 spaceSliceCount）—— '
                     '下一轮日志无法确认空格链路是否真的通了')
            else:
                ok('S5 纯空白 run 被保留、置 hasText、并单独计数')

    # ══════════════════════════════════════════════════════════════
    # 问题二：开关跨批次累积
    # ══════════════════════════════════════════════════════════════
    rs = extract_func(src, 'CSFSResetOptionState')
    if rs is None:
        fail('R1 找不到 CSFSResetOptionState —— 开关仍会跨导出累积，'
             '表现为「选不选都删」（真机日志 merged w=1 s=1 而 mgr 给的是 0）')
    else:
        ok('R1 CSFSResetOptionState 存在')

    ewa = extract_func(src, 'CSFS_exportWordAction')
    if ewa is None:
        fail('R1 找不到 CSFS_exportWordAction，判据失效')
    else:
        body = strip_comments(ewa)
        i_reset = body.find('CSFSResetOptionState')
        i_read = body.find('CSFSReadOptionsFromBottomView')
        if i_reset < 0:
            fail('R1 exportWordAction 里没有调用 CSFSResetOptionState —— '
                 '批次边界没清零，上一批的勾选会渗到这一批')
        elif i_read >= 0 and i_reset > i_read:
            fail('R2 CSFSResetOptionState 排在读开关之后 —— '
                 '先把本次读到的值清掉了，等于开关永远读成 NO')
        else:
            ok('R2 重置排在读开关之前（批次清零 → 再读本次值）')

    # R3：重置体必须覆盖关键变量
    #
    # 逐项检查而不是「有没有赋值语句」。漏一项的后果是具体的：
    #   hide*          → 本批仍按上一批的勾选删
    #   seen*          → 「本次有没有读到」沿用上一批结论
    #   handToResolved → 手写转文字沿用上一批
    #   optSrc         → 日志来源名残留，排查时被误导
    rimpl = extract_func(src, 'CSFSResetOptionStateImpl')
    if rimpl is None:
        fail('R3 找不到 CSFSResetOptionStateImpl（重置的实际实现）')
    else:
        rb = strip_comments(rimpl)
        av = assigned_vars(rb)
        # 必须真的被**赋值为「关/空」**，不能只是名字出现过。
        need_no = ['gCSFSHideWritten', 'gCSFSHideStamp', 'gCSFSHandToImage',
                   'gCSFSOptKnown', 'gCSFSSeenWritten',
                   'gCSFSSeenStamp', 'gCSFSSeenHandTo', 'gCSFSHandToResolved']
        miss = []
        for v in need_no:
            vals = av.get(v, [])
            if not any(re.fullmatch(r'NO|FALSE|0', x) for x in vals):
                miss.append(v + '（未被置 NO）')
        # optSrc 置 nil
        if not any(re.fullmatch(r'nil|NULL|@"-"', x)
                   for x in av.get('gCSFSOptSrc', [])):
            miss.append('gCSFSOptSrc（未被置 nil）')
        if miss:
            fail('R3 重置没清 %s —— 残留会导致「日志里读到了 0，输出却还是删」'
                 % ', '.join(miss))
        else:
            ok('R3 三个开关 + 四个 seen/解析标记 + optSrc 全部被置回初始值')

        # R4：版式上下文也要清
        #
        # 这两组值的初始态不同：scale/width 是 0.0，档位是 0，bool 是 NO。
        # 逐个按初值校验，避免「写了个别的值」也算通过。
        need4 = {
            'gCSFSPageScale':   r'0\.0*|[0-9]+',
            'gCSFSPageWidth':   r'0\.0*|[0-9]+',
            'gCSFSRenderWidth': r'0\.0*|[0-9]+',
            'gCSFSFontSizeMode': r'0',
            'gCSFSLineSpaceMode': r'0',
            'gCSFSAiBeautify':  r'NO|FALSE|0',
        }
        miss2 = []
        for v, pat in need4.items():
            vals = av.get(v, [])
            if not any(re.fullmatch(pat, x) for x in vals):
                miss2.append(v if vals else v + '（完全没赋值）')
        if miss2:
            fail('R4 重置没清 %s —— 换页/换文档后分母变了，'
                 '沿用上一批会让缩进按错误的值算' % ', '.join(miss2))
        else:
            ok('R4 版式上下文（scale/宽度/字号档/行距档/AI美化）全部被清')

    # ══════════════════════════════════════════════════════════════
    # 问题三（手写判据）已迁出本文件 —— 见文件头说明。
    #
    # v31 曾在此断言「stype 含 handwrit 但 cat≠1 必须保留」，
    # 而那是基于错误推导的结论（详见文件头）。保留它等于把
    # 「去除手写开关失效」登记成合规行为，所以整节删除，
    # 改由 check_v32.py 按行为判定。
    # ══════════════════════════════════════════════════════════════

    print('=== check_v31 ===')
    for m in oks:
        print('  [ OK ] ' + m)
    for m in fails:
        print('  [FAIL] ' + m)
    print('\nOK %d / FAIL %d' % (len(oks), len(fails)))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())