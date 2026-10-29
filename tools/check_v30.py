#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_v30.py —— v30「排版照本地排版引擎的真实公式」的静态判据。

为什么必须单独有这个检查器：
  用户的原话是「在手机里能预览成果，说明 app 里有转换成 word 排版的代码，
  导出时直接调用他的逻辑不就行了吗」。
  这句话指出了一个我一直搞错的前提：**排版逻辑确实在本地**。
  本轮反汇编把整条链挖通了：

      -[CSWordEditRenderView drawRect:]
        -> CSWordEditRenderManager.drawManager
           -> CSWordEditDefaultDrawManager / CSWordEditFlowDrawManager
              -[displayInContext:size:ocrPage:scale:showBorder:]
                 -> -[CSWordEditFlowDataManager
                       textWithSegment:ocrPage:]
                    -> -[CSWordEditFlowDataManager
                          setupParaStyleWithAttributeString:
                          para:ocrPage:segment:isCellPara:]

  排版的全部规则都在最后这个方法里。逐条反汇编后得到的事实：

  【缩进】0x10147dc98 起
      floating_box 为真 -> 整段不设缩进
      indent_hanging >= 1 -> setHeadIndent(scale * hanging * k)
                             且此时首行缩进一律不设（互斥）
      否则 indent_first_line != 0 -> setFirstLineHeadIndent(scale * fl * k)
      k = isCellPara ? 0.8 : 1.0
      全函数只出现 STUB[indent_hanging] / STUB[indent_first_line]，
      **indent_left / indent_right 一次都没读** —— 所以 docx 里不该有
      w:left（除非是悬挂缩进的等价物）/ w:right。

  【行距】0x10147db34 起
      aiBeautifyEnable -> 1.25（常量 @0x1088cdc50），跳过修正
      否则 multiple = line_gap / (font_size * 1.44)（常量 @0x1088cbfb8）
           再走 -[CSITextEngineSettings
             caculateLineHeightMultipleWithOriginalLineHeightMultiple:
             lineSpacingMode:isExport:]

  【行距的第二道修正 —— 这是白算了一轮的地方】0x1015294a0
      mode==2 -> +0.25
      mode==1 -> -0.25
      mode==0 -> 原值
      然后**无论哪个 mode，出口都夹到 [1.0, 1.5]**
      （1015294c0: fcmp 1.0 / 1015294cc: 1.5 / 1015294dc: 压到 1.5）
      真机日志 gap=25.94、11pt -> 1.637x，App 导出时会被压成 1.5。
      v29 没夹，docx 里写的是 w:line=393（1.637x），
      与 App 自己的导出结果差一档 —— 这就是「排版看着还是不对」。

  【scale 恒为 0 的机制性原因】
      v25 把 CSFSCaptureLayoutContext(src) 放在 CSFSPullOptions 末尾，
      而它上面有一句 `if (!hw && !st && !hi) return NO;`。
      真机上这三个字段一个都没有（v27 日志 optKnown=0 seen=000），
      于是**每次都在抓版式之前就 return 了**。
      真机日志的旁证：全程 `why=px@200dpi scale=0.0000` ——
      scale 一次都没取到，不是取不到，是那行代码没执行。
      修法：把 CaptureLayoutContext 提到早退判断**之前**。

本检查器断言 5 件事，每条都对应一个「能把它改回去」的具体动作：

  M1 CSFSLineTwipsFromGap 出口必须夹到 [1.0, 1.5]
     —— 去掉上限 1.5 就退回 v29（1.637 直接写进 w:line）
  M2 aiBeautify 分支必须是 1.25 且**不经 clamp**
     —— 反汇编里它 cbz 跳到 0x10147dc84，压根不调 caculate
  M3 缩进换算必须是 raw * scale，不许再出现 chars / 200dpi 两条猜测
     —— 这两条是 v25 猜的，反汇编证明不存在
  M4 CSFSIndentTwips 不许再按字号折算（basePt 只能被 (void) 掉）
     —— 反汇编里缩进与 font_size 没有任何乘法关系
  M5 CaptureLayoutContext 必须早于 CSFSPullOptions 里的早退 return
     —— 顺序反了 scale 永远是 0，缩进全部退化成估值

用法：python3 tools/check_v30.py src/CamScannerSaveToFiles.m
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
    """抹掉注释，保留字符串字面量（判据要看的正是字面量里的 XML/公式）。"""
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
    """抠 static / C 函数定义（跳过前置声明），按大括号配平。"""
    pos = 0
    while True:
        idx = src.find(name + '(', pos)
        if idx < 0:
            return None
        # 必须是个定义（前面不能是 . 或字母，避免命中 XXcsfsyy( 之类）
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


def main():
    if len(sys.argv) < 2:
        print('用法: check_v30.py <file.m>')
        return 2
    raw = open(sys.argv[1], encoding='utf-8').read()
    src = strip_comments(raw)

    # ══════════════════════════════════════════════════════════════
    # M1 / M2：行距
    # ══════════════════════════════════════════════════════════════
    lg = extract_func(src, 'CSFSLineTwipsFromGap')
    if lg is None:
        fail('M1 找不到 CSFSLineTwipsFromGap —— 行距换算整体消失')
    else:
        body = strip_comments(lg)

        # M1 出口必须夹到 [1.0, 1.5]。
        #
        # 只认「真的把 1.5 用作上限」这一种写法：既有对 1.5 的比较，
        # 也有把 multiple 赋成 1.5 的动作。写成 `if (multiple > 1.5)` 但不赋值，
        # 是「检查了却没纠正」，仍然会把 1.637 写出去。
        has_cmp15 = re.search(r'multiple\s*>\s*1\.5', body) is not None
        has_clamp15 = re.search(r'multiple\s*=\s*1\.5\s*;', body) is not None
        has_clamp10 = re.search(r'multiple\s*=\s*1\.0\s*;', body) is not None
        if not (has_cmp15 and has_clamp15):
            fail('M1 行距出口没有夹到上限 1.5 —— '
                 'App 的 caculateLineHeightMultiple... 出口一律 clamp[1.0,1.5]'
                 '（0x1015294cc / 0x1015294dc），真机 gap=25.94 算出的 1.637'
                 '会被它压成 1.5。不夹就等于比 App 多一档行距')
        elif not has_clamp10:
            fail('M1 行距只夹了上限，没夹下限 1.0 —— '
                 'caculate 的第一段就是 fcmp 1.0 / b.mi 取 1.0')
        else:
            ok('M1 行距出口夹到 [1.0, 1.5]，与 App 导出同一口径')

        # M2 aiBeautify：1.25 且不经 clamp
        #
        # 反汇编 0x10147db18: cbz w27 -> 0x10147db34（走公式）
        #          否则直接 setLineHeightMultiple:1.25 并 b 到 0x10147dc84
        # 也就是说 1.25 这条路**完全不经过 caculateLineHeightMultiple**，
        # 不该被 clamp 影响。若把它写进同一套 clamp 里，1.25 会被夹到 1.0 ——
        # 比不设还紧，正是「AI 美化后特别挤」的成因。
        m_ai = re.search(r'multiple\s*=\s*1\.25\s*;', body)
        if not m_ai:
            fail('M2 找不到 aiBeautify 的 1.25 —— 该值来自常量 @0x1088cdc50，'
                 '由 setupParaStyle 在 0x10147db18 直接 setLineHeightMultiple')
        else:
            tail = body[m_ai.end():]
            # aiBeautify 分支之后到 else 分支之前的这段不许出现 clamp
            k_else = tail.find('} else {')
            seg = tail if k_else < 0 else tail[:k_else]
            if re.search(r'multiple\s*<\s*1\.0\s*\)\s*multiple\s*=\s*1\.0', seg) or \
               re.search(r'multiple\s*>\s*1\.5\s*\)\s*multiple\s*=\s*1\.5', seg):
                fail('M2 aiBeautify 的 1.25 被套进了 clamp —— '
                     '反汇编里它 cbz 分支直接 set 后跳到 0x10147dc84，'
                     '不经过 caculate；被夹到 1.0 会让 AI 美化反而更挤')
            else:
                ok('M2 aiBeautify 行距 1.25 走独立路径，未被 clamp 影响')

    # ══════════════════════════════════════════════════════════════
    # M3 / M4：缩进
    # ══════════════════════════════════════════════════════════════
    ind = extract_func(src, 'CSFSIndentTwips')
    if ind is None:
        fail('M3 找不到 CSFSIndentTwips —— 缩进换算整体消失')
    else:
        body = strip_comments(ind)

        # M3 必须是 raw * scale
        if 'gCSFSPageScale' not in body:
            fail('M3 缩进换算没有乘 gCSFSPageScale —— '
                 '反汇编 0x10147dccc: fmul d0, d8, d0（d8 = ocrPage.scale），'
                 '缩进的真实换算就是 raw * scale')
        else:
            ok('M3 缩进按 raw * scale 换算（对应 fmul d8 一条）')

        # M3b 不许再有 chars / 200dpi 两条猜测
        #
        # 这两条是 v25 在「不知道单位」时的估值。反汇编已经把真实公式拿到了，
        # 留着它们只会在 scale 拿不到时悄悄给出一个假值，
        # 让日志看起来「有结果」而实际错得更离谱。
        if re.search(r'["\']chars["\']', body) or 'a <= 12.0' in body:
            fail('M3 缩进里仍有「按字符数折算」的分支 —— '
                 '反汇编全函数没有任何与字号相乘的指令，这条是纯猜测')
        elif '595.0' in body or 'px@200dpi' in body or '1654' in body:
            fail('M3 缩进里仍有「按 200dpi 折算」的分支（595/1654）—— '
                 '同样无任何反汇编依据')
        else:
            ok('M3 缩进里两条猜测分支（chars / 200dpi）已删除')

        # M4 basePt 不许参与运算
        #
        # 保留参数只是为了不改 4 处调用点。它一旦真的参与乘法，
        # 缩进就会随字号变化 —— 而 App 的缩进与字号完全无关。
        if re.search(r'pt\s*=\s*a\s*\*\s*basePt', body) or \
           re.search(r'a\s*\*\s*basePt', body):
            fail('M4 缩进仍在乘字号 basePt —— 反汇编只乘 scale，不乘字号')
        else:
            ok('M4 缩进与字号无关（basePt 未被参与运算）')

    # ══════════════════════════════════════════════════════════════
    # M5：CaptureLayoutContext 必须早于早退
    #
    # 这是 scale 一直是 0 的机制性原因，也是本检查器最重要的一条：
    # 只要有人把它挪回函数末尾（或放到 return 之后），
    # 缩进立刻全部退化成估值，而所有其他判据照样全绿。
    # ══════════════════════════════════════════════════════════════
    pull = extract_func(src, 'CSFSPullOptions')
    if pull is None:
        fail('M5 找不到 CSFSPullOptions，判据失效')
    else:
        body = strip_comments(pull)
        i_cap = body.find('CSFSCaptureLayoutContext')
        if i_cap < 0:
            fail('M5 CSFSPullOptions 里根本没有调用 CSFSCaptureLayoutContext —— '
                 'scale 永远拿不到，缩进全部退化成估值')
        else:
            # 早退语句：if (!hw && !st && !hi) return NO;
            m_ret = re.search(r'if\s*\(\s*!hw\s*&&\s*!st\s*&&\s*!hi\s*\)\s*return', body)
            if m_ret is None:
                # 找不到这条早退本身也算隐患：说明判据依赖的锚点变了
                fail('M5 找不到 CSFSPullOptions 里 `if (!hw && !st && !hi) return` 早退 —— '
                     '判据锚点消失，请确认是否改了读字段的方式')
            elif i_cap > m_ret.start():
                fail('M5 CSFSCaptureLayoutContext 排在早退 return 之后 —— '
                     '真机上三个开关字段常常一个都没有（v27 日志 optKnown=0 seen=000），'
                     '这句 return 会先执行，抓版式的代码永远跑不到，'
                     'scale 恒为 0.0000，缩进全部退化成猜测值')
            else:
                ok('M5 CSFSCaptureLayoutContext 早于早退 return，scale 一定能拿到')

    # ══════════════════════════════════════════════════════════════
    # M6：OOXML 不许凭空写 w:left / w:right 的留白缩进
    #
    # App 只设 headIndent 与 firstLineHeadIndent。落成 OOXML 后：
    #   悬挂缩进 → w:left=X w:hanging=X  （首行顶格的等价写法）
    #   首行缩进 → w:firstLine=X
    # 若只写 w:left=X 而漏 w:hanging，首行也会缩进，整段右移一格。
    # v29 及以前正是这么写的。
    # ══════════════════════════════════════════════════════════════
    i_left = src.find('occurrence-guard: w:left')
    # 直接扫所有 w:left 写法，逐条看是否配了 hanging
    lefts = [m.start() for m in re.finditer(r'w:left=\\"%ld\\"', src)]
    if not lefts:
        ok('M6 OOXML 里没有残留的裸 w:left 写法')
    else:
        bad = 0
        for p in lefts:
            seg = src[p:p + 200]
            if 'w:hanging' not in seg:
                bad += 1
        if bad:
            fail('M6 有 %d 处 w:left 没配 w:hanging —— '
                 'App 设 headIndent 时同时把首行缩进置 0，'
                 '只写 w:left 会让首行也缩进，整段右移一格' % bad)
        else:
            ok('M6 所有 w:left 都配了 w:hanging（悬挂缩进的正确 OOXML 等价式）')

    print('=== check_v30 ===')
    for m in oks:
        print('  [ OK ] ' + m)
    for m in fails:
        print('  [FAIL] ' + m)
    print('\nOK %d / FAIL %d' % (len(oks), len(fails)))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())