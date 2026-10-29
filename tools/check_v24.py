# -*- coding: utf-8 -*-
"""
v24 专项检查：导出面板开关 + 行内版式

为什么必须单独检查这两件事：

1) 「去除手写 / 去除印章」勾了不生效，不是判据写错，而是**压根没读开关**。
   编译器、lint、离线样本都看不见这种缺失 —— 代码完全合法，只是没做那件事。
   所以只能对源码断言「开关被读、且过滤排在取图之前」。

2) 行内多字段粘连，是因为忽略了 para.tabs 与 slice.add_tabstop。
   同样是「少做了一件事」，不是做错。断言字段被读、模板被写。

顺序类判据（E3）的写法要特别小心：
  必须比较「过滤语句」与「取图语句」在文件中的真实先后，
  不能只看「两个词都出现过」——后者永远通过，是典型的假检查。
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_render_c import extract_func  # noqa: E402

fails = []
oks = []


def ok(m):
    oks.append(m)


def fail(m):
    fails.append(m)


def strip_comments(s):
    """去掉 // 与 /* */ 注释，字符串原样保留。

    ⚠ 这一步不能省。注释里写 `<w:ind w:firstLine>` 是在解释语义，
    但检查器若拿注释当代码，就会得出「ind 在 tabs 之前」这种**假 FAIL**。
    假 FAIL 比漏报更害人：它会让人去改本来正确的实现。
    """
    out = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            out.append(c)
            i += 1
            while i < n:
                if s[i] == '\\' and i + 1 < n:
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


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'src/CamScannerSaveToFiles.m'
    src = io.open(path, encoding='utf-8').read()

    # ── E1 面板开关必须在导出动作里读
    #
    # 时机是硬约束：导出在后台线程跑，那时面板可能已经销毁，
    # 只有 exportWordAction 触发这一刻能拿到 _originalData。
    try:
        fn = extract_func(src, 'CSFS_exportWordAction')
    except Exception:
        fn = ''
    if 'CSFSReadOptionsFromBottomView(self)' in fn:
        ok('E1 exportWordAction 里读取了导出面板开关')
    else:
        fail('E1 exportWordAction 没有调用 CSFSReadOptionsFromBottomView —— '
             '面板状态只有这一刻能拿到，错过就永远读不到')

    # ── E2 三个键都要读
    try:
        pull = extract_func(src, 'CSFSPullOptions')
    except Exception:
        pull = ''
    missing = [k for k in ('hideWrittenImage', 'hideStampImage', 'handWrittenToImage')
               if ('@"%s"' % k) not in pull]
    if missing:
        fail('E2 CSFSPullOptions 没有读 %s' % ', '.join(missing))
    else:
        ok('E2 CSFSPullOptions 读了 hideWrittenImage / hideStampImage / handWrittenToImage')

    # ── E3 过滤必须排在取图之前
    #
    # 这条是真正容易写反的地方：只要「文字优先」或「取图」先执行，
    # 手写切片的 OCR 文字就已经进了 runs，后面再拦也删不掉。
    # 用文件内的真实先后比较，不是「两个词都出现过」。
    #
    # v25 判据从 `gCSFSHideStamp && stLow` 改成
    # `gCSFSHideStamp && (slCat == 2`（含 image_category 精确匹配 + stype 兜底）。
    # 条件跨行写，所以用正则匹配而不是 find。
    #
    # v31：手写过滤改成了块结构（因为判据本身要重写，见源码那段长注释），
    # 形态从
    #     if (gCSFSHideWritten && (slCat == 1 || stLow contains handwrit))
    # 变成
    #     if (gCSFSHideWritten) { … catSaysHW / stypeSaysHW … }
    # 于是原来绑 `gCSFSHideWritten\s*&&\s*\(?\s*slCat` 的判据**当场失明**
    # （实测：改完后它报「手写过滤缺失」，而代码里过滤明明在）。
    #
    # 这正是本项目反复踩的坑：判据绑「代码长什么样」而不是「行为对不对」。
    # 所以这里改成按**实质**判两件事：
    #   A) 存在一个由 gCSFSHideWritten 控制、且内部会 continue 的手写过滤块
    #   B) 该块的起点早于取图语句
    # 不再要求块内出现 `slCat == 1` 这种具体写法 —— 只要它受开关控制、
    # 且真的会跳过当前 slice，位置对了就是对的。
    import re
    code = strip_comments(src)
    pos_stamp_filter = re.search(r'gCSFSHideStamp\s*&&\s*\(?\s*slCat', code)

    # 手写过滤：找 `if (gCSFSHideWritten)` 起的块，向后截到配对的 }
    def _find_hand_block(text):
        m = re.search(r'if\s*\(\s*gCSFSHideWritten\s*\)\s*\{', text)
        if not m:
            return None
        i = text.find('{', m.start())
        depth = 0
        j = i
        while j < len(text):
            c = text[j]
            if c in '"\'':
                q = c
                j += 1
                while j < len(text):
                    if text[j] == '\\':
                        j += 2
                        continue
                    if text[j] == q:
                        break
                    j += 1
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return (m.start(), text[m.start():j + 1])
            j += 1
        return None

    hand_blk = _find_hand_block(code)
    pos_take_img = code.find('textWins ? nil : CSFSSliceImageInfo(sl)')
    if pos_take_img < 0:
        fail('E3 找不到切片取图语句（textWins ? nil : CSFSSliceImageInfo(sl)），'
             '模板结构变了，需人工复核')
    else:
        bad = []
        if not pos_stamp_filter:
            bad.append('印章过滤缺失')
        elif pos_stamp_filter.start() > pos_take_img:
            bad.append('印章过滤排在取图之后')
        if not hand_blk:
            bad.append('手写过滤缺失')
        else:
            pos_hand, hbody = hand_blk
            # 必须真的会 continue —— 只读开关不跳过，等于没过滤
            if 'continue' not in hbody:
                bad.append('手写过滤块里没有 continue（读了开关却没跳过）')
            elif pos_hand > pos_take_img:
                bad.append('手写过滤排在取图之后')
        if bad:
            fail('E3 切片级过滤位置错误：%s —— 一旦取图先跑，'
                 '手写文字已入列，再拦无效' % '；'.join(bad))
        else:
            ok('E3 印章/手写切片过滤均排在取图之前')

    # ── E4 块级隐藏
    if 'CSFSValue(block, @"hiding")' in src:
        ok('E4 块级 hiding 被尊重（App 隐掉的块不再输出）')
    else:
        fail('E4 没有检查 block.hiding —— App 已标记隐藏的块仍会被导出')

    # ── E5 手写/印章图块的块级拦截
    # v25：判据从 containsString 改成 CSFSCategoryType（严格相等），
    # 检查器匹配新函数名。
    if 'gCSFSHideStamp' in src and 'CSFSCategoryType' in src:
        ok('E5 印章/手写图块有块级拦截（CSFSCategoryType 精确匹配）')
    elif 'gCSFSHideStamp' in src and 'isStampImage' in src:
        ok('E5 印章图块有块级拦截（image_category + isStampImage）')
    else:
        fail('E5 印章图块缺块级拦截：勾了「去除印章」，STAMP 图仍会进文档')

    # ── E6 制表符来源
    try:
        sl = extract_func(src, 'CSFSParseSlice')
    except Exception:
        sl = ''
    if '@"add_tabstop"' in sl:
        ok('E6 CSFSParseSlice 读了 slice.add_tabstop')
    else:
        fail('E6 CSFSParseSlice 没读 add_tabstop —— 同行字段会继续粘连')

    # ── E7 段落版式字段
    miss2 = [k for k in ('indent_first_line', 'tabs', 'line_gap')
             if ('@"%s"' % k) not in src]
    if miss2:
        fail('E7 没有读取段落版式字段：%s' % ', '.join(miss2))
    else:
        ok('E7 读取了 indent_first_line / tabs / line_gap')

    # ── E8 tabs 模板与顺序
    try:
        rp = extract_func(src, 'CSFSRenderPara')
    except Exception:
        rp = ''
    rp = strip_comments(rp)          # 必须先剥注释，否则注释里的 <w:tabs> 会让存在性检查永远通过
    # 顺序判据必须盯「append 到 pPr 的位置」，不是字面量出现的位置。
    # 若 tabs 经中间变量再 append，字面量位置与真实顺序脱钩，
    # 那种检查在「删掉 append」时仍然通过 —— 就是假检查。
    if 'appendString:@"<w:tabs>"' not in rp:
        fail('E8 CSFSRenderPara 没有输出 <w:tabs> —— 有 tab 也没有落点')
    else:
        p_tabs = rp.find('appendString:@"<w:tabs>"')
        p_sp = rp.find('appendFormat:@"<w:spacing')
        p_ind = rp.find('appendFormat:@"<w:ind')
        if p_sp >= 0 and p_tabs > p_sp:
            fail('E8 <w:tabs> 排在 <w:spacing> 之后 —— CT_PPrBase 是 sequence，顺序错会被静默忽略')
        elif p_ind >= 0 and p_tabs > p_ind:
            fail('E8 <w:tabs> 排在 <w:ind> 之后 —— CT_PPrBase 是 sequence')
        else:
            ok('E8 <w:tabs> 存在且排在 spacing / ind 之前')

    # ── E9 tab run 真的被输出
    if '<w:tab/>' in rp and 'kCSFSRunTab' in rp:
        ok('E9 制表符被渲染成 <w:tab/>')
    else:
        fail('E9 制表位有定义但 run 里没有 <w:tab/> —— 不产生实际间隔')

    # ── E10 选项缺失时不能静默当成「没勾」
    #
    # 这是安全边界：读不到开关（optKnown=0）时必须留下痕迹，
    # 否则「用户明明勾了」和「用户没勾」在日志里长得一模一样。
    #
    # 判据不能绑版本号字面量（v24 曾写死 'v24 stats: optKnown='，
    # 一升到 v27 就假 FAIL）。按**实质**判：日志格式串里同时出现
    # optKnown 与 hideWritten/hideStamp，说明这一行确实在报开关判读结果。
    stats_line = None
    for ln in src.split('\n'):
        if 'CSFS_LOG' in ln and 'optKnown=' in ln and 'hideWritten=' in ln:
            stats_line = ln
            break
    if stats_line is None:
        fail('E10 统计行没有 optKnown —— 读不到开关时会被误判成「用户没勾」')
    else:
        ok('E10 统计行带 optKnown，可区分「没读到开关」与「读到了 NO」')

    print('=== check_v24 ===')
    for m in oks:
        print('  [ OK ] ' + m)
    for m in fails:
        print('  [FAIL] ' + m)
    print('\nOK %d / FAIL %d' % (len(oks), len(fails)))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
