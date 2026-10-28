# -*- coding: utf-8 -*-
"""校验「文字优先」这条规则在源码里真的成立。

为什么需要这个脚本（2026-10-28 的教训）：
    v21 修好了图片，但把「手写转文字」导出的手写区又推回了图片。
    根因不是图片逻辑本身错，而是**判据顺序错**：
    slice 循环里图片分支排在文字之前，且只看 stype 一个字段。
    这类缺陷编译器看不见、lint 看不见、离线渲染样本更看不见
    （样本里根本没有手写 slice）。

    所以这里只做一件事：把 .m 当数据读，断言「文字关必须排在图片关之前」。
    不重新实现解析逻辑，因此不存在镜像失真。

检查项（D 系列）：
  D1  CSFSSliceText 存在，且除 text 外还有别名兜底
  D2  CSFSSliceImageInfo 里，文字判定出现在 stype 判定之前
  D3  CSFSParseSlice 走 CSFSSliceText，不再直接摸 sl.text
  D4  块过滤只跳过 LINE，不存在「非 PARA 一律 continue」的白名单过滤
  D5  IMAGE 分支里，取文字(CSFSBlockTextParas)排在取图(CSFSFindImage)之前
  D6  IMAGE 分支有「手写类」语义门槛（image_category + handwrit）
  D7  有 v22 统计行，能区分「没识别」与「判错了」
  D8  CSFSBlockTextParas 内部不碰图片（它只负责文字）

用法:
    python check_text_priority.py src/CamScannerSaveToFiles.m
    退出码 0 = 全过，1 = 有失败
"""
import sys, io, re
import os

# 复用 check_render_c 的函数体提取（按花括号配平，不信列 0 的 '}'）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_render_c import extract_func  # noqa: E402

fails = []
oks = []


def ok(m):
    oks.append(m)


def fail(m):
    fails.append(m)


def strip_comments(s):
    """剥掉 // 与 /* */ 注释，保留字符串字面量与换行。

    为什么必须剥（第一版就栽在这）：D2 要比较「文字判定」与「stype 判定」
    的先后，而函数体的注释里恰好写着 stype 这个词，于是注释里的
    "stype" 被当成代码位置，报了假 FAIL。

    ⚠ 这正是「检查器自己出错」的典型：先给结论再找证据，
      真正的问题会被一条假报淹掉。
      所以剥注释必须在**保留字符串字面量**的前提下做 ——
      裸 replace('//', '') 会把 @"file://" / @"http://" 一起切坏。
    换行原样保留，注释内容替换成等长空白。
    """
    out = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c in ('"', "'"):
            q = c
            j = i + 1
            while j < n:
                if s[j] == '\\':
                    j += 2
                    continue
                if s[j] == q:
                    j += 1
                    break
                j += 1
            out.append(s[i:j])
            i = j
            continue
        if s.startswith('//', i):
            j = s.find('\n', i)
            if j < 0:
                j = n
            out.append(' ' * (j - i))
            i = j
            continue
        if s.startswith('/*', i):
            j = s.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r'[^\n]', ' ', s[i:j]))
            i = j
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def main():
    path = sys.argv[1]
    # 全部检查都在「剥掉注释后」的源码上做，理由见 strip_comments 注释。
    src = strip_comments(io.open(path, encoding='utf-8').read())

    # ── D1：CSFSSliceText ──
    fn_text = extract_func(src, 'static NSString *CSFSSliceText(')
    if fn_text is None:
        fail("D1 找不到 CSFSSliceText —— 文字取值没有统一入口")
    else:
        need = ['"text"', '"content"']
        miss = [k for k in need if k not in fn_text]
        if miss:
            fail("D1 CSFSSliceText 缺少候选键 %s —— 手写识别结果未必落在 text 上"
                 % ",".join(miss))
        else:
            ok("D1 CSFSSliceText 存在且含 text/content 别名")

    # ── D2：文字关必须在 stype 关之前 ──
    fn_img = extract_func(src, 'static NSDictionary *CSFSSliceImageInfo(')
    if fn_img is None:
        fail("D2 找不到 CSFSSliceImageInfo")
    else:
        p_text = fn_img.find('CSFSSliceText(')
        # stype 判定已经抽成 CSFSSTypeLooksImage（v22 重构）。
        # 先找新函数名，找不到再退回字面 stype —— 两种写法都算「图片判据」，
        # 但**位置比较的对象必须是判据本身**，不能是别的什么东西。
        p_stype = fn_img.find('CSFSSTypeLooksImage(')
        if p_stype < 0:
            p_stype = fn_img.find('stype')
        if p_text < 0:
            fail("D2 CSFSSliceImageInfo 里没有 CSFSSliceText —— "
                 "手写转文字后 stype 仍是 handwrite，只按 stype 判图必然把文字丢掉")
        elif p_stype < 0:
            fail("D2 CSFSSliceImageInfo 里找不到 stype 判定，函数结构已变")
        elif p_text > p_stype:
            fail("D2 顺序错：stype 判定在第 %d 字符，文字判定在第 %d 字符 —— "
                 "文字必须先判" % (p_stype, p_text))
        else:
            ok("D2 文字判定排在 stype 判定之前")

    # ── D3：CSFSParseSlice 走统一入口 ──
    fn_parse = extract_func(src, 'static NSMutableDictionary *CSFSParseSlice(')
    if fn_parse is None:
        fail("D3 找不到 CSFSParseSlice")
    else:
        if 'CSFSSliceText(' not in fn_parse:
            fail("D3 CSFSParseSlice 没走 CSFSSliceText")
        elif 'CSFSValue(sl, @"text")' in fn_parse:
            fail("D3 CSFSParseSlice 仍直接取 sl.text —— 别名兜底被绕过")
        else:
            ok("D3 CSFSParseSlice 统一走 CSFSSliceText")

    # ── D4：块过滤只跳 LINE ──
    if '![bt isEqualToString:@"PARA"]' in src:
        fail("D4 仍存在「非 PARA 一律 continue」的白名单过滤 —— "
             "任何新块类型（手写/表格/题注）都会被整块吞掉")
    elif 'if ([bt isEqualToString:@"LINE"])' not in src:
        fail("D4 找不到 LINE 跳过分支，块过滤逻辑已变")
    else:
        ok("D4 块过滤只跳过 LINE，其余类型按文字处理")

    # ── D5 / D6：IMAGE 分支内部顺序 ──
    fn_image_block = extract_func(src, 'if ([bt isEqualToString:@"IMAGE"]) {')
    if fn_image_block is None:
        fail("D5 找不到 IMAGE 分支")
    else:
        p_paras = fn_image_block.find('CSFSBlockTextParas(')
        p_find = fn_image_block.find('CSFSFindImage(block')
        if p_paras < 0:
            fail("D5 IMAGE 分支没有取文字 —— 手写区会被无条件贴成图片")
        elif p_find < 0:
            fail("D5 IMAGE 分支找不到 CSFSFindImage，结构已变")
        elif p_paras > p_find:
            fail("D5 顺序错：取图在第 %d 字符，取文字在第 %d 字符" % (p_find, p_paras))
        else:
            ok("D5 IMAGE 分支先取文字、后取图")

        if 'image_category' not in fn_image_block:
            fail("D6 IMAGE 分支没有读 image_category —— 无法区分手写区与普通插图")
        elif 'handwrit' not in fn_image_block:
            fail("D6 IMAGE 分支缺少 handwrite 语义门槛")
        else:
            ok("D6 IMAGE 分支有手写类语义门槛（image_category/handwrit）")

    # ── D7：统计行 ──
    for needle, label in [('v22 stats: types=', '块类型清单'),
                          ('imgText=', '因文字而跳过图片的计数')]:
        if needle not in src:
            fail("D7 缺少 %s 统计（日志串 %r）" % (label, needle))
    if 'v22 stats: types=' in src and 'imgText=' in src:
        ok("D7 有 v22 统计行，可区分「没识别」与「判错了」")

    # ── D8：CSFSBlockTextParas 只碰文字 ──
    fn_btp = extract_func(src, 'static NSArray *CSFSBlockTextParas(')
    if fn_btp is None:
        fail("D8 找不到 CSFSBlockTextParas")
    elif 'CSFSFindImage' in fn_btp:
        fail("D8 CSFSBlockTextParas 里出现 CSFSFindImage —— 职责越界")
    else:
        ok("D8 CSFSBlockTextParas 只负责文字")

    print('=== check_text_priority ===')
    for m in oks:
        print('  [ OK ] ' + m)
    for m in fails:
        print('  [FAIL] ' + m)
    print('\nOK %d / FAIL %d' % (len(oks), len(fails)))
    return 0 if not fails else 1


if __name__ == '__main__':
    sys.exit(main())
