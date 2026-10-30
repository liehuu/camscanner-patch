#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_v37 —— 版心：页边距 1440 → 800，内容区宽度必须跟着变

用户：「你看一下导出的 word 每行文字数目与我手机预览的截图很多不一样」

实测链条（同一份真机导出的 docx，只改左右边距，Word → PDF，逐行量 bbox）：

    边距   版心      「根据…」收尾      「第一条」收尾     总行数
    1440   451.3pt   法律、法（41 字）  5 单（44 字）     60
    1080   487.3pt   法规规定，（45 字） 单元．了（47 字）  55
     800   515.3pt   在平（47 字）      层2 号（56 字）    52  ← 与截图逐行一致
     720   523.3pt   在平等、（49 字）  层2 号（56 字）    52

再验一次：只改左右 800 与四周全改 800「逐行完全一致」（行数、字数、x0/x1、
首尾文字全同）—— 所以上下边距不参与折行，只改左右。

v37 改动唯一，但牵动五处判据，所以检查器守三件事：

【P】页边距本身
  P1 左右都是 800
  P2 上下保持 1440（无实证，不动）
  P3 header / footer / gutter 三个必需属性还在（缺一个 Word 判损坏）
  P4 全文只有一处 <w:pgMar/>（多份 sectPr 会互相覆盖）

【W】内容区宽度常量
  W1 kCSFSContentTwips == 10306.0
  W2 定义在 CSFSRenderImagePara 之前（static const 先声明后使用）
  W3 只定义一次

【C】两处必须同源 —— 这条是防「只改一半」的关键
  C1 11906 − left − right == 常量

【S】所有引用方
  S1 图片宽度上限引用常量，不另写一份硬编码
  S2 五处阈值（lineW / maxPt / lim / 均分制表位 / 制表位上限）都引用常量
  S3 全文无旧版心 9026 残留

为什么 C1 要写成等式而不是“断言两边都是某个数字”：
  断言字面量只能证明“没被改成别的数”，证明不了“两处一致”。
  v37 最容易出的缺陷不是改错值，是**只改一处** —— pgMar 改了、常量没改，
  或反过来。那种情况下版心实际是新的、判据还是旧的，日志一片绿但折行全错，
  与 v35 的 squeeze“一次不触发”是同一个形态。
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


def main():
    if len(sys.argv) < 2:
        print('用法: check_v37.py <file.m>')
        return 2
    raw = open(sys.argv[1], encoding='utf-8').read()
    src = strip_comments(raw)
    f = src.replace('\\"', '"')          # 去掉 ObjC 字符串里的 \"

    print('=' * 66)
    print('check_v37  CamScannerSaveToFiles.m')
    print('=' * 66)

    # ══════════════════════════════════════════════════════════════
    # P 组：页边距
    # ══════════════════════════════════════════════════════════════
    pms = re.findall(r'<w:pgMar([^>]*)/>', f)
    attrs = {}
    if len(pms) != 1:
        fail('P4 <w:pgMar/> 出现 %d 处（应为 1）—— 多份 sectPr 会互相覆盖，'
             '看不出哪份真正生效' % len(pms))
    else:
        ok('P4 全文只有一处 <w:pgMar/>')
        attrs = dict(re.findall(r'w:(\w+)="(-?\d+)"', pms[0]))

    def gi(k):
        v = attrs.get(k)
        try:
            return int(v) if v is not None else None
        except ValueError:
            return None

    left, right = gi('left'), gi('right')
    top, bottom = gi('top'), gi('bottom')

    if left == 800 and right == 800:
        ok('P1 左右边距都是 800 twips（实测值与手机预览逐行一致）')
    else:
        fail('P1 左右边距是 left=%s right=%s，应为 800/800 —— '
             '1440 是 Word 默认值，会把版心压窄 12%%，每行少 5~8 个汉字'
             % (left, right))

    if top == 1440 and bottom == 1440:
        ok('P2 上下保持 1440（对照实验证明上下不参与折行，不动）')
    else:
        fail('P2 上下边距被改成了 top=%s bottom=%s —— 没有实证支持，'
             '只会无端改变每页行数' % (top, bottom))

    missing = [k for k in ('header', 'footer', 'gutter') if k not in attrs]
    if not missing:
        ok('P3 header / footer / gutter 三个必需属性都在'
           '（ECMA-376 标 use="required"，缺一个 Word 判损坏）')
    else:
        fail('P3 <w:pgMar> 缺 %s —— Word 会按「无法读取的内容」处理'
             % '/'.join(missing))

    # ══════════════════════════════════════════════════════════════
    # W 组：常量
    # ══════════════════════════════════════════════════════════════
    const = None
    m_c = re.search(r'static const double kCSFSContentTwips\s*=\s*([0-9.]+)\s*;', f)
    if not m_c:
        fail('W1 找不到 static const double kCSFSContentTwips 定义')
    else:
        const = float(m_c.group(1))
        if abs(const - 10306.0) < 0.5:
            ok('W1 kCSFSContentTwips = 10306.0（A4 11906 − 左右各 800）')
        else:
            fail('W1 kCSFSContentTwips = %s，应为 10306.0 —— '
                 '版心改了而它不改，五处阈值全部按旧值算'
                 % m_c.group(1))

    n_def = len(re.findall(r'static const double kCSFSContentTwips\s*=', f))
    if n_def == 1:
        ok('W3 常量只定义一次（没有重复定义）')
    elif n_def > 1:
        fail('W3 常量定义了 %d 次 —— 改一处改不全，另一份会偷偷生效' % n_def)

    i_def = f.find('static const double kCSFSContentTwips')
    i_img = f.find('static NSString *CSFSRenderImagePara')
    if i_def < 0:
        pass                        # W1 已报
    elif i_img < 0:
        fail('W2 找不到 CSFSRenderImagePara')
    elif i_def < i_img:
        ok('W2 常量定义在图片渲染之前（static const 先声明后使用）')
    else:
        fail('W2 常量定义在 CSFSRenderImagePara 之后 —— C 里 static const '
             '必须先声明，图片宽度上限会取不到值')

    # ══════════════════════════════════════════════════════════════
    # C1：两处必须同源
    # ══════════════════════════════════════════════════════════════
    if const is None or left is None or right is None:
        fail('C1 无法校验自洽（pgMar 或常量缺失）')
    else:
        want = 11906 - left - right
        if abs(want - const) <= 1.0:
            ok('C1 自洽：11906 − %d − %d = %d，与常量 %.1f 一致'
               % (left, right, want, const))
        else:
            fail('C1 不自洽：pgMar 算出内容区 %d twips，常量却是 %.1f —— '
                 '只改一处，等于版心是新的、判据还是旧的'
                 % (want, const))

    # ══════════════════════════════════════════════════════════════
    # S 组：所有引用方
    # ══════════════════════════════════════════════════════════════
    if re.search(r'kMaxCx\s*=\s*kCSFSContentTwips\s*\*\s*635\.0', f):
        ok('S1 图片宽度上限引用 kCSFSContentTwips（不另写一份硬编码）')
    elif 'kMaxCx' in f:
        fail('S1 图片宽度上限没引用 kCSFSContentTwips —— '
             '版心变宽后长图会被无谓压小')
    else:
        fail('S1 找不到 kMaxCx')

    nf = re.sub(r'\s+', ' ', f)
    need = [
        (r'double lineW = kCSFSContentTwips / 20\.0;', 'lineW（折行判定）'),
        (r'double maxPt = kCSFSContentTwips / 20\.0;', 'maxPt（空白宽度上限）'),
        (r'\(long\)\(kCSFSContentTwips \* 0\.9\)', 'lim（缩进上限）'),
        (r'double pos = kCSFSContentTwips \* \(double\)i / \(double\)\(tabCount \+ 1\);',
         '均分制表位'),
        (r'if \(t > kCSFSContentTwips\) break;', '制表位上限'),
    ]
    miss = [d for pat, d in need if not re.search(pat, nf)]
    if not miss:
        ok('S2 五处阈值都引用常量（lineW / maxPt / lim / 均分制表位 / 制表位上限）')
    else:
        fail('S2 这些阈值没用 kCSFSContentTwips：%s —— '
             '版心变了、阈值不变，会出现「判据在跑、分支从不触发」'
             % '、'.join(miss))

    if '9026' in f:
        fail('S3 源码里还有 9026（旧版心）—— 说明只改了一半')
    else:
        ok('S3 无旧版心 9026 残留')

    print('-' * 66)
    print('check_v37 通过：OK %d / FAIL %d' % (OK, FAIL))
    if FAIL:
        for m in FAILED:
            print('  - %s' % m)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
