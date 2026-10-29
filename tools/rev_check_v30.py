#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rev_check_v30.py —— check_v30.py 的反向验证（缺陷注入）。

为什么必须有这个文件：
  本项目已经踩过三次「检查器本身是假的」：
    · verify_artifact.py 用 `"Architecture: iphoneos-arm64" in ctrl` 做子串匹配，
      `iphoneos-arm64e` 也含这个子串，于是架构写错时它照样报 OK，
      正是这条假检查放行了装不上的包。
    · check_v29.py 的 M5 判据写成了黑名单 `(?!...|mw|ms|w|s|fw|fs)`，
      注入 `gCSFSHideWritten = mw;` 恰好落在排除名单里 → 假通过。
    · check_v27.py 的 F2 绑了变量名 ``\bgot[123]\s*=``，
      v28 把变量改名成 gotModel 就整条失效。

  共同点：**判据绑在了「代码长什么样」上，而不是「行为对不对」上**，
  于是只要改法稍微变一下，检查就瞎了。
  唯一可靠的验证方式：造一个真实缺陷，确认检查器真的会报错。

本文件注入 7 例，每例都对应一个「真实出现过或极易发生」的改法：

  D1 去掉行距上限 1.5        → 退回 v29 的 1.637x
  D2 行距下限也不夹          → 1.0 以下的行距会让 Word 报错/挤压
  D3 aiBeautify 的 1.25 被夹 → AI 美化反而更挤
  D4 缩进换回按字符折算      → 退回 v25 的猜测
  D5 缩进换回 200dpi 折算    → 同上
  D6 缩进乘上字号            → 缩进随字号漂移
  D7 CaptureLayoutContext 挪到早退之后 → scale 恒 0（本轮的机制性真因）
  D8 w:left 漏掉 w:hanging    → 首行也缩进，整段右移一格

用法：python3 tools/rev_check_v30.py [src/CamScannerSaveToFiles.m]
      （CI 里不带参数，默认读仓库根下的 src/CamScannerSaveToFiles.m）
"""

import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, 'check_v30.py')

# CI 里 rev_check_* 一律**不带参数**调用（见 build.yml 的 Pre-syntax check），
# 所以这里必须自己定位源码。v29 的同一处也这么写，保持一致：
# 参数可选，缺省就用仓库根下的 src/CamScannerSaveToFiles.m。
ROOT = os.path.dirname(HERE)
SRC_DEFAULT = os.path.join(ROOT, 'src', 'CamScannerSaveToFiles.m')


def run_check(text):
    """把改造后的源码写临时文件，跑 check_v30，返回 (退出码, 输出)。"""
    fd, path = tempfile.mkstemp(suffix='.m', text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
        p = subprocess.run([sys.executable, CHECK, path],
                           capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def inject(src, old, new, tag):
    """精确替换一次。replace 不到就说明注入目标串写错了（用例本身失效）。"""
    n = src.count(old)
    if n != 1:
        print('  [BAD ] %s 注入目标串出现 %d 次（应为 1）—— 用例本身失效'
              % (tag, n))
        return None
    return src.replace(old, new)


def main():
    src_path = sys.argv[1] if len(sys.argv) > 1 else SRC_DEFAULT
    if not os.path.exists(src_path):
        print('找不到源码：%s' % src_path)
        return 2
    orig = open(src_path, encoding='utf-8').read()

    # 先确认原始源码是全绿的，否则后面「注入了才变红」没有意义
    rc0, out0 = run_check(orig)
    if rc0 != 0:
        print('[BAD ] 原始源码本来就没通过 check_v30 —— 反向验证无意义')
        print(out0)
        return 2
    print('基线：原始源码 check_v30 全绿\n')

    cases = []

    # ── D1 去掉行距上限 1.5 ──────────────────────────────────────
    #
    # 对应 v29 的真实缺陷：算对了 1.637，但没夹。
    cases.append((
        'D1',
        '去掉行距上限 1.5（退回 v29 的 1.637x）',
        'M1 行距出口没有夹到上限',
        lambda s: inject(s,
                         '        if (multiple < 1.0) multiple = 1.0;\n'
                         '        if (multiple > 1.5) multiple = 1.5;\n',
                         '        if (multiple < 1.0) multiple = 1.0;\n',
                         'D1'),
    ))

    # ── D2 只夹上限不夹下限 ──────────────────────────────────────
    cases.append((
        'D2',
        '去掉行距下限 1.0',
        'M1 行距只夹了上限',
        lambda s: inject(s,
                         '        if (multiple < 1.0) multiple = 1.0;\n'
                         '        if (multiple > 1.5) multiple = 1.5;\n',
                         '        if (multiple > 1.5) multiple = 1.5;\n'
                         '        if (multiple < 0.5) multiple = 0.5;\n',
                         'D2'),
    ))

    # ── D3 aiBeautify 的 1.25 被套进 clamp ───────────────────────
    #
    # 把 clamp 提到 if/else 之外，1.25 就会被夹到 1.0。
    # 这是「为了一致性顺手把 clamp 挪到出口」时最自然的写法，
    # 也正是最容易发生、且肉眼最难发现的一类回归。
    cases.append((
        'D3',
        'aiBeautify 的 1.25 被 clamp 夹到 1.0',
        'M2 aiBeautify 的 1.25 被套进了 clamp',
        lambda s: inject(s,
                         '        multiple = 1.25;                 // 常量 @0x1088cdc50，不 clamp\n',
                         '        multiple = 1.25;\n'
                         '        if (multiple < 1.0) multiple = 1.0;\n'
                         '        if (multiple > 1.5) multiple = 1.5;\n',
                         'D3'),
    ))

    # ── D4 缩进换回按字符折算 ────────────────────────────────────
    cases.append((
        'D4',
        '缩进换回按字符数折算（v25 的猜测）',
        'M3 缩进里仍有「按字符数折算」的分支',
        lambda s: inject(s,
                         '    double pt = a * scale;\n',
                         '    double pt = (a <= 12.0) ? (a * basePt) : (a * scale);\n',
                         'D4'),
    ))

    # ── D5 缩进换回 200dpi 折算 ──────────────────────────────────
    cases.append((
        'D5',
        '缩进换回按 200dpi 折算（595/1654）',
        'M3 缩进里仍有「按 200dpi 折算」的分支',
        lambda s: inject(s,
                         '    double pt = a * scale;\n',
                         '    double pt = (scale > 0.0) ? (a * scale) : (a * (595.0 / 1654.0));\n',
                         'D5'),
    ))

    # ── D6 缩进乘上字号 ──────────────────────────────────────────
    cases.append((
        'D6',
        '缩进乘上字号 basePt',
        'M4 缩进仍在乘字号',
        lambda s: inject(s,
                         '    double pt = a * scale;\n',
                         '    double pt = a * basePt * scale;\n',
                         'D6'),
    ))

    # ── D7 CaptureLayoutContext 挪到早退之后 ─────────────────────
    #
    # 这是本轮最核心的机制性缺陷：v25～v29 一直是这样写的。
    # 把调用从函数开头删掉、改挂到合并日志之前 —— 行为上等价于
    # 「开关读到了才抓版式」，而真机上开关恰好读不到。
    #
    # 锚点必须唯一：`return YES;` 在这里出现 9 次，用它做锚点会「用例本身失效」。
    # 改用 CSFSPullOptions 里独有的那行合并日志做锚点。
    def d7(s):
        a = inject(s,
                   '        CSFSCaptureLayoutContext(src);\n\n'
                   '        id hw = CSFSValue(src, @"hideWrittenImage");\n',
                   '        id hw = CSFSValue(src, @"hideWrittenImage");\n',
                   'D7a')
        if a is None:
            return None
        return inject(a,
                      '        CSFS_LOG(@"v27 opts(%@) hideWritten=%d hideStamp=%d handToImage=%d"',
                      '        CSFSCaptureLayoutContext(src);\n'
                      '        CSFS_LOG(@"v27 opts(%@) hideWritten=%d hideStamp=%d handToImage=%d"',
                      'D7b')

    cases.append((
        'D7',
        'CaptureLayoutContext 挪到早退 return 之后（scale 恒 0）',
        'M5 CSFSCaptureLayoutContext 排在早退 return 之后',
        d7,
    ))

    # ── D8 w:left 漏掉 w:hanging ─────────────────────────────────
    cases.append((
        'D8',
        '悬挂缩进只写 w:left，漏掉 w:hanging',
        'M6 有 1 处 w:left 没配 w:hanging',
        lambda s: inject(s,
                         '[pPr appendFormat:@"<w:ind w:left=\\"%ld\\" w:hanging=\\"%ld\\"/>", indHang, indHang];',
                         '[pPr appendFormat:@"<w:ind w:left=\\"%ld\\"/>", indHang];',
                         'D8'),
    ))

    bad = 0
    for tag, desc, expect, fn in cases:
        mutated = fn(orig)
        if mutated is None:
            bad += 1
            continue
        rc, out = run_check(mutated)
        hit = (rc != 0 and expect in out)
        if hit:
            line = [l for l in out.splitlines() if expect in l]
            print('  [HIT ] %s %s' % (tag, desc))
            print('         → %s' % (line[0].strip() if line else expect))
        else:
            bad += 1
            print('  [MISS] %s %s —— 注入后检查器没报出预期缺陷' % (tag, desc))
            print('         期望包含：%s' % expect)
            print('         实际输出：')
            for l in out.splitlines():
                if '[FAIL]' in l or 'OK ' in l:
                    print('           ' + l.strip())

    total = len(cases)
    print('\n反向验证：%d/%d 命中' % (total - bad, total))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())