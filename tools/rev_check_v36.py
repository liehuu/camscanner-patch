#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rev_check_v36 —— 对 check_v36 做缺陷注入反向验证

v36 的判据比 v35 更"结构"，也就更容易写成假绿：

  · 「不再有 fallback-2chars」—— 只要注释里不出现就行，
    真正的兜底代码换成另一个算式照样绿（所以 I1/I2 分开测）；
  · 「清缩进后立即 return」—— 函数末尾还有一个 return flags，
    只看"有没有 return"永远绿（所以要比 return 与 tailSum 的先后）；
  · 「同时改宽度与字符数」—— 两处写回可以分别在两个函数里，
    名字一 grep 就有（所以要求同一个函数体内）；
  · 「1pt 临界垫」—— 只要源码任意位置出现 right="-20" 就绿。

每条用例都写成**真机上会出现过的半成品形态**：
  · 兜底还在，但日志串改了名（I1 抓不到，I2 抓得到）
  · 结论算出来了，return 忘了（D5）
  · 压了空白，但只改了估算值（S1，v35 的真实形态）
  · 清缩进的结论返回了，渲染端没消费（R1）

规则（与 rev_check_v31~v35 一致）：
  · 注入后 check_v36 必须变红，且报出的必须是**这一条**判据；
  · 锚点命中数不是 1 就算用例失效（说明源码改过，锚点要更新）；
  · 注入函数返回 None 时**必须打印**，否则「20/21」看不出是哪条挂了。

跑法：python3 tools/rev_check_v36.py
"""

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src', 'CamScannerSaveToFiles.m')
CHECK = os.path.join(HERE, 'check_v36.py')


def run_check(text):
    fd, p = tempfile.mkstemp(suffix='.m', text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
        r = subprocess.run([sys.executable, CHECK, p],
                           capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr
    finally:
        try:
            os.unlink(p)
        except OSError:
            pass


def inject(src, old, new, tag):
    n = src.count(old)
    if n != 1:
        print('  [BAD ] %s 锚点命中 %d 次（应为 1）—— 用例失效，请更新锚点'
              % (tag, n))
        return None
    return src.replace(old, new, 1)


def main():
    orig = open(SRC, encoding='utf-8').read()

    rc, out = run_check(orig)
    if rc != 0:
        print('基线不绿，先修 check_v36 本身：')
        print(out)
        return 1
    print('基线：原始源码 check_v36 全绿\n')

    cases = []

    # ══════════════════════════════════════════════════════════════
    # I 组：兜底是否真删了
    # ══════════════════════════════════════════════════════════════

    # I1 兜底还在，只是日志串换了名
    cases.append((
        'I1',
        '两字符兜底还在（日志串换名，躲过字符串检查）',
        '[FAIL] I1',
        lambda s: inject(s, 'v36 ind none:',
                         'fallback-2chars', 'I1'),
    ))

    # I2 兜底的算式回来了，但没打日志 —— I1 抓不到，只能靠算式抓
    cases.append((
        'I2',
        '兜底算式 paraPt * 40.0 回来了（没打日志，I1 抓不到）',
        '[FAIL] I2',
        lambda s: inject(
            s,
            'indFirst = (long)(flT + 0.5);',
            'indFirst = (long)(flT + 0.5);\n'
            '                if (indFirst <= 0) '
            'indFirst = (long)(paraPt * 40.0 + 0.5);',
            'I2'),
    ))

    # I3 缩进落笔的守卫丢了（fl 为 0 也会写 firstLine）
    cases.append((
        'I3',
        '首行缩进没被 indFirst > 0 守卫',
        '[FAIL] I3',
        lambda s: inject(s,
                         '} else if (indFirst > 0) {',
                         '} else if (indFirst >= 0) {', 'I3'),
    ))

    # ══════════════════════════════════════════════════════════════
    # F 组：位标志
    # ══════════════════════════════════════════════════════════════

    cases.append((
        'F1',
        'kCSFSFitLeft 位标志被删（左对齐结论没地方放）',
        '[FAIL] F1',
        lambda s: inject(s, '#define kCSFSFitLeft      1',
                         '/* kCSFSFitLeft 删除 */', 'F1'),
    ))

    cases.append((
        'F2',
        'kCSFSFitNoIndent 位标志被删（清缩进结论没地方放）',
        '[FAIL] F2',
        lambda s: inject(s, '#define kCSFSFitNoIndent  2',
                         '/* kCSFSFitNoIndent 删除 */', 'F2'),
    ))

    # F3 退回 v35 的 BOOL —— 正是「两个结论只能二选一」的根源
    cases.append((
        'F3',
        '返回值退回 BOOL（清缩进与左对齐只能二选一）',
        '[FAIL] F3',
        lambda s: inject(s,
                         'static int CSFSFitParaWidth(NSMutableArray *runs, '
                         'double paraPt, long indentTw,',
                         'static BOOL CSFSFitParaWidth(NSMutableArray *runs, '
                         'double paraPt, long indentTw,', 'F3'),
    ))

    # F4 算出 flags 却不返回（渲染端永远收不到）
    cases.append((
        'F4',
        'fitFlags 算出来却没返回（渲染端收不到结论）',
        '[FAIL] F4',
        lambda s: inject(s, '    return fitFlags;',
                         '    return 0;', 'F4'),
    ))

    # ══════════════════════════════════════════════════════════════
    # D 组：清缩进的四条判据
    # ══════════════════════════════════════════════════════════════

    cases.append((
        'D1',
        '去掉「本来有缩进」的前提（顶格段落也被处理）',
        '[FAIL] D1',
        lambda s: inject(
            s,
            'if (indentPt > 1.0 && total > avail && total <= lineW * 1.18 &&',
            'if (indentPt >= 0.0 && total > avail && total <= lineW * 1.18 &&',
            'D1'),
    ))

    cases.append((
        'D2',
        '去掉「加了缩进装不下」（装得下也被清缩进）',
        '[FAIL] D2',
        lambda s: inject(
            s,
            '    if (indentPt > 1.0 && total > avail && total <= lineW * 1.18 &&\n'
            '        total > avail * 0.6) {',
            '    if (indentPt > 1.0 && total > 0.0 && total <= lineW * 1.18 &&\n'
            '        total > avail * 0.6) {',
            'D2'),
    ))

    # D3 容差退回 1.06 —— 这不是假想的错误，是 v36 第一版真写过的值。
    #    按真机估算（p2 491.5 / p3 502.1）对照 451.3×1.06=478.4，
    #    两段都过不了上限，整条分支一次都不会触发。
    cases.append((
        'D3',
        '容差退回 1.06（真机三段全过不了上限，分支一次不触发）',
        '[FAIL] D3',
        lambda s: inject(s, 'total <= lineW * 1.18',
                         'total <= lineW * 1.06', 'D3'),
    ))

    cases.append((
        'D4',
        '去掉极短段落下限（只有几个字的段落也被改）',
        '[FAIL] D4',
        lambda s: inject(s, 'total > avail * 0.6) {',
                         'total > 0.0) {', 'D4'),
    ))

    # D5 结论算出来了，却没在分支内 return —— 继续落到压空白
    #    这是最像「写对了」的形态：代码全都在，只是漏了一个 return。
    cases.append((
        'D5',
        '清缩进后没 return，继续落到压空白分支',
        '[FAIL] D5',
        lambda s: inject(
            s,
            '            flags |= kCSFSFitLeft;\n'
            '        }\n'
            '        return flags;\n',
            '            flags |= kCSFSFitLeft;\n'
            '        }\n',
            'D5'),
    ))

    cases.append((
        'D6',
        'outDropIndent 没跟着置位（调用方拿不到结论）',
        '[FAIL] D6',
        lambda s: inject(s, '*outDropIndent = YES;',
                         '*outDropIndent = NO;', 'D6'),
    ))

    # ══════════════════════════════════════════════════════════════
    # S 组：空白必须真改（v35 的「算了不用」形态）
    # ══════════════════════════════════════════════════════════════

    # S1 只改宽度字段 —— v35 的真身。日志报 ratio=0.836，XML 里一个没少。
    cases.append((
        'S1',
        '压空白只改估算宽度、不改字符数（v35 的真实形态）',
        '[FAIL] S1',
        lambda s: inject(s, '[r setObject:ns forKey:kCSFSRunText];',
                         '(void)ns;', 'S1'),
    ))

    # S2 字符数不按比例折算（压了等于没压，或压成空串）
    cases.append((
        'S2',
        '字符数不按 ratio 折算',
        '[FAIL] S2',
        lambda s: inject(
            s,
            'NSUInteger nn = (NSUInteger)((double)t.length * ratio + 0.5);',
            'NSUInteger nn = t.length;', 'S2'),
    ))

    cases.append((
        'S3',
        '段尾自适应没走 ScaleSpaceRuns（只改估算值）',
        '[FAIL] S3',
        lambda s: inject(s, 'CSFSScaleSpaceRuns(runs, YES, r2);',
                         '(void)r2;', 'S3'),
    ))

    cases.append((
        'S4',
        'squeeze 没走 ScaleSpaceRuns（只改估算值）',
        '[FAIL] S4',
        lambda s: inject(s, 'CSFSScaleSpaceRuns(runs, NO, ratio);',
                         '(void)ratio;', 'S4'),
    ))

    # S5 又出现了裸写宽度字段（哪怕 ScaleSpaceRuns 还在，也会漏网一处）
    cases.append((
        'S5',
        'CSFSFitParaWidth 里又出现裸写 kCSFSRunSpaceW',
        '[FAIL] S5',
        lambda s: inject(
            s,
            '            CSFSScaleSpaceRuns(runs, YES, r2);',
            '            CSFSScaleSpaceRuns(runs, YES, r2);\n'
            '            [runs setObject:[NSNumber numberWithDouble:1.0] '
            'forKey:kCSFSRunSpaceW];',
            'S5'),
    ))

    # ══════════════════════════════════════════════════════════════
    # R 组：渲染端落笔
    # ══════════════════════════════════════════════════════════════

    cases.append((
        'R1',
        '渲染端没消费 kCSFSFitNoIndent（缩进照样写出去）',
        '[FAIL] R1',
        lambda s: inject(s, '        indFirst = 0;\n',
                         '        (void)0;\n', 'R1'),
    ))

    cases.append((
        'R2',
        '没有 1pt 临界垫（差 0.2pt 的段落仍折掉最后一个字）',
        '[FAIL] R2',
        lambda s: inject(s,
                         '[pPr appendString:@"<w:ind w:right=\\"-20\\"/>"];',
                         '[pPr appendString:@""];', 'R2'),
    ))

    cases.append((
        'R3',
        '左对齐不绑 paraFitFlags（标题 center 被覆盖）',
        '[FAIL] R3',
        lambda s: inject(
            s,
            'if ((paraFitFlags & kCSFSFitLeft) && '
            '[align isKindOfClass:[NSString class]] &&',
            'if ([align isKindOfClass:[NSString class]] &&',
            'R3'),
    ))

    # ══════════════════════════════════════════════════════════════
    bad = 0
    for tag, desc, expect, fn in cases:
        mutated = fn(orig)
        if mutated is None:
            # 静默失败最要命：计数 +1 却没有一行输出
            print('  [BAD ] %s %s —— 注入函数返回 None'
                  '（锚点没命中 / 前置条件不成立），用例失效' % (tag, desc))
            bad += 1
            continue
        if mutated == orig:
            print('  [BAD ] %s 注入后源码未变化 —— 用例本身失效' % tag)
            bad += 1
            continue
        rc, out = run_check(mutated)
        hit = (rc != 0 and expect in out)
        if hit:
            line = [l for l in out.splitlines() if expect in l]
            print('  [HIT ] %s %s' % (tag, desc))
            print('         → %s' % (line[0].strip()[:150] if line else expect))
        else:
            bad += 1
            print('  [MISS] %s %s —— 注入后检查器没报出预期缺陷' % (tag, desc))
            print('         期望包含：%s' % expect)
            print('         实际输出：')
            for l in out.splitlines():
                if '[FAIL]' in l or 'OK ' in l:
                    print('           ' + l.strip()[:150])

    print()
    print('=' * 66)
    total = len(cases)
    print('反向验证：%d/%d 命中' % (total - bad, total))
    if bad:
        print('有 %d 条用例未命中 —— 对应判据是假绿，必须重写' % bad)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
