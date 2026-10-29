#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rev_check_v32 —— 对 check_v32 做缺陷注入反向验证

为什么必须做这一步（本项目已四次栽在这里，写在最前面）：
一个从未被反向验证过的检查器，很可能只是「永远绿」的装饰。
check_v27 绑变量名、check_v29 的 M5 黑名单、check_v31 的 S1 正则
永不匹配、check_v31 的 R4 前缀子串 —— 全都是「写的时候觉得对、
跑起来全绿、其实一条都没抓住」。

所以本文件的规则是：
  · 每个注入的缺陷都必须是**真实可能发生的写法**（不是为判据量身定做）；
  · 注入后 check_v32 必须变红，且报出的必须是**这一条**判据；
  · 注入后源码没变化（锚点失效）也算失败 —— 那说明用例本身废了。

跑法：python3 tools/rev_check_v32.py
"""

import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src', 'CamScannerSaveToFiles.m')
CHECK = os.path.join(HERE, 'check_v32.py')


def run_check(text):
    """把变造后的源码喂给 check_v32，返回 (rc, stdout)。"""
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


def inject_all(src, old, new, tag):
    n = src.count(old)
    if n < 1:
        print('  [BAD ] %s 锚点一个都没命中 —— 用例失效，请更新锚点' % tag)
        return None
    return src.replace(old, new)


def main():
    orig = open(SRC, encoding='utf-8').read()

    rc, out = run_check(orig)
    if rc != 0:
        print('基线不绿，先修 check_v32 本身：')
        print(out)
        return 1
    print('基线：原始源码 check_v32 全绿\n')

    cases = []

    # ══════════════════════════════════════════════════════════════
    # P 组：带下划线的空格长度
    # ══════════════════════════════════════════════════════════════

    # Q1 不读 width（回到 v31 的行为：只知道有个空格，不知道它多宽）
    cases.append((
        'Q1',
        'CSFSParseSlice 不再读 slice.width',
        'P1 CSFSParseSlice 没有读 slice 的 width',
        lambda s: inject(s,
                         'double sw = CSFSDoubleValue(CSFSValue(sl, @"width"));',
                         'double sw = 0.0;',
                         'Q1'),
    ))

    # Q2 读了但没存进 run（最常见的半成品：值拿到了，忘了带走）
    cases.append((
        'Q2',
        '读到了 width 但没写进 kCSFSRunSpaceW',
        'P1 读到了 width 但没写进 kCSFSRunSpaceW',
        lambda s: inject(s,
                         'forKey:kCSFSRunSpaceW',
                         'forKey:@"sw_unused"',
                         'Q2'),
    ))

    # Q3 守卫退化成「长度不为 0」—— 于是文字 run 也会被记宽度
    #
    # 锚点必须带上 `double sw = ...`：v33 在同一个函数里新增了一处
    # `if (CSFSIsPureWhiteSpace(t))`（纯空白的 DIAG 日志），
    # 只按 if 条件注入会命中 2 次 —— 注入进去的往往是 DIAG 那一处，
    # 而真正记 width 的守卫没被改，于是用例静默失效。
    cases.append((
        'Q3',
        '守卫从「纯空白」退化成「长度不为 0」',
        'P2 记 width 的守卫里没有「纯空白」判断',
        lambda s: inject(s,
                         'if (CSFSIsPureWhiteSpace(t)) {\n'
                         '        double sw = CSFSDoubleValue(CSFSValue(sl, @"width"));',
                         'if (t.length > 0) {\n'
                         '        double sw = CSFSDoubleValue(CSFSValue(sl, @"width"));',
                         'Q3'),
    ))

    # Q4 渲染端没用展开结果（width 带进来了，却还写原始 text）
    cases.append((
        'Q4',
        '渲染端仍把原始 text 交给 CSFSXMLEscape',
        'P3 <w:t> 里写的还是原始 text',
        lambda s: inject_all(s,
                             'CSFSXMLEscape(emitText)',
                             'CSFSXMLEscape(text)',
                             'Q4'),
    ))

    # Q5 去掉上限 clamp
    cases.append((
        'Q5',
        '展开去掉上限 clamp',
        'P4 展开没有上限 clamp',
        lambda s: inject(s, 'if (n > 200) n = 200;', '', 'Q5'),
    ))

    # Q6 去掉「不许更短」保护
    cases.append((
        'Q6',
        '展开去掉「不许短于原有空白」保护',
        'P5 展开没有「不许比原有空白更短」的保护',
        lambda s: inject(s,
                         'if ((long)text.length > n) n = (long)text.length;',
                         '', 'Q6'),
    ))

    # Q7 去掉 width 不可用的兜底
    cases.append((
        'Q7',
        'width 不可用时不再原样返回（会凭空造空格）',
        'P6 width 不可用时没有原样返回',
        lambda s: inject(s, 'if (!(sliceWidthPx > 0.0)) return text;', '', 'Q7'),
    ))

    # Q8 批次重置漏清计数
    cases.append((
        'Q8',
        '批次重置漏清 gCSFSSpaceExpandRuns',
        'P7 批次重置没清 gCSFSSpaceExpandRuns',
        lambda s: inject(s, 'gCSFSSpaceExpandRuns = 0;', '', 'Q8'),
    ))

    # ══════════════════════════════════════════════════════════════
    # H 组：去除手写
    # ══════════════════════════════════════════════════════════════

    # Q9 —— 这是 v31 的真实形态：「有识别文字就保留」
    #    对 stype=handwritten 的那 33 条（全部 hasText=1）会全部 KEEP，
    #    于是手写开关彻底失效。必须被抓到。
    cases.append((
        'Q9',
        '恢复 v31 的「有文字就保留」旁路（手写开关失效）',
        'H1 勾了「去除手写」，但 stype=handwritten 且有识别文字的 slice',
        lambda s: inject(s,
                         'BOOL looksHW = (catSaysHW || stypeSaysHW);',
                         'BOOL looksHW = (catSaysHW || stypeSaysHW)'
                         ' && !hasTextHW;',
                         'Q9'),
    ))

    # Q10 只认 image_category（改成 v31 的另一半：slCat==1）
    cases.append((
        'Q10',
        '判据只认 image_category（丢掉 stype）',
        'H1 勾了「去除手写」，但 stype=handwritten 且有识别文字的 slice',
        lambda s: inject(s,
                         'BOOL looksHW = (catSaysHW || stypeSaysHW);',
                         'BOOL looksHW = catSaysHW;',
                         'Q10'),
    ))

    # Q11 没勾也删 —— v27 OR 残留那类「选不选都删」
    cases.append((
        'Q11',
        '外层条件加 `|| YES`（没勾也删）',
        'H3 没勾「去除手写」时仍有 continue 会执行',
        lambda s: inject(s,
                         'if (gCSFSHideWritten) {',
                         'if (gCSFSHideWritten || YES) {',
                         'Q11'),
    ))

    # Q12 判据命中数只留名字、不留计数（日志永远 handHW=0）
    cases.append((
        'Q12',
        '删掉 handHWCount 的自增（日志永远报 0）',
        'H4 handHWCount 从头到尾没有自增',
        lambda s: inject(s, 'handHWCount++;', '', 'Q12'),
    ))

    bad = 0
    for tag, desc, expect, fn in cases:
        mutated = fn(orig)
        if mutated is None:
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

    # ══════════════════════════════════════════════════════════════
    # E 组：求值器自检
    # ══════════════════════════════════════════════════════════════
    #
    # H 组全靠「把条件真的算一遍」。如果求值器本身就坏，
    # H1/H2/H3 会一起失真 —— 而且失真的方向可能是「全绿」。
    # 所以这里单独验证它：算得出真、算得出假、算不出来的时候会抛异常
    # （而不是悄悄返回 False，那会把「翻不动」伪装成「不会删」）。
    print('\n--- E 组：条件求值器自检 ---')
    sys.path.insert(0, HERE)
    import importlib
    cv32 = importlib.import_module('check_v32')

    defs = {'looksHW': '(catSaysHW || stypeSaysHW)'}

    # E1：cat=0 / stype=handwrit → 展开后应为 True（会删）
    try:
        c = cv32.expand_defs('looksHW', defs, cv32.SC_HW_TEXT)
        py = cv32.cond_to_py(c, cv32.SC_HW_TEXT)
        v = bool(eval(py, {'__builtins__': {}}, {}))
        if v:
            print('  [HIT ] E1 looksHW 在「cat=0 / stype=handwrit」下算得 True')
        else:
            bad += 1
            print('  [MISS] E1 算成 False（py=%s）—— H1 会永远红/永远绿' % py)
    except Exception as e:
        bad += 1
        print('  [BAD ] E1 求值抛异常：%r' % e)

    # E2：cat=0 / stype 不命中 → 应为 False（不删）
    try:
        sc = dict(cv32.SC_HW_TEXT)
        sc['stypeSaysHW'] = False
        sc['HWMSG'] = False
        c = cv32.expand_defs('looksHW', defs, sc)
        py = cv32.cond_to_py(c, sc)
        v = bool(eval(py, {'__builtins__': {}}, {}))
        if not v:
            print('  [HIT ] E2 两个判据都不命中时算得 False（不是恒真）')
        else:
            bad += 1
            print('  [MISS] E2 算成 True —— 求值器恒真，H1~H3 全是假结论')
    except Exception as e:
        bad += 1
        print('  [BAD ] E2 求值抛异常：%r' % e)

    # E3：无法解析的标识符必须**抛异常**，不能悄悄当作 False
    try:
        cv32.evaluates_true(['someUnknownVar'], cv32.SC_OFF, {})
        bad += 1
        print('  [MISS] E3 未知标识符没有抛异常 —— 求值失败会被伪装成'
              '「不会删」，H3 于是会假通过')
    except Exception:
        print('  [HIT ] E3 未知标识符会抛异常（不会把「翻不动」伪装成「不删」）')

    total = len(cases) + 3
    print('\n反向验证：%d/%d 命中' % (total - bad, total))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
