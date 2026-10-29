# -*- coding: utf-8 -*-
"""
v24 检查器的注入式反向验证。

每条检查都要往里注入一个**真实会发生的缺陷形态**，
确认它能精确报出对应那条。没做过反向验证的检查等于没有。

expect 用的是「失败文案独有的片段」，不能用 'E1' 这种：
OK 行里也有 E1，用 in 判断会永远成立 —— 那就是一条注定通过的假断言，
这个坑在 v23 已经踩过两次。
"""
import io
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src', 'CamScannerSaveToFiles.m')
CHECK = os.path.join(HERE, 'check_v24.py')


def run_on(text):
    fd, tmp = tempfile.mkstemp(suffix='.m', dir=ROOT)
    os.close(fd)
    try:
        io.open(tmp, 'w', encoding='utf-8').write(text)
        r = subprocess.run([sys.executable, CHECK, tmp],
                           capture_output=True, text=True)
        return (r.stdout or '') + (r.stderr or ''), r.returncode
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def inject(name, text, old, new):
    if old not in text:
        print('[FAIL] %s: 注入目标串没找到，用例本身失效' % name)
        return None
    t = text.replace(old, new, 1)
    if t == text:
        print('[FAIL] %s: 替换后内容未变' % name)
        return None
    return t


def main():
    base = io.open(SRC, encoding='utf-8').read()
    # 基线判据不能绑版本号（曾写死 'v24 stats: optKnown='，升到 v27 就假 FAIL）。
    # 改为要求 check_v24 真正依赖的那几个实质特征存在。
    for need in ('optKnown=', 'hideWritten=', 'CSFSReadOptionsFromBottomView'):
        if need not in base:
            print('[FAIL] 基线里找不到 %s，源码版本不对' % need)
            return 1

    # 基线必须通过
    out, rc = run_on(base)
    if rc != 0:
        print('[FAIL] 基线未通过，先修源码：\n' + out[-800:])
        return 1
    print('[ OK ] 基线通过')

    cases = []

    # 1) 导出动作里不读开关 —— v23 的真实状态
    cases.append((
        'E1 未读面板开关',
        lambda t: inject('E1', t, '        CSFSReadOptionsFromBottomView(self);\n', ''),
        '没有调用 CSFSReadOptionsFromBottomView'))

    # 2) 漏读「手写转文字」开关
    cases.append((
        'E2 漏读 handWrittenToImage',
        lambda t: inject('E2', t, '"handWrittenToImage"', '"handWrittenToImageX"'),
        '没有读 handWrittenToImage'))

    # 3) 过滤被挪到取图之后 —— 最容易写反的一条
    cases.append((
        'E3 过滤晚于取图',
        lambda t: inject('E3', t,
                         '                                                                for (id sl in slices) {\n',
                         '                                                                for (id sl in slices) {\n'
                         '                                                                    { id probe = textWins ? nil : CSFSSliceImageInfo(sl); (void)probe; }\n'),
        '切片级过滤位置错误'))

    # 4) 不尊重块级隐藏
    cases.append((
        'E4 忽略 block.hiding',
        lambda t: inject('E4', t, 'CSFSValue(block, @"hiding")', 'CSFSValue(block, @"hidingX")'),
        '没有检查 block.hiding'))

    # 5) 不读 add_tabstop
    cases.append((
        'E6 漏读 add_tabstop',
        lambda t: inject('E6', t, '"add_tabstop"', '"add_tabstopX"'),
        '没读 add_tabstop'))

    # 6) 完全没有 tabs 模板
    cases.append((
        'E8 缺 tabs 模板',
        lambda t: inject('E8', t, 'appendString:@"<w:tabs>"', 'appendString:@"<w:tabsX>"'),
        '没有输出 <w:tabs>'))

    # 7) tabs 被挪到 ind 之后 —— 顺序型
    def inj_e8_order(t):
        tabs_line = '            [pPr appendString:@"<w:tabs>"];\n'
        t = inject('E8b-1', t, tabs_line, '')
        if t is None:
            return None
        return inject('E8b-2', t,
                      '[pPr appendFormat:@"<w:jc w:val=\\"%@\\"/>", align];',
                      '[pPr appendString:@"<w:tabs>"];\n'
                      '        [pPr appendFormat:@"<w:jc w:val=\\"%@\\"/>", align];')
    cases.append(('E8 tabs 顺序被破坏', inj_e8_order, 'CT_PPrBase 是 sequence'))

    # 8) 统计行丢了 optKnown —— 会让「没读到」和「用户没勾」长得一样
    #
    # 注入方式跟着判据走：check_v24 现在按「日志行里同时有 optKnown= 与
    # hideWritten=」认定，所以注入改成把 optKnown= 整个抹掉，
    # 而不是只改版本号前缀（后者在判据升级后已经不管用了）。
    cases.append((
        'E10 统计行缺 optKnown',
        lambda t: inject('E10', t, 'optKnown=%d', 'knownFlag=%d'),
        '没有 optKnown'))

    passed = 0
    for name, mut, expect in cases:
        t = mut(base)
        if t is None:
            continue
        out, rc = run_on(t)
        if rc != 0 and expect in out:
            print('[ OK ] %s → 精确报出「%s」' % (name, expect))
            passed += 1
        else:
            print('[FAIL] %s：期望「%s」，实际 rc=%d\n%s'
                  % (name, expect, rc, out[-500:]))

    print('\n注入 %d 例，精确命中 %d 例' % (len(cases), passed))
    return 0 if passed == len(cases) else 1


if __name__ == '__main__':
    sys.exit(main())
