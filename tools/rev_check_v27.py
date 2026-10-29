# -*- coding: utf-8 -*-
"""
check_v27.py 的注入式反向验证。

每一条都注入**真实发生过的缺陷形态**，不做假设性构造：

  G1 → v25 的原始写法 `if (CSFSPullOptions(...)) return;`（短路，后面成为死代码）
  G2 → 返回值不留变量，直接 if 判断
  G3 → 把 OR 合并改回「直接赋值」（后一份 NO 覆盖前一份 YES）
  G4 → 抹掉 FINAL 汇总日志

expect 一律用**失败文案独有**的片段，不用 'G1' 这种：
OK 行里也有 G1，用 in 判断永远成立 —— 那是注定通过的假断言。
"""

import io
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src', 'CamScannerSaveToFiles.m')
CHECK = os.path.join(HERE, 'check_v27.py')


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
    for need in ('CSFSReadOptionsFromBottomView',
                 'CSFSPullOptions',
                 'gCSFSHideWritten = YES'):
        if need not in base:
            print('[FAIL] 基线里找不到 %s，源码版本不对' % need)
            return 1

    out, rc = run_on(base)
    if rc != 0:
        print('[FAIL] 基线未通过，先修源码：\n' + out[-800:])
        return 1
    print('[ OK ] 基线通过')

    cases = []

    # 1) 复现 v25 原始缺陷：三个来源里任意一个改成「命中即 return」
    cases.append((
        'F1 来源短路（v25 原样）',
        lambda t: inject('F1', t,
                         '    BOOL got1 = CSFSPullOptions(CSFSValue(bottomView, @"originalData"), @"bottomView.originalData");',
                         '    if (CSFSPullOptions(CSFSValue(bottomView, @"originalData"), @"bottomView.originalData")) return;'),
        '后面的来源成为死代码'))

    # 2) 返回值不留变量
    def inj_f2(t):
        t = inject('F2-1', t,
                   '    BOOL got1 = CSFSPullOptions(',
                   '    CSFSPullOptions(')
        if t is None:
            return None
        t = inject('F2-2', t,
                   '        got2 = CSFSPullOptions(',
                   '        CSFSPullOptions(')
        if t is None:
            return None
        return inject('F2-3', t,
                      '    BOOL got3 = CSFSPullOptions(',
                      '    CSFSPullOptions(')
    cases.append(('F2 返回值不留变量', inj_f2, '返回值没被保留'))

    # 3) OR 合并退化成直接赋值（后一份覆盖前一份）
    cases.append((
        'F3 直接赋值覆盖',
        lambda t: inject('F3', t,
                         '        if (w) gCSFSHideWritten = YES;',
                         '        gCSFSHideWritten = hw;'),
        '会把前一份的 YES 覆盖掉'))

    # 3b) handToImage 被误用 OR —— 语义方向相反，会把「手写转文字」永久压成 YES
    cases.append((
        'F3b handToImage 误用 OR',
        lambda t: inject('F3b', t,
                         '        if (hi) {\n            gCSFSHandToImage   = h;',
                         '        if (h) {\n            gCSFSHandToImage   = YES;'),
        '语义与 hide* 相反，不能取 OR'))

    # 4) 去掉 FINAL 汇总日志
    def inj_f4(t):
        i = t.find('"v27 opts: FINAL hideWritten=')
        if i < 0:
            print('[FAIL] F4: 找不到 FINAL 日志串')
            return None
        j = t.find(');', i)
        if j < 0:
            return None
        return t[:i] + '"v27 opts: done"' + t[j:]
    cases.append(('F4 缺 FINAL 汇总日志', inj_f4, '合并结果不可观测'))

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