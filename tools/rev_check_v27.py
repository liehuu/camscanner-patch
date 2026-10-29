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

    # 1) 复现 v25 原始缺陷：任意一个来源改成「命中即 return」
    cases.append((
        'F1 来源短路（v25 原样）',
        lambda t: inject('F1', t,
                         '        gotModel = CSFSPullOptions(mp, @"currentAIEditModel.ocrPage");',
                         '        if (CSFSPullOptions(mp, @"currentAIEditModel.ocrPage")) return;'),
        '后面的来源成为死代码'))

    # 2) 返回值不留变量（只有调用、没人接结果 → 无法判断这份来源跑没跑过）
    cases.append((
        'F2 返回值不留变量',
        lambda t: inject('F2', t,
                         '        gotModel = CSFSPullOptions(mp, @"currentAIEditModel.ocrPage");',
                         '        CSFSPullOptions(mp, @"currentAIEditModel.ocrPage");'),
        '把返回值落进了变量'))

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
    #
    # 这里的定位串也不能绑版本号：v27 写的是 "v27 opts: FINAL hideWritten="，
    # v28 变成了 "v28 opts: ..."。按 check_v27 的 F4 判据（FINAL hideWritten=）
    # 去找，才不会升一次版本就报「找不到 FINAL 日志串」而整例失效。
    def inj_f4(t):
        i = t.find('FINAL hideWritten=')
        if i < 0:
            print('[FAIL] F4: 找不到 FINAL 日志串')
            return None
        j = t.find(');', i)
        if j < 0:
            return None
        return t[:i] + 'done"' + t[j:]
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