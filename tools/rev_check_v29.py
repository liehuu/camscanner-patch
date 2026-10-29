#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_v29.py 的注入式反向验证。

每条注入的都是**真实发生过的缺陷形态**，不是假设性构造：

  M1 → 名字表里删掉少 n 的 hideWritteImage
       这正是 v24～v28 的实际状态：只认完整拼写，落在 Manager 上恒为 nil。
  M2 → 删掉 CSImageToJsonManager 单例获取
       这是 v24～v28 的实际做法：从没看过这个对象。
  M3 → 把 Manager 来源挪到 currentAIEditModel 之后
       v28 的真实顺序，读的是那个只在点过 AI 美化后才非 nil 的对象。
  M4 → setter 硬编码，不派生
       典型手滑：加兼容拼写时只改表不改逻辑，两处拼写各自漂移。
  M5 → gCSFSHideWritten 直接赋值
       后一份同步落后的 NO 会把 Manager 的 YES 抹掉，退回「勾了跟没勾一样」。

expect 一律用**失败文案独有**的片段，不用 'M1' 这种：
OK 行里也有 M1，用 in 判断永远成立 —— 那是注定通过的假断言。
"""

import io
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src', 'CamScannerSaveToFiles.m')
CHECK = os.path.join(HERE, 'check_v29.py')


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
    for need in ('kCSFSMgrHideWritten',
                 'CSFSImageToJsonManager',
                 'CSFSWriteBoolTo',
                 'CSFSReadOptionsFromBottomView'):
        if need not in base:
            print('[FAIL] 基线里找不到 %s，源码版本不对' % need)
            return 1

    out, rc = run_on(base)
    if rc != 0:
        print('[FAIL] 基线未通过，先修源码：\n' + out[-900:])
        return 1
    print('[ OK ] 基线通过')

    cases = []

    # 1) 删掉少 n 的真名 —— v24～v28 的实际状态
    #
    # 注入时不能带前导空格：真实源码里是
    #     static const char *kCSFSMgrHideWritten[] = { "hideWritteImage", ... };
    # 第一版把 '{' 直接顶在第 4 个字符，实际源码那行前面还有
    # `kCSFSMgrHideWritten[] = `，所以 '{...}' 那段字面量匹配不上。
    cases.append((
        'M1 名字表丢少 n 的真名',
        lambda t: inject('M1', t,
                         '= { "hideWritteImage", "hideWrittenImage", NULL };',
                         '= { "hideWrittenImage", NULL };'),
        '缺 hideWritteImage（少一个 n 的那个）'))

    # 1b) 反过来：只留少 n 的，丢掉完整拼写
    cases.append((
        'M1b 名字表丢完整拼写',
        lambda t: inject('M1b', t,
                         '= { "hideWritteImage", "hideWrittenImage", NULL };',
                         '= { "hideWritteImage", NULL };'),
        '缺完整拼写 hideWrittenImage'))

    # 2) 不获取 Manager 单例 —— 前五轮的实际做法
    def inj_m2(t):
        # 把整个 Manager 分支的调用点换成一个永远返回 nil 的写法等价物：
        # 最贴近真实改法的是让函数体里不再出现 CSFSImageToJsonManager()
        t = t.replace('id mgr = CSFSImageToJsonManager();',
                      'id mgr = nil; /* 不再看 Manager */', 1)
        return t
    cases.append(('M2 不看 Manager 单例', inj_m2,
                  '没有获取 CSImageToJsonManager 单例'))

    # 3) 顺序退回 v28：model 在前
    def inj_m3(t):
        i = t.find('id mgr = CSFSImageToJsonManager();')
        if i < 0:
            print('[FAIL] M3: 找不到 Manager 调用点')
            return None
        # 在 model 分支之后插入一行同名单例获取，制造「Manager 在后」
        j = t.find('gotModel = CSFSPullOptions(mp,', i)
        if j < 0:
            print('[FAIL] M3: 找不到 model 分支')
            return None
        # 把 Manager 那行搬到 model 之后：先删再插
        t2 = t[:i] + t[i:].replace('id mgr = CSFSImageToJsonManager();',
                                   '', 1)
        k = t2.find('gotModel = CSFSPullOptions(mp,')
        k2 = t2.find('\n', k)
        return t2[:k2 + 1] + '    id mgr = CSFSImageToJsonManager();\n' + t2[k2 + 1:]
    cases.append(('M3 Manager 顺序掉到 model 之后', inj_m3,
                  '顺序掉了就等于又先去读那个只在点过 AI 美化后才非 nil 的对象'))

    # 4) setter 硬编码
    cases.append((
        'M4 setter 不派生、硬编码',
        lambda t: inject('M4', t,
                         'NSString *setterName = [NSString stringWithFormat:@"set%@%@:",',
                         'NSString *setterName = [NSString stringWithFormat:@"setHideWritteImage%@%@",'),
        '没有按 getter 名派生 setter 名'))

    # 4b) 派生但忘首字母大写
    cases.append((
        'M4b 派生忘大写',
        lambda t: inject('M4b', t,
                         '[[getter substringToIndex:1] uppercaseString]',
                         '[getter substringToIndex:1]'),
        '没做首字母大写'))

    # 5) OR 退化成直接赋值
    cases.append((
        'M5 hide* 直接赋值覆盖',
        lambda t: inject('M5', t,
                         'if (mw) gCSFSHideWritten = YES;',
                         'gCSFSHideWritten = mw;'),
        '被直接赋成了某个来源的值'))

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
                  % (name, expect, rc, out[-600:]))

    print('\n注入 %d 例，精确命中 %d 例' % (len(cases), passed))
    return 0 if passed == len(cases) else 1


if __name__ == '__main__':
    sys.exit(main())