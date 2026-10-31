#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rev_check_final —— 对 check_final 做缺陷注入反向验证

每条用例都还原成「真发生过 / 真会发生」的形态，而不是为了让它变红随便塞一行：

  I1  诊断 dump 复活（开发期最常干的事：出问题就加一条 DIAG）
  I2  崩溃取证复活（闪退一出现，第一反应就是加 CrashTrace）
  I3  启动自证 toast 复活（装完想确认加载成功，最容易临时加回来）
  I4  诊断出参复活（把 &diagDone 加回去，源码里看不出是诊断，但结构就是诊断）
  I5  死代码复活（删了调用点没删函数）
  I6  版本横幅忘记改（装完分不清哪一版）
  I7  连日志框架一起删（「去诊断」删过头，排障断路）
  I8  页边距被顺手改回 1440（删代码时误伤 v37 成果）
  I9  版心常量与页边距不同源（只改一半）
  I10 诊断开关变量残留（删了日志留着开关）

规则与 rev_check_v31~v37 一致：
  · 注入后 check_final 必须变红，且报出的必须是**这一条**判据；
  · 锚点命中数不是 1 就算用例失效（用例本身要维护）；
  · 注入函数返回 None 时**必须打印**，否则「9/10」看不出是哪条挂了。

允许连带变红：I8 必然同时打红 V3（页边距与常量不同源）—— 我们验证的是
「注入后这一条会报」，不是「只有这一条会报」。

跑法：python3 tools/rev_check_final.py
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src', 'CamScannerSaveToFiles.m')
CHECK = os.path.join(HERE, 'check_final.py')


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
        print('基线不绿，先修 check_final 本身：')
        print(out)
        return 1
    print('基线：原始源码 check_final 全绿\n')

    cases = []

    # ── I1 诊断 dump 复活 ────────────────────────────────────────
    cases.append((
        'I1',
        '结构勘探 dump 复活',
        'F1 仍有结构勘探 dump',
        lambda s: inject(
            s,
            '    id style = CSFSValue(sl, @"style");',
            '    id style = CSFSValue(sl, @"style");\n'
            '    CSFS_LOG(@"v21 DIAG slice %@", sl);',
            'I1'),
    ))

    # ── I2 崩溃取证复活 ─────────────────────────────────────────
    cases.append((
        'I2',
        '崩溃取证 CSFSCrashTrace 复活',
        'F2 仍有崩溃取证',
        lambda s: inject(
            s,
            'static void CSFSLogToFile(NSString *msg) {',
            'static void CSFSCrashTrace(const char *tag) { (void)tag; }\n'
            'static void CSFSLogToFile(NSString *msg) {',
            'I2'),
    ))

    # ── I3 启动自证 toast 复活 ───────────────────────────────────
    cases.append((
        'I3',
        '启动自证 toast 复活',
        'F3 仍有启动自证 toast',
        lambda s: inject(
            s,
            '        CSFSInstall();\n        if (!gCSFSInstalled) {',
            '        CSFSShowLoadedBanner();\n'
            '        CSFSInstall();\n        if (!gCSFSInstalled) {',
            'I3'),
    ))

    # ── I4 诊断出参复活 ─────────────────────────────────────────
    cases.append((
        'I4',
        '诊断出参 BOOL * 复活',
        'F4 CSFSParseSlice 仍带诊断指针参数',
        lambda s: inject(
            s,
            'static NSMutableDictionary *CSFSParseSlice(id sl) {',
            'static NSMutableDictionary *CSFSParseSlice(id sl, BOOL *diagOut) {\n'
            '    if (diagOut) *diagOut = NO;',
            'I4'),
    ))

    # ── I5 死代码复活 ───────────────────────────────────────────
    cases.append((
        'I5',
        '死代码 CSFSDescribeDeep 复活',
        'F5 死代码仍在',
        lambda s: inject(
            s,
            'static NSMutableDictionary *CSFSParseSlice(id sl) {',
            'static NSString *CSFSDescribeDeep(id o, int d) { return @"(nil)"; }\n'
            'static NSMutableDictionary *CSFSParseSlice(id sl) {',
            'I5'),
    ))

    # ── I6 版本横幅忘记改 ───────────────────────────────────────
    cases.append((
        'I6',
        '版本横幅退回 v5（分不清装的是哪版）',
        'F6 版本横幅不是终版标识',
        lambda s: inject(
            s,
            'CSFS_LOG(@"CamScannerSaveToFiles v37 final loaded (build %s %s)"',
            'CSFS_LOG(@"CamScannerSaveToFiles v5 loaded (build %s %s)"',
            'I6'),
    ))

    # ── I7 日志框架被删过头 ─────────────────────────────────────
    cases.append((
        'I7',
        'CSFS_LOG 宏被删（排障断路）',
        'V1 CSFS_LOG 框架被删了',
        lambda s: inject(
            s,
            '#define CSFS_LOG(',
            '#define CSFS_LOGX(',
            'I7'),
    ))

    # ── I8 页边距被改回 1440 ────────────────────────────────────
    # ⚠ 锚点必须是源码里的字面形态：XML 在 @"…" 里，引号带反斜杠转义
    cases.append((
        'I8',
        '页边距被改回 1440（误伤 v37 版心成果）',
        'V2 页边距不是 800',
        lambda s: inject(
            s,
            r'w:right=\"800\"',
            r'w:right=\"1440\"',
            'I8'),
    ))

    # ── I9 常量与页边距不同源 ───────────────────────────────────
    cases.append((
        'I9',
        '版心常量改回 9026（只改一半）',
        'V3 版心常量不是 10306.0',
        lambda s: inject(
            s,
            'static const double kCSFSContentTwips = 10306.0;',
            'static const double kCSFSContentTwips = 9026.0;',
            'I9'),
    ))

    # ── I10 诊断开关变量残留 ────────────────────────────────────
    cases.append((
        'I10',
        '诊断开关变量残留',
        'V5 诊断开关变量残留',
        lambda s: inject(
            s,
            'NSMutableArray *styledParas = [NSMutableArray array];',
            'NSMutableArray *styledParas = [NSMutableArray array];\n'
            '                                    BOOL paraDiagDone = NO;',
            'I10'),
    ))

    hit = 0
    bad = 0
    for tag, desc, expect, fn in cases:
        print('─' * 66)
        print('[%s] %s' % (tag, desc))
        mutated = fn(orig)
        if mutated is None:
            bad += 1
            continue
        rc, out = run_check(mutated)
        if rc == 0:
            print('  [MISS] 注入后仍然全绿 —— 这条判据是装饰，没有检查能力')
            bad += 1
            continue
        if expect in out:
            print('  [HIT ] → 报出预期判据：%s' % expect)
            hit += 1
        else:
            print('  [MISS] 变红了，但报的不是这一条（期望 %s）' % expect)
            for line in out.splitlines():
                if '[FAIL]' in line:
                    print('        实际：%s' % line.strip())
            bad += 1

    print('=' * 66)
    print('反向验证：%d/%d 命中' % (hit, len(cases)))
    if bad:
        print('失效用例 %d 个 —— 反向验证不完整' % bad)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
