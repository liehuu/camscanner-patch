#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rev_check_v35 —— 对 check_v35 做缺陷注入反向验证

v35 判的全是「结构关系」，比 v34 更容易写成假绿：
  · 「调用排在 pPr 之前」—— 用 start() 比位置，若两处都取不到就永远绿
  · 「NBSP 只用于段尾」—— 条件里含 emitAtTail，但 emitAtTail 本身可以是常量
  · 「个数折半」—— (x+1)/2 这种式子在任何地方出现都会命中
  · 「压留白只在 5% 以内」—— 阈值写在哪一步都可能被别的 <= 满足

所以每个用例都写成**真机上会出现的半成品形态**，不是为判据定制的字符串。

规则（与 rev_check_v31~v34 一致）：
  · 注入后 check_v35 必须变红，且报出的必须是**这一条**判据；
  · 锚点命中数不是 1 就算用例失效（说明源码改过，锚点要更新）；
  · 注入后源码没变化也算失败。

跑法：python3 tools/rev_check_v35.py
"""

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src', 'CamScannerSaveToFiles.m')
CHECK = os.path.join(HERE, 'check_v35.py')


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
        print('基线不绿，先修 check_v35 本身：')
        print(out)
        return 1
    print('基线：原始源码 check_v35 全绿\n')

    cases = []

    # ══════════════════════════════════════════════════════════════
    # O 组：结构顺序
    # ══════════════════════════════════════════════════════════════

    # R1 把 run 级修正挪回 pPr 之后（= v34 的实际形态）
    cases.append((
        'R1',
        'run 级修正挪回 <w:pPr> 之后（左对齐结论写不进 jc）',
        '[FAIL] O1',
        lambda s: inject(s,
                         '    int paraFitFlags = 0;\n'
                         '    if (runsOK) {\n'
                         '        paraFitFlags = CSFSFixSpaceRuns((NSMutableArray *)runs, paraPt, fitIndentTw);\n'
                         '    }\n',
                         '    int paraFitFlags = 0;\n',
                         'R1'),
    ))

    # R1b 挪到 pPr 之后（保留调用，只是位置错）
    cases.append((
        'R1b',
        '保留调用但插到 <w:pPr> 输出之后',
        '[FAIL] O1',
        lambda s: inject(s,
                         '    if (pPr.length > 0) {\n'
                         '        [out appendFormat:@"<w:pPr>%@</w:pPr>", pPr];\n'
                         '    }\n',
                         '    if (pPr.length > 0) {\n'
                         '        [out appendFormat:@"<w:pPr>%@</w:pPr>", pPr];\n'
                         '    }\n'
                         '    CSFSFixSpaceRuns((NSMutableArray *)runs, paraPt, fitIndentTw);\n',
                         'R1b'),
    ))

    # R2 重复调用（第二次会把压过的空白再压一遍）
    cases.append((
        'R2',
        'CSFSFixSpaceRuns 被调用两次',
        '[FAIL] O2',
        lambda s: inject(s,
                         '    if (pPr.length > 0) {\n'
                         '        [out appendFormat:@"<w:pPr>%@</w:pPr>", pPr];\n'
                         '    }\n',
                         '    if (pPr.length > 0) {\n'
                         '        [out appendFormat:@"<w:pPr>%@</w:pPr>", pPr];\n'
                         '    }\n'
                         '    (void)CSFSFixSpaceRuns((NSMutableArray *)runs, paraPt, fitIndentTw);\n',
                         'R2'),
    ))

    # ══════════════════════════════════════════════════════════════
    # F 组：字体统一
    # ══════════════════════════════════════════════════════════════

    # R3 文字 run 分支整段删掉（只修空白 = v34 的形态）
    cases.append((
        'R3',
        '删掉文字 run 的字体统一（只修空白 = v34 形态）',
        '[FAIL] F1',
        lambda s: inject(s,
                         '        if (!CSFSIsPureWhiteSpace(t)) {\n'
                         '            NSString *tf = [r objectForKey:kCSFSRunFace];\n',
                         '        if (!CSFSIsPureWhiteSpace(t) && 0) {\n'
                         '            NSString *tf = [r objectForKey:kCSFSRunFace];\n',
                         'R3'),
    ))

    # R4 判出来了却没写回
    cases.append((
        'R4',
        '文字 run 判出字体却没写回（算了不用）',
        '[FAIL] F1',
        lambda s: inject(s,
                         '                [r setObject:wideFace forKey:kCSFSRunFace];\n'
                         '                textFaceFix++;\n',
                         '                (void)wideFace;\n'
                         '                textFaceFix++;\n',
                         'R4'),
    ))

    # R5 文字判据退回「为空才处理」
    cases.append((
        'R5',
        '文字 run 判据退回「face 为空才处理」',
        '[FAIL] F2',
        lambda s: inject(s,
                         '            if (!CSFSIsCJKFace(tf)) {',
                         '            if (tf.length == 0) {',
                         'R5'),
    ))

    # ══════════════════════════════════════════════════════════════
    # N 组：NBSP
    # ══════════════════════════════════════════════════════════════

    # R6 去掉段尾限定（= v33/v34 形态，行中也是 NBSP）
    cases.append((
        'R6',
        'NBSP 条件去掉段尾限定（行中也变不可断块）',
        '[FAIL] N1',
        lambda s: inject(s,
                         '        if (emitIsSpace && emitUnder && emitAtTail && emitText.length > 0) {',
                         '        if (emitIsSpace && emitUnder && emitText.length > 0) {',
                         'R6'),
    ))

    # R7 不折半（NBSP 宽度翻倍）
    cases.append((
        'R7',
        'NBSP 个数不折半（宽度翻倍）',
        '[FAIL] N2',
        lambda s: inject(s,
                         '            NSUInteger nbCount = (tn + 1) / 2;     // 每 2 个普通空格 = 1 个 NBSP',
                         '            NSUInteger nbCount = tn;              // 逐个替换',
                         'R7'),
    ))

    # R8 多出一处 NBSP 字面量（行中也会漏出去）
    cases.append((
        'R8',
        '多一处 NBSP 字面量（行中空白也被换掉）',
        '[FAIL] N3',
        lambda s: inject(s,
                         '        NSString *emitText = text;\n',
                         '        NSString *emitText = text;\n'
                         '        if (CSFSIsPureWhiteSpace(text) && text.length > 0) {\n'
                         '            emitText = [text stringByReplacingOccurrencesOfString:@" " withString:@"\\u00A0"];\n'
                         '        }\n',
                         'R8'),
    ))

    # ══════════════════════════════════════════════════════════════
    # T 组：段尾留白
    # ══════════════════════════════════════════════════════════════

    # R9 不标记段尾
    cases.append((
        'R9',
        '不标记段尾空白（自适应与 NBSP 都失效）',
        '[FAIL] T1',
        lambda s: inject(s,
                         '                [lr setObject:[NSNumber numberWithBool:YES] forKey:kCSFSRunTail];\n',
                         '                (void)lr;\n',
                         'R9'),
    ))

    # R10 tailDrop 只按位置判（会删掉段尾填空线）
    cases.append((
        'R10',
        'tailDrop 不看下划线（段尾填空线被整条删掉）',
        '[FAIL] T2',
        lambda s: inject(s,
                         '        if (!ws || (und && [ct isKindOfClass:[NSString class]] && ct.length > 0)) {',
                         '        if (!ws) {',
                         'R10'),
    ))

    # R11 段尾不自适应
    cases.append((
        'R11',
        '段尾留白不按剩余宽度自适应',
        '[FAIL] T3',
        lambda s: inject(s,
                         '        double room = avail - noTail;',
                         '        double room = 0.0;',
                         'R11'),
    ))

    # ══════════════════════════════════════════════════════════════
    # B 组：tab 去重
    # ══════════════════════════════════════════════════════════════

    # R12 不删重复 tab
    cases.append((
        'R12',
        '不删与空白重复的 tab（整行被顶爆）',
        '[FAIL] B1',
        lambda s: inject(s,
                         '            [r setObject:[NSNumber numberWithBool:NO] forKey:kCSFSRunTab];\n',
                         '            [r setObject:[NSNumber numberWithBool:YES] forKey:kCSFSRunTab];\n',
                         'R12'),
    ))

    # ══════════════════════════════════════════════════════════════
    # W 组：宽度预算
    # ══════════════════════════════════════════════════════════════

    # R13 估算系数离谱
    cases.append((
        'R13',
        '估算系数改成 2.0（全部误判为超宽）',
        '[FAIL] W1',
        lambda s: inject(s,
                         '    return w * 1.06;',
                         '    return w * 2.00;',
                         'R13'),
    ))

    # R14 空白不用 slice.width
    cases.append((
        'R14',
        '空白 run 不用 slice.width（退回按字符数估）',
        '[FAIL] W1b',
        lambda s: inject(s,
                         '    if (CSFSIsPureWhiteSpace(t) && sw > 0.0) return sw;',
                         '    if (0) return sw;',
                         'R14'),
    ))

    # R15 去掉「差 5% 压留白」分支
    cases.append((
        'R15',
        '去掉「差 5% 压留白挤进一行」',
        '[FAIL] W2',
        lambda s: inject(s,
                         '    if (total <= avail * 1.05 && spaceSum > 1.0) {',
                         '    if (0 && spaceSum > 1.0) {',
                         'R15'),
    ))

    # R16 去掉「差得多走左对齐」分支
    cases.append((
        'R16',
        '去掉「差得多走左对齐」分支',
        '[FAIL] W3',
        lambda s: inject(s,
                         '    CSFS_LOG(@"v35 overflow: total=%.1f avail=%.1f rem=%.1f left=%d",\n',
                         '    CSFS_LOG(@"v35 overrun: total=%.1f avail=%.1f rem=%.1f left=%d",\n',
                         'R16'),
    ))

    # R17 左对齐无差别覆盖（会把标题也改成左对齐）
    cases.append((
        'R17',
        '左对齐无差别覆盖 jc（标题被拉回左边）',
        '[FAIL] W4',
        lambda s: inject(s,
                         '        [(NSString *)align isEqualToString:@"both"]) {\n'
                         '        align = @"left";',
                         '        [(NSString *)align isEqualToString:@"__none__"]) {\n'
                         '        align = @"left";',
                         'R17'),
    ))

    # ══════════════════════════════════════════════════════════════
    # C 组：标题
    # ══════════════════════════════════════════════════════════════

    # R18 标题阈值离谱（把正文也当标题）
    cases.append((
        'R18',
        '标题字号阈值降到 0.1 倍（正文全被居中）',
        '[FAIL] C1',
        lambda s: inject(s,
                         '                if (s0 > defaultPt * 1.5 && s0 < 200.0) {',
                         '                if (s0 > defaultPt * 0.1 && s0 < 200.0) {',
                         'R18'),
    ))

    # R19 算出居中却没用
    cases.append((
        'R19',
        '判出标题却不改 jc（照样贴右边）',
        '[FAIL] C1',
        lambda s: inject(s,
                         '                    align = @"center";\n',
                         '                    (void)0;\n',
                         'R19'),
    ))

    bad = 0
    for tag, desc, expect, fn in cases:
        mutated = fn(orig)
        if mutated is None:
            # 静默失败最要命：计数 +1 却没有一行输出，看日志只看到
            # 「19/20」却不知道是哪条挂了（本项目栽过多次）。
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
