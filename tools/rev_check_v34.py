#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rev_check_v34 —— 对 check_v34 做缺陷注入反向验证

为什么必须做这一步（本项目已经反复栽在这里）：
check_v31 的 S1 正则永不匹配、R4 前缀子串假通过、
check_v32 的 H 块取错对象全绿、check_v33 的 U4 被函数开头的赋值满足 ——
每一次都是「判据写出来觉得对、跑起来全绿、其实一条都没抓住」。

v34 要判的东西尤其容易写成假绿，因为全是「有没有做某件事」：
  · 「字体判据是不是 CSFSIsCJKFace」—— 函数里还有一处
    `if (!CSFSIsCJKFace(gCSFSBodyFace))`，正则写松了就永远命中
  · 「有没有覆盖字体」—— 只 grep setObject:...kCSFSRunFace 不够，
    还得确认写进去的是从 gCSFSBodyFace 派生的那个变量
  · 「spacing 排在 sz 之前」—— 源码里 <w:sz 出现在多处，
    必须限定在 CSFSRenderPara 体内比对位置
  · 「spacing 值来自 spTw」—— 允许过一手 spInt，但那一手必须是纯派生

所以每个用例都写成**真机上会出现的半成品形态**，不是为判据定制的字符串。

规则（与前几版一致）：
  · 注入后 check_v34 必须变红，且报出的必须是**这一条**判据；
  · 锚点命中数不是 1 就算用例失效（说明源码改过，锚点要更新）；
  · 注入后源码没变化也算失败。

跑法：python3 tools/rev_check_v34.py
"""

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src', 'CamScannerSaveToFiles.m')
CHECK = os.path.join(HERE, 'check_v34.py')


def run_check(text):
    """把变造后的源码喂给 check_v34，返回 (rc, stdout)。"""
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
        print('基线不绿，先修 check_v34 本身：')
        print(out)
        return 1
    print('基线：原始源码 check_v34 全绿\n')

    cases = []

    # ══════════════════════════════════════════════════════════════
    # V 组：字体必须撑得住 0.5em
    # ══════════════════════════════════════════════════════════════

    # R1 整个判据函数消失
    cases.append((
        'R1',
        'CSFSIsCJKFace 被删（回到「不做字体判断」）',
        '[FAIL] V1',
        lambda s: inject(s,
                         'static BOOL CSFSIsCJKFace(NSString *f) {',
                         'static BOOL CSFSIsCJKFaceACLDeleted(NSString *f) {',
                         'R1'),
    ))

    # R2 判据退回「face 为空才处理」—— 这正是 v33 的实际形态
    cases.append((
        'R2',
        '判据退回「face 为空才处理」（Calibri 永不进分支）',
        '[FAIL] V2',
        lambda s: inject(s,
                         'if (!CSFSIsCJKFace(face0)) {',
                         'if (face0.length == 0) {',
                         'R2'),
    ))

    # R3 判出来却没写回 run —— 半成品形态
    cases.append((
        'R3',
        '判出字体却没写回 run（算了不用）',
        '[FAIL] V3',
        lambda s: inject(s,
                         '            [r setObject:wideFace forKey:kCSFSRunFace];\n',
                         '            (void)wideFace;\n',
                         'R3'),
    ))

    # R3b 写回的不是统一出口，而是临时拼的字符串
    cases.append((
        'R3b',
        '写回 run 的字体不是从 gCSFSBodyFace 派生的',
        '[FAIL] V3',
        lambda s: inject(s,
                         '    NSString *wideFace = gCSFSBodyFace;',
                         '    NSString *wideFace = @"Arial";',
                         'R3b'),
    ))

    # R4 只认汉字码位，不认拼音名（英文名是实际取值的绝大多数）
    cases.append((
        'R4',
        'CSFSIsCJKFace 只认汉字码位、不认 SimSun/Songti 这类拼音名',
        '[FAIL] V4',
        lambda s: inject(s,
                         'if ((ch >= 0x2E80 && ch <= 0x9FFF) ||   // CJK 部首 ~ 统一表意文字',
                         'if ((ch >= 0xE000 && ch <= 0xF8FF) ||   // （故意改成私用区）',
                         'R4'),
    ))

    # R4b 只认拼音名，不认汉字（中文名「宋体」会判错）
    cases.append((
        'R4b',
        'CSFSIsCJKFace 只认拼音名、不认汉字码位',
        '[FAIL] V4',
        lambda s: inject(s,
                         '    for (NSUInteger i = 0; i < f.length; i++) {\n'
                         '        unichar ch = [f characterAtIndex:i];\n'
                         '        if ((ch >= 0x2E80 && ch <= 0x9FFF) ||   // CJK 部首 ~ 统一表意文字\n'
                         '            (ch >= 0xF900 && ch <= 0xFAFF) ||   // CJK 兼容表意文字\n'
                         '            (ch >= 0xFF00 && ch <= 0xFFEF)) {   // 全角形式\n'
                         '            return YES;\n'
                         '        }\n'
                         '    }\n',
                         '',
                         'R4b'),
    ))

    # R5 没有「宋体」兜底 —— 全文 Calibri 时空格仍是 0.226em
    cases.append((
        'R5',
        '去掉「宋体」兜底',
        '[FAIL] V5',
        lambda s: inject(s,
                         'if (gCSFSBodyFace.length == 0) gCSFSBodyFace = @"宋体";',
                         'if (gCSFSBodyFace.length == 0) gCSFSBodyFace = @"";',
                         'R5'),
    ))

    # ══════════════════════════════════════════════════════════════
    # H 组：下划线只认数据
    # ══════════════════════════════════════════════════════════════

    # R6 把 v33 的 em 判据重新加回来 —— 这就是本轮要修的原始缺陷
    cases.append((
        'R6',
        '按 em 阈值补下划线（v33 的假线来源，签字区 5 条假线就出在这）',
        '[FAIL] H1',
        lambda s: inject(s,
                         '        // 3) 下划线：只统计，不修改。',
                         '        BOOL hadUnder = [[r objectForKey:kCSFSRunUnderline] boolValue];\n'
                         '        double em = 2.5;\n'
                         '        if (!hadUnder && em >= 2.0) {\n'
                         '            [r setObject:@YES forKey:kCSFSRunUnderline];\n'
                         '        }\n'
                         '        // 3) 下划线：只统计，不修改。',
                         'R6'),
    ))

    # R7 补线但换了个变量名表达阈值
    #
    # 期望写 H2 而不是 H1：H1 只认 `em` 这个变量名，改个名字就能绕过 ——
    # 这是 H1 的能力边界，如实记在这里，不假装它能抓。
    # 真正的兜底是 H2：只要这个函数往 kCSFSRunUnderline 写东西就是错，
    # 不管用什么变量名、什么阈值。
    cases.append((
        'R7',
        '补下划线改用别的变量名表达阈值（验证 H2 兜得住）',
        '[FAIL] H2',
        lambda s: inject(s,
                         '        // 3) 下划线：只统计，不修改。',
                         '        double emx = 3.0;\n'
                         '        if (emx >= 1.0) {\n'
                         '            [r setObject:@YES forKey:kCSFSRunUnderline];\n'
                         '        }\n'
                         '        // 3) 下划线：只统计，不修改。',
                         'R7'),
    ))

    # R8 不猜阈值，但直接把下划线写成 YES（同样是从数据以外来的线）
    cases.append((
        'R8',
        '无条件给空白 run 补下划线',
        '[FAIL] H2',
        lambda s: inject(s,
                         '        // 3) 下划线：只统计，不修改。',
                         '        [r setObject:@YES forKey:kCSFSRunUnderline];\n'
                         '        // 3) 下划线：只统计，不修改。',
                         'R8'),
    ))

    # ══════════════════════════════════════════════════════════════
    # E 组：宽度精度
    # ══════════════════════════════════════════════════════════════

    # R9 展开函数丢掉出参 —— 余量无处传递
    cases.append((
        'R9',
        '展开函数没有 outSpTw 出参',
        '[FAIL] E1',
        lambda s: inject(s,
                         '                                    double fontSizePt, double *outSpTw) {',
                         '                                    double fontSizePt) {',
                         'R9'),
    ))

    # R10 退回四舍五入 —— 一半必然偏短
    cases.append((
        'R10',
        '个数退回四舍五入（舍去的一半必然偏短）',
        '[FAIL] E2',
        lambda s: inject(s,
                         '    long n = (long)floor(pt / per);',
                         '    long n = (long)(pt / per + 0.5);',
                         'R10'),
    ))

    # R11 余量算了不用
    cases.append((
        'R11',
        '余量算出来但不摊进 spTw（等于没补）',
        '[FAIL] E3',
        lambda s: inject(s,
                         '        spTw = (remPt * 20.0) / (double)n;',
                         '        spTw = 1.0;',
                         'R11'),
    ))

    # R12 没有行宽上限 —— 整段空白把段落撑爆
    cases.append((
        'R12',
        '去掉行宽上限（18pt×56 空格 = 504pt > 451pt 会撑爆段落）',
        '[FAIL] E4',
        lambda s: inject(s,
                         '    double maxPt = kCSFSContentTwips / 20.0;',
                         '    double maxPt = 1e9;',
                         'R12'),
    ))

    # ══════════════════════════════════════════════════════════════
    # S 组：spacing 的输出位置
    # ══════════════════════════════════════════════════════════════

    # R13 spacing 排到 sz 后面（CT_RPr sequence 违规，Word 静默忽略）
    cases.append((
        'R13',
        'spacing 排到 sz 之后（违反 CT_RPr sequence）',
        '[FAIL] S1',
        lambda s: inject(s,
                         '        if (spTw >= 1.0) {',
                         '        [rPr appendString:@"<w:sz w:val=\\"21\\"/>"];\n'
                         '        if (spTw >= 1.0) {',
                         'R13'),
    ))

    # R14 spacing 完全不输出 —— 余量白算
    cases.append((
        'R14',
        '不输出 <w:spacing>（余量白算）',
        '[FAIL] S1',
        lambda s: inject(s,
                         '            [rPr appendFormat:@"<w:spacing w:val=\\"%ld\\"/>", spInt];\n',
                         '',
                         'R14'),
    ))

    # R15 spTw 初值非 0 —— 非空白 run 也会被拉开字距
    cases.append((
        'R15',
        'spTw 初值不是 0（整篇文字字距被拉坏）',
        '[FAIL] S2',
        lambda s: inject(s,
                         '        double spTw = 0.0;',
                         '        double spTw = 5.0;',
                         'R15'),
    ))

    # R16 spacing 写成常量
    cases.append((
        'R16',
        'spacing 写死常量',
        '[FAIL] S3',
        lambda s: inject(s,
                         '            [rPr appendFormat:@"<w:spacing w:val=\\"%ld\\"/>", spInt];',
                         '            [rPr appendFormat:@"<w:spacing w:val=\\"20\\"/>"];',
                         'R16'),
    ))

    # ══════════════════════════════════════════════════════════════
    # D 组：诊断
    # ══════════════════════════════════════════════════════════════

    # R17 明细日志丢掉 spTw —— 看不出宽度到底补没补进去
    cases.append((
        'R17',
        '明细日志丢掉 spTw 字段',
        '[FAIL] D1',
        lambda s: inject(s,
                         '                 @" clamped=%ld n=%ld rem=%.2f spTw=%.1f srcLen=%lu clip=%d"',
                         '                 @" clamped=%ld n=%ld rem=%.2f srcLen=%lu clip=%d"',
                         'R17'),
    ))

    # R18 汇总日志不报字体
    cases.append((
        'R18',
        '汇总日志不报 bodyFace',
        '[FAIL] D2',
        lambda s: inject(s,
                         'CSFS_LOG(@"v34 space stats: expandedRuns=%ld underNBSP=%ld bodyFace=%@"\n'
                         '             @" (bodyFace 必须是中文字体名；若是 Calibri，空格只有 0.226em)",',
                         'CSFS_LOG(@"v34 space stats: expandedRuns=%ld underNBSP=%ld",',
                         'R18'),
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
