#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rev_check_v33 —— 对 check_v33 做缺陷注入反向验证

为什么必须做这一步（本项目已经五次栽在这里）：
check_v27 绑变量名、check_v29 的 M5 黑名单、check_v31 的 S1 正则永不匹配、
check_v31 的 R4 前缀子串、check_v32 的 H 块取错对象 —— 全都是
「写的时候觉得对、跑起来全绿、其实一条都没抓住」。

v33 这一轮的判据尤其容易写成假绿，因为要判的东西都是「有没有做某件事」：
  · 「有没有把 width 当 pt 用」—— 只要函数里还出现 sliceWidthPx 就可能误判
  · 「有没有继承字体」—— 兜底分支里也有一处 forKey:kCSFSRunFace
  · 「有没有换成 NBSP」—— 光出现 00A0 字面量不算，必须真的赋回 emitText
所以本文件里的每个用例都刻意写成**真机上会出现的半成品形态**，
而不是为判据量身定做的字符串。

规则（与前几版一致）：
  · 注入后 check_v33 必须变红，且报出的必须是**这一条**判据；
  · 锚点命中数不是 1 就算用例失效（说明源码改过，锚点要更新）；
  · 注入后源码没变化也算失败。

跑法：python3 tools/rev_check_v33.py
"""

import importlib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src', 'CamScannerSaveToFiles.m')
CHECK = os.path.join(HERE, 'check_v33.py')

sys.path.insert(0, HERE)
cv33 = importlib.import_module('check_v33')


def run_check(text):
    """把变造后的源码喂给 check_v33，返回 (rc, stdout)。"""
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


# ══════════════════════════════════════════════════════════════════
# 注入用的原文片段（与源码逐字节对齐）
# ══════════════════════════════════════════════════════════════════

# S1 用：docx 写出日志 + v33 space stats 的整段
BLK_SPACE_STATS = (
    '    BOOL ok = [zipData writeToFile:outPath atomically:YES];\n'
    '    CSFS_LOG(@"v21 docx written=%d paras=%lu imgs=%lu defPt=%.1f size=%lu",\n'
    '             (int)ok, (unsigned long)paras.count, (unsigned long)images.count,\n'
    '             defaultPt, (unsigned long)zipData.length);\n'
    '    // v33：空格统计必须打在**渲染之后**。\n'
    '    // v32 把它放在解析后、渲染前，于是日志里永远 spaceExpanded=0，\n'
    '    // 而紧接着的 v32 space 明细又明明打出来了 —— 自相矛盾，\n'
    '    // 上一轮差点据此判断「展开根本没走」。\n'
    '    CSFS_LOG(@"v33 space stats: expandedRuns=%ld underNBSP=%ld bodyFace=%@",\n'
    '             gCSFSSpaceExpandRuns, gCSFSUnderSpaceRuns,\n'
    '             gCSFSBodyFace ?: @"(nil)");\n'
)

# S1 注入后：统计先打、写入日志后打（= v32 的时序）
BLK_SPACE_STATS_EARLY = (
    '    CSFS_LOG(@"v33 space stats: expandedRuns=%ld underNBSP=%ld bodyFace=%@",\n'
    '             gCSFSSpaceExpandRuns, gCSFSUnderSpaceRuns,\n'
    '             gCSFSBodyFace ?: @"(nil)");\n'
    '    BOOL ok = [zipData writeToFile:outPath atomically:YES];\n'
    '    CSFS_LOG(@"v21 docx written=%d paras=%lu imgs=%lu defPt=%.1f size=%lu",\n'
    '             (int)ok, (unsigned long)paras.count, (unsigned long)images.count,\n'
    '             defaultPt, (unsigned long)zipData.length);\n'
)

NBSP_SPLIT = (
    "(ch == ' ' ? @\"\\u00A0\" : "
    "[NSString stringWithCharacters:&ch length:1])"
)

UNDER_BLACKLIST = (
    '        if ([s isEqualToString:@"0"] || [s isEqualToString:@"false"] ||\n'
    '            [s isEqualToString:@"no"]  || [s isEqualToString:@"none"] ||\n'
    '            [s isEqualToString:@"nil"] || [s isEqualToString:@"null"]) {\n'
    '            return NO;\n'
    '        }\n'
    '        return YES;'
)


def main():
    orig = open(SRC, encoding='utf-8').read()

    rc, out = run_check(orig)
    if rc != 0:
        print('基线不绿，先修 check_v33 本身：')
        print(out)
        return 1
    print('基线：原始源码 check_v33 全绿\n')

    cases = []

    # ══════════════════════════════════════════════════════════════
    # W 组：宽度单位（真机样本 w=56/12/36 对应 11/2/7 个空格）
    # ══════════════════════════════════════════════════════════════

    # R1 回到 v32 的 200dpi 折算 —— 这是本轮要修掉的原始缺陷
    cases.append((
        'R1',
        '宽度又乘 200dpi 系数（退回 v32，长度做小 2.8 倍）',
        'W1 CSFSExpandSpaceRun 仍在乘 200dpi 的 0.3597',
        lambda s: inject(s,
                         'double pt = sliceWidthPx;\n',
                         'double pt = sliceWidthPx * (595.0 / 1654.0);\n',
                         'R1'),
    ))

    # R2 去掉「不许更短」的下限
    cases.append((
        'R2',
        '去掉「不得少于原文字符数」的下限',
        'W2 删掉了',
        lambda s: inject(s,
                         'if ((long)text.length > n) n = (long)text.length;',
                         '', 'R2'),
    ))

    # R3 去掉上限 clamp
    cases.append((
        'R3',
        '去掉上限 clamp（单位一旦不是 pt 会算出上万空格）',
        'W3 没有上限 clamp',
        lambda s: inject(s, 'if (n > 200) n = 200;', '', 'R3'),
    ))

    # R4 去掉 width 不可用的兜底
    cases.append((
        'R4',
        'width 不可用时不再原样返回（凭空造空格）',
        'W4 width 不可用时没有原样返回',
        lambda s: inject(s,
                         'if (!(sliceWidthPx > 0.0)) return text;',
                         '', 'R4'),
    ))

    # ══════════════════════════════════════════════════════════════
    # F 组：空白 run 的属性补齐
    # ══════════════════════════════════════════════════════════════

    # R5 压根不调用补齐函数（最常见：写了函数忘了接）
    cases.append((
        'R5',
        'CSFSRenderPara 里不调用 CSFSFixSpaceRuns',
        'F1 CSFSRenderPara 里没有调用 CSFSFixSpaceRuns',
        lambda s: inject(s,
                         'CSFSFixSpaceRuns((NSMutableArray *)runs, paraPt);',
                         '/* removed */', 'R5'),
    ))

    # R6 读了邻居字体但没写进 run —— 半成品形态
    cases.append((
        'R6',
        '读到邻居字体却没写进 run（get 了不 set）',
        'F2 读到了邻居字体却没有写进 run',
        lambda s: inject(s,
                         '                [r setObject:sf forKey:kCSFSRunFace];\n',
                         '                (void)sf;\n', 'R6'),
    ))

    # R7 补齐函数排在写 XML 之后 ——
    #    只改了内存里的 run，输出早就生成了，等于白做。
    #    （原用例是「不往前找邻居」，但那种改法不改变数据流形态，
    #     F2 判的是「有没有从 src 读并写回」，本来就覆盖不到
    #     「src 是否一定能拿到」—— 那是判据的能力边界，不是假通过。
    #     所以换成这条同样真实、且判据明确覆盖的缺陷。）
    cases.append((
        'R7',
        'CSFSFixSpaceRuns 挪到写 XML 之后（改了内存，输出已生成）',
        'F1 CSFSFixSpaceRuns 排在写 XML 之后',
        lambda s: inject(
            s.replace('CSFSFixSpaceRuns((NSMutableArray *)runs, paraPt);\n',
                      '', 1),
            '    [out appendString:@"</w:p>"];',
            '    CSFSFixSpaceRuns((NSMutableArray *)runs, paraPt);\n'
            '    [out appendString:@"</w:p>"];',
            'R7'),
    ))

    # R8 兜底字体留空 —— 整段都是填空线时 face 仍为空，掉回 Calibri
    cases.append((
        'R8',
        '兜底字体给空串（留空等于没兜底）',
        'F3 继承不到时没有兜底字体',
        lambda s: inject(s,
                         'NSString *df = (gCSFSBodyFace.length > 0) ? gCSFSBodyFace : @"SimSun";',
                         'NSString *df = @"";', 'R8'),
    ))

    # R9 算了兜底字体却没写进去
    cases.append((
        'R9',
        '兜底字体算出来了却没写进 run',
        'F3 兜底字体算出来了',
        lambda s: inject(s,
                         '            [r setObject:df forKey:kCSFSRunFace];\n',
                         '            (void)df;\n', 'R9'),
    ))

    # R10 不在段落级统一记录正文字体（每段各猜，跨段不一致）
    cases.append((
        'R10',
        '不记录全文正文字体 gCSFSBodyFace',
        'F4 没有记录 gCSFSBodyFace',
        lambda s: inject(s,
                         '            if (cf.length > 0) { gCSFSBodyFace = [cf copy]; break; }',
                         '            if (cf.length > 0) { break; }', 'R10'),
    ))

    # R11 批次重置漏清（第二次导出会混进上一次的字体与计数）
    cases.append((
        'R11',
        '批次重置漏清 gCSFSBodyFace / gCSFSUnderSpaceRuns',
        'F5 批次重置没清',
        lambda s: inject(s,
                         '    gCSFSUnderSpaceRuns  = 0;\n'
                         '    gCSFSBodyFace        = nil;\n',
                         '', 'R11'),
    ))

    # ══════════════════════════════════════════════════════════════
    # U 组：下划线属性
    # ══════════════════════════════════════════════════════════════

    # R12 退回 CSFSBoolValue —— v32 的真实写法，
    #     "single" 被当成「没有下划线」，整条填空线消失
    cases.append((
        'R12',
        'underline 退回 CSFSBoolValue（v32 原写法）',
        'U1 underline 仍用 CSFSBoolValue 判断',
        lambda s: inject(s,
                         'if (CSFSUnderlineValue(CSFSValue(attr, @"underline"))) {',
                         'if (CSFSBoolValue(CSFSValue(attr, @"underline"))) {',
                         'R12'),
    ))

    # R13 改成白名单列举 —— 漏掉 "thick"/"double" 就又丢线
    cases.append((
        'R13',
        '下划线改成白名单列举（漏 "thick"/"double"）',
        'U2 用白名单列举下划线写法',
        lambda s: inject(s,
                         UNDER_BLACKLIST,
                         '        return ([s isEqualToString:@"1"] || '
                         '[s isEqualToString:@"single"]);', 'R13'),
    ))

    # R14 黑名单漏一个否定词 —— "none" 被当有下划线，整段都被画线
    cases.append((
        'R14',
        '黑名单漏掉 "none"',
        'U3 没有把',
        lambda s: inject(s,
                         '            [s isEqualToString:@"no"]  || '
                         '[s isEqualToString:@"none"] ||\n',
                         '            [s isEqualToString:@"no"]  ||\n',
                         'R14'),
    ))

    # R15 不做 NBSP 替换 —— 行尾空格的下划线被 Word 裁掉
    cases.append((
        'R15',
        '不做 NBSP 替换（行尾空格的下划线会被裁掉）',
        'U4 没有把带下划线的空白换成不换行空格',
        lambda s: inject(s, NBSP_SPLIT,
                         '[NSString stringWithCharacters:&ch length:1]', 'R15'),
    ))

    # R16 构造了 NBSP 却没赋回 emitText —— 写了没用上
    cases.append((
        'R16',
        '构造了 NBSP 字符串却没赋回 emitText',
        'U4 找不到「把 NBSP 结果赋回 emitText」的语句',
        lambda s: inject(s,
                         '            emitText = nb;\n',
                         '            (void)nb;\n', 'R16'),
    ))

    # R17 NBSP 替换只被「纯空白」守卫 —— 所有词间空格都变 NBSP，整行溢出
    cases.append((
        'R17',
        'NBSP 替换丢了「带下划线」守卫',
        'U5 NBSP 替换只被「纯空白」守卫',
        lambda s: inject(s,
                         'if (emitIsSpace && emitUnder && emitText.length > 0) {',
                         'if (emitIsSpace && emitText.length > 0) {',
                         'R17'),
    ))

    # ══════════════════════════════════════════════════════════════
    # T 组：填空线判据
    # ══════════════════════════════════════════════════════════════

    # R18 按「空格个数」判 —— 个数是 OCR 给的，可能被截断
    cases.append((
        'R18',
        '填空线改用「空格个数」判定',
        'T1 补下划线用「空格个数」判定',
        lambda s: inject(s,
                         'if (!hadUnder && em >= 2.0) {',
                         'if (!hadUnder && (long)t.length >= 3) {',
                         'R18'),
    ))

    # R19 阈值放到 0.5em —— 两三个词间空格就被画成线
    cases.append((
        'R19',
        '填空线阈值降到 em>=0.5（词间距被误画成线）',
        'T2 填空线阈值 em>',
        lambda s: inject(s,
                         'if (!hadUnder && em >= 2.0) {',
                         'if (!hadUnder && em >= 0.5) {',
                         'R19'),
    ))

    # ══════════════════════════════════════════════════════════════
    # S 组：统计日志时机
    # ══════════════════════════════════════════════════════════════

    # R20 统计挪到渲染前（= v32 的自相矛盾：明细有、汇总为 0）
    cases.append((
        'R20',
        'space stats 挪到 docx 写入之前（v32 的时序）',
        'S1 「space stats」打在 docx 写入**之前**',
        lambda s: inject(s, BLK_SPACE_STATS, BLK_SPACE_STATS_EARLY, 'R20'),
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
    # E 组：提取器自检
    # ══════════════════════════════════════════════════════════════
    #
    # check_v33 的每条判据都建立在 extract_func 之上。如果提取器取错了
    # 对象（历史上 check_v32 的 H 组就取到了块级过滤而不是切片级），
    # 后面所有判据都会在**错误的对象**上全绿。这里单独验证三件事：
    # 取得到、取得准、取不到时返回 None 而不是乱返回一段。
    print('\n--- E 组：函数提取器自检 ---')

    def brace_balanced(s):
        depth = 0
        i = 0
        while i < len(s):
            c = s[i]
            if c == '"':
                i += 1
                while i < len(s):
                    if s[i] == '\\':
                        i += 2
                        continue
                    if s[i] == '"':
                        break
                    i += 1
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth < 0:
                    return False
            i += 1
        return depth == 0

    # E1：取 CSFSExpandSpaceRun 必须拿到展开函数本身
    f_exp = cv33.extract_func(orig, 'CSFSExpandSpaceRun')
    if f_exp is None:
        bad += 1
        print('  [BAD ] E1 取不到 CSFSExpandSpaceRun')
    elif ('sliceWidthPx' not in f_exp or 'fontSizePt' not in f_exp
          or 'static ' in f_exp or not brace_balanced(f_exp)):
        bad += 1
        print('  [BAD ] E1 取到的不是展开函数本身（含 static / 花括号不配平 / '
              '缺参数名）—— W1~W4 在错的对象上判')
    else:
        print('  [HIT ] E1 取到 CSFSExpandSpaceRun 本体（参数齐、花括号配平、不含下一个函数）')

    # E2：取 CSFSUnderlineValue 必须同时含黑名单与肯定返回
    f_und = cv33.extract_func(orig, 'CSFSUnderlineValue')
    if f_und is None:
        bad += 1
        print('  [BAD ] E2 取不到 CSFSUnderlineValue')
    elif ('"none"' not in f_und or 'return YES;' not in f_und
          or 'CSFSBoolValue' in f_und):
        bad += 1
        print('  [BAD ] E2 取到的不是下划线判据本身 —— U2/U3 会在错的对象上判')
    else:
        print('  [HIT ] E2 取到 CSFSUnderlineValue 本体（含黑名单与 return YES）')

    # E3：取不存在的函数必须返回 None（不能乱返回一段别的代码）
    if cv33.extract_func(orig, 'NoSuchFunctionZZZ') is not None:
        bad += 1
        print('  [MISS] E3 取不存在的函数竟然返回了内容 —— 提取器会误配，'
              '所有判据都可能落在错的对象上')
    else:
        print('  [HIT ] E3 取不存在的函数返回 None（不会误配）')

    # E4：assigned_vars 必须做整标识符匹配。
    #     gCSFSUnderSpaceRuns 含有 gCSFSUnderSpace 这个前缀，
    #     若用子串判断，「只赋了前缀变量」也会被当成已赋值。
    #     —— 本项目第六次踩子串坑，这里主动验一次。
    if cv33.assigned_vars('gCSFSUnderSpaceRuns = 0;', 'gCSFSUnderSpace'):
        bad += 1
        print('  [MISS] E4 assigned_vars 把 gCSFSUnderSpaceRuns 当成 '
              'gCSFSUnderSpace 的赋值 —— 前缀子串误判，F5 会假通过')
    elif not cv33.assigned_vars('gCSFSUnderSpaceRuns = 0;', 'gCSFSUnderSpaceRuns'):
        bad += 1
        print('  [BAD ] E4 assigned_vars 连真正的赋值都识别不了')
    else:
        print('  [HIT ] E4 assigned_vars 按整标识符匹配（前缀子串不算）')

    total = len(cases) + 4
    print('\n反向验证：%d/%d 命中' % (total - bad, total))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
