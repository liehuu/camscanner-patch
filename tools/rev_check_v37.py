#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rev_check_v37 —— 对 check_v37 做缺陷注入反向验证

v37 的缺陷形态只有一种：**只改一半**。它比「改错值」危险得多，因为：

  · 改错值 → 导出来一眼就能看出不对，用户会反馈；
  · 只改一半 → 版心是新的、判据是旧的，日志一片绿，折行全错，
    下一次反馈还是「每行字数不对」，但所有检查器都过。

所以每条用例都写成真机上会出现过的半成品形态：

  · pgMar 改了、常量没改（C1）
  · 常量改了、pgMar 没改（C1）
  · 图片上限漏改（S1，第三处最容易忘）
  · 阈值漏改一处（S2，就是 v35 squeeze 不触发的同一原因）
  · 常量定义被挪到使用之后（W2，C 里直接编译不过）
  · 常量被复制成两份（W3）

规则（与 rev_check_v31~v36 一致）：
  · 注入后 check_v37 必须变红，且报出的必须是**这一条**判据；
  · 锚点命中数不是 1 就算用例失效；
  · 注入函数返回 None 时**必须打印**，否则「9/10」看不出是哪条挂了。

允许同时变红：例如 C1 用例必然连带 W1。我们验证的是
「注入后 C1 会报」，不是「只有 C1 会报」—— 这比强行构造单一失败更忠于真实。

跑法：python3 tools/rev_check_v37.py
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src', 'CamScannerSaveToFiles.m')
CHECK = os.path.join(HERE, 'check_v37.py')


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
        print('基线不绿，先修 check_v37 本身：')
        print(out)
        return 1
    print('基线：原始源码 check_v37 全绿\n')

    cases = []

    # ⚠ 锚点必须写成源码里的**字面形态**：这是 .m 源文件，XML 都在
    #   Objective-C 的 @"..." 里，引号带一层反斜杠转义（\"）。
    #   check_v37 内部会先 replace('\\"', '"') 再校验，但 rev_check 是在
    #   原始源码上做注入 —— 两边视角不同，锚点写裸引号会一个都命中不了，
    #   而「锚点 0 次」只会打印一行 BAD，看起来像用例失效，
    #   实际是「这一条根本没被测过」。本文件第一版就栽在这里（P1~P4、W2）。
    #
    # ══════════════════════════════════════════════════════════════
    # P 组：页边距
    # ══════════════════════════════════════════════════════════════
    cases.append((
        'P1',
        '左右边距退回 Word 默认 1440（版本根因原封不动）',
        '[FAIL] P1',
        lambda s: inject(s, r'w:right=\"800\"', r'w:right=\"1440\"', 'P1'),
    ))

    cases.append((
        'P2',
        '上下边距被一并改成 800（没有实证，只会改变每页行数）',
        '[FAIL] P2',
        lambda s: inject(s, r'w:top=\"1440\"', r'w:top=\"800\"', 'P2'),
    ))

    cases.append((
        'P3',
        'gutter 被删（ECMA-376 标 required，Word 会判损坏）',
        '[FAIL] P3',
        lambda s: inject(s, r'w:gutter=\"0\"/>', r'/>', 'P3'),
    ))

    cases.append((
        'P4',
        '多一份 sectPr 页边距（两份互相覆盖，看不出哪份生效）',
        '[FAIL] P4',
        # 必须插在**同一个 @"..." 内部**。写成两个相邻字面量
        # （@"a""b"）在 C 里是语法错误，注入件编不过，用例就失去意义。
        # 尾部带 \" 是为了只命中 sectPr 那一处 —— <w:pgSz.../> 在文件里
        # 出现两次（另一处在图片段的空 sectPr 里，后面紧跟 </w:sectPr>）。
        lambda s: inject(
            s,
            r'<w:pgSz w:w=\"11906\" w:h=\"16838\"/>"',
            r'<w:pgSz w:w=\"11906\" w:h=\"16838\"/>'
            r'<w:pgMar w:top=\"1440\" w:right=\"1440\" w:bottom=\"1440\"'
            r' w:left=\"1440\" w:header=\"851\" w:footer=\"992\"'
            r' w:gutter=\"0\"/>"',
            'P4'),
    ))

    # ══════════════════════════════════════════════════════════════
    # C1：只改一半
    # ══════════════════════════════════════════════════════════════
    cases.append((
        'C1',
        '常量没跟着改（版心是新的、判据还是旧的）',
        '[FAIL] C1',
        lambda s: inject(s,
                         'static const double kCSFSContentTwips = 10306.0;',
                         'static const double kCSFSContentTwips = 9026.0;',
                         'C1'),
    ))

    cases.append((
        'C1b',
        '常量改了、pgMar 没改（反向的只改一半）',
        '[FAIL] C1',
        lambda s: inject(s,
                         'static const double kCSFSContentTwips = 10306.0;',
                         'static const double kCSFSContentTwips = 10466.0;',
                         'C1b'),
    ))

    # ══════════════════════════════════════════════════════════════
    # W 组：常量本身
    # ══════════════════════════════════════════════════════════════
    cases.append((
        'W1',
        '常量被改成一个显然不对的值',
        '[FAIL] W1',
        lambda s: inject(s,
                         'static const double kCSFSContentTwips = 10306.0;',
                         'static const double kCSFSContentTwips = 9000.0;',
                         'W1'),
    ))

    def move_def_after_img(s):
        # W2：定义被挪到图片函数之后 —— static const 先声明后使用，真机上编不过
        # 锚点不能带行尾换行：源码这一行后面接了注释
        #   ... = 10306.0;   // v37：A4 11906 - 左右边距各 800
        # 第一版写成 '...10306.0;\n' 就永远命中 0 次。
        old = 'static const double kCSFSContentTwips = 10306.0;'
        n = s.count(old)
        if n != 1:
            print('  [BAD ] W2 锚点命中 %d 次（应为 1）' % n)
            return None
        s = s.replace(old, '', 1)
        head = 'static NSString *CSFSRenderImagePara(NSDictionary *img, long seq) {\n'
        if s.count(head) != 1:
            print('  [BAD ] W2 函数头锚点命中 %d 次' % s.count(head))
            return None
        return s.replace(head,
                         head + '    static const double kCSFSContentTwips = 10306.0;\n',
                         1)

    cases.append((
        'W2',
        '常量定义被挪到使用之后（编不过，或取值是 0）',
        '[FAIL] W2',
        move_def_after_img,
    ))

    cases.append((
        'W3',
        '常量被复制成两份（改一处改不全）',
        '[FAIL] W3',
        lambda s: inject(
            s,
            '#define kCSFSFitLeft      1',
            'static const double kCSFSContentTwips = 10306.0;\n'
            '#define kCSFSFitLeft      1',
            'W3'),
    ))

    # ══════════════════════════════════════════════════════════════
    # S 组：引用方漏改
    # ══════════════════════════════════════════════════════════════
    cases.append((
        'S1',
        '图片宽度上限写死旧版心 9026（第三处最容易忘）',
        '[FAIL] S1',
        lambda s: inject(s, 'kMaxCx = kCSFSContentTwips * 635.0',
                         'kMaxCx = 9026.0 * 635.0', 'S1'),
    ))

    cases.append((
        'S2',
        '缩进上限写死旧值（版心变了阈值不变）',
        '[FAIL] S2',
        lambda s: inject(s, '(long)(kCSFSContentTwips * 0.9)',
                         '(long)8123', 'S2'),
    ))

    cases.append((
        'S3',
        '新代码里又引入 9026（旧版心回流）',
        '[FAIL] S3',
        lambda s: inject(s, '#define kCSFSFitLeft      1',
                         '#define kCSFSFitLeft      1\n'
                         'static const double kLegacyW = 9026.0;', 'S3'),
    ))

    bad = 0
    hit = 0
    for tag, desc, expect, fn in cases:
        mutated = fn(orig)
        if mutated is None:
            bad += 1
            continue
        rc, out = run_check(mutated)
        if rc == 0:
            print('  [MISS] %-4s %s —— 注入后仍然全绿' % (tag, desc))
            bad += 1
            continue
        if expect not in out:
            print('  [WRONG] %-4s 报的不是 %s —— %s' % (tag, expect, desc))
            # 把实际的失败行打出来，否则无从判断
            for ln in out.split('\n'):
                if '[FAIL]' in ln:
                    print('          ' + ln.strip()[:120])
            bad += 1
            continue
        hit += 1
        print('  [HIT ] %-4s %s' % (tag, desc))

    print('-' * 66)
    print('rev_check_v37 精确命中 %d/%d' % (hit, len(cases)))
    return 0 if bad == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
