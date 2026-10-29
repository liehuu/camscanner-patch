#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rev_check_v31.py —— check_v31.py 的反向验证（缺陷注入）。

为什么必须有这个文件：
  本项目已经踩过**四次**「检查器本身是假的」：
    · verify_artifact.py 用 `"Architecture: iphoneos-arm64" in ctrl` 子串匹配，
      `iphoneos-arm64e` 也含该子串 → 架构写错照样 OK，放行了装不上的包。
    · check_v29.py 的 M5 判据写成黑名单 `(?!...|mw|ms|w|s|fw|fs)`，
      注入 `gCSFSHideWritten = mw;` 恰好落在排除名单里 → 假通过。
    · check_v27.py 的 F2 绑了变量名 got123 的正则，v28 改名 gotModel 即失效。
    · check_v31.py 初版的 S1 判据写成
          stringByTrimmingCharactersInSet[^;]*\\)\\.length
      但真实代码是 `[s stringByTrimmingCharactersInSet:ws].length`
      —— `.length` 前是 `]` 不是 `)`，那条正则**永远匹配不到任何东西**，
      于是「空格被丢掉」这个头号缺陷它一条都抓不住。
      是写本文件时发现的。

  共同点：判据绑在「代码长什么样」，不在「行为对不对」。
  唯一可靠的验证方式：造一个真实缺陷，确认检查器真的会报错。

本文件注入 12 例，每例都对应一个「真实出现过或极易发生」的改法：

  D1  CSFSSliceText 恢复 trim 后判空 continue（v30 及以前的真实写法）
  D1b 同上，但写成两行 + 变量改名 trimmed（换形态，判据必须照样抓到）
  D2 纯空白分支在 return 之前被挪走（判了出来却没返回）
  D3 CSFSIsPureWhiteSpace 去掉全角空格 0x3000
  D4 段落收集循环恢复 trim 判空丢 run（空格被丢的第二处）
  D5 纯空白 run 不回写 hasText（填空段整段被丢）

  R1 exportWordAction 里删掉 reset 调用
  R2 reset 挪到读开关之后（顺序反了 = 清掉刚读到的值）
  R3 reset 漏清某个 seen 变量（上一批的「读到过」渗进这一批）
  R4 reset 漏清版式 scale（换页后分母变了仍沿用）

  H1 手写过滤删掉 slCat == 1（退回「凭 stype 就删」）
  H3 手写过滤改回 v30 的 OR 写法：
     `if (gCSFSHideWritten && (catSaysHW || stypeSaysHW)) { … continue; }`
     —— 这是唯一真正导致「33 段正文消失」的形态，判据必须实打实抓到它

  另外做一次**正向求值自检**（F1）：
     把 v30 的 OR 写法喂给 H3 的求值器，确认它真的算出「会删」。
     如果求值器坏了，H3 会永远绿 —— 那种「永远通过」的检查等于没有。

用法：python3 tools/rev_check_v31.py [src/CamScannerSaveToFiles.m]
      （CI 里不带参数，默认读仓库根下的 src/CamScannerSaveToFiles.m）
"""

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, 'check_v31.py')

# CI 里 rev_check_* 一律**不带参数**调用（见 build.yml），
# 所以这里必须自己定位源码。
ROOT = os.path.dirname(HERE)
SRC_DEFAULT = os.path.join(ROOT, 'src', 'CamScannerSaveToFiles.m')


def run_check(text):
    """把改造后的源码写临时文件，跑 check_v31，返回 (退出码, 输出)。"""
    fd, path = tempfile.mkstemp(suffix='.m', text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
        p = subprocess.run([sys.executable, CHECK, path],
                           capture_output=True, text=True,
                           encoding='utf-8', errors='replace')
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def inject(src, old, new, tag):
    """精确替换一次。replace 不到、或出现多次，都说明用例本身失效。"""
    n = src.count(old)
    if n != 1:
        print('  [BAD ] %s 注入目标串出现 %d 次（应为 1）—— 用例本身失效'
              % (tag, n))
        return None
    return src.replace(old, new, 1)


def main():
    src_path = sys.argv[1] if len(sys.argv) > 1 else SRC_DEFAULT
    if not os.path.exists(src_path):
        print('找不到源码：%s' % src_path)
        return 2
    orig = open(src_path, encoding='utf-8').read()

    # 先确认原始源码全绿，否则「注入了才变红」没有意义
    rc0, out0 = run_check(orig)
    if rc0 != 0:
        print('[BAD ] 原始源码本来就没通过 check_v31 —— 反向验证无意义')
        print(out0)
        return 2
    print('基线：原始源码 check_v31 全绿\n')

    # 复用的锚点串（都取自当前源码，唯一）
    A_SPACE_BRANCH = (
        '        if (CSFSIsPureWhiteSpace(s)) {\n'
        '            // 纯空白：保留原样（不 trim），它是合法的排版内容\n'
        '            return s;\n'
        '        }\n'
    )
    A_LOOP_BRANCH = (
        '                                                                    if (tt.length == 0) continue;\n'
        '                                                                    BOOL ttIsSpace = CSFSIsPureWhiteSpace(tt);\n'
        '                                                                    if (ttIsSpace) {\n'
        '                                                                        spaceSliceCount++;\n'
    )
    A_HAS_YES = (
        '                                                                        hasText = YES;\n'
        '                                                                        [runs addObject:run];\n'
        '                                                                        continue;\n'
    )
    A_HAND_HEAD = (
        '                                                                        if (gCSFSHideWritten) {\n'
        '                                                                            BOOL catSaysHW  = (slCat == 1);\n'
    )
    A_HAND_TAIL = (
        '                                                                            }\n'
        '                                                                        }\n'
        '                                                                        if (CSFSBoolValue(CSFSValue(sl, @"hiding"))) {\n'
    )

    cases = []

    # ══════════════════════════════════════════════════════════════
    # 问题一：空格
    # ══════════════════════════════════════════════════════════════

    # ── D1 CSFSSliceText 恢复 trim 后判空（v30 真实写法）──────────
    #
    # 插到纯空白分支**内部**（在 return 之前）—— 这就是 v30 的原始形态：
    # 先判断有没有文字，纯空白判定为空 → continue。只替换分支体，不依赖
    # 分支后面跟的是什么（那里现在有几行说明性注释，拼接锚点会失效）。
    cases.append((
        'D1',
        'CSFSSliceText 恢复「trim 后判空 → continue」（内联形态）',
        'S1 CSFSSliceText 仍用「trim 后为空',
        lambda s: inject(
            s,
            A_SPACE_BRANCH,
            '        if ([s stringByTrimmingCharactersInSet:ws].length == 0) continue;\n',
            'D1'),
    ))

    # ── D1b 同义改法，但写成两行、变量改名 ───────────────────────
    #
    # 这是最关键的一例：判据若绑字面形态，这一例必然 MISS。
    cases.append((
        'D1b',
        '同义改法：两行 + 变量改名 trimmed（判据须照样抓到）',
        'S1 CSFSSliceText 仍用「trim 后为空',
        lambda s: inject(
            s,
            A_SPACE_BRANCH,
            '        NSString *trimmed = [s stringByTrimmingCharactersInSet:'
            'CSFSWhiteSpaceSet()];\n'
            '        if (trimmed.length == 0) continue;\n',
            'D1b'),
    ))

    # ── D2 纯空白分支判了却没返回 ────────────────────────────────
    cases.append((
        'D2',
        '纯空白分支没有 return s（判出来却没放行）',
        'S2 CSFSIsPureWhiteSpace 分支里没有 return s',
        lambda s: inject(
            s,
            A_SPACE_BRANCH,
            '        if (CSFSIsPureWhiteSpace(s)) {\n'
            '            (void)0;\n'
            '        }\n',
            'D2'),
    ))

    # ── D3 去掉全角空格 ──────────────────────────────────────────
    cases.append((
        'D3',
        'CSFSIsPureWhiteSpace 去掉全角空格 0x3000',
        'S3 CSFSIsPureWhiteSpace 没覆盖全角空格',
        lambda s: inject(
            s,
            "        if (c == ' ' || c == '\\t' || c == '\\n' || c == '\\r' ||\n"
            "            c == 0x00A0 || c == 0x3000) {\n",
            "        if (c == ' ' || c == '\\t' || c == '\\n' || c == '\\r') {\n",
            'D3'),
    ))

    # ── D4 段落收集循环恢复 trim 判空 ────────────────────────────
    cases.append((
        'D4',
        '段落收集循环恢复「trim 后判空 → continue」丢 run',
        'S4 段落收集循环里仍用「trim 后判空 → continue」丢 run',
        lambda s: inject(
            s,
            A_LOOP_BRANCH,
            '                                                                    NSString *tt2 = [tt stringByTrimmingCharactersInSet:CSFSWhiteSpaceSet()];\n'
            '                                                                    if (tt2.length == 0) continue;\n'
            '                                                                    BOOL ttIsSpace = CSFSIsPureWhiteSpace(tt);\n'
            '                                                                    if (ttIsSpace) {\n'
            '                                                                        spaceSliceCount++;\n',
            'D4'),
    ))

    # ── D5 纯空白 run 不回写 hasText ─────────────────────────────
    cases.append((
        'D5',
        '纯空白 run 不置 hasText（填空行整段被 !hasText 丢掉）',
        'S5 纯空白 run 没有把 hasText 置 YES',
        lambda s: inject(
            s,
            A_HAS_YES,
            '                                                                        [runs addObject:run];\n'
            '                                                                        continue;\n',
            'D5'),
    ))

    # ══════════════════════════════════════════════════════════════
    # 问题二：开关跨批次累积
    # ══════════════════════════════════════════════════════════════

    # ── R1 删掉 reset 调用 ───────────────────────────────────────
    cases.append((
        'R1',
        'exportWordAction 里删掉 CSFSResetOptionState()',
        'R1 exportWordAction 里没有调用 CSFSResetOptionState',
        lambda s: inject(
            s,
            '        CSFSResetOptionState();\n',
            '',
            'R1'),
    ))

    # ── R2 reset 挪到读开关之后 ──────────────────────────────────
    cases.append((
        'R2',
        'reset 挪到读开关之后（清掉刚读到的本次值）',
        'R2 CSFSResetOptionState 排在读开关之后',
        lambda s: inject(
            s,
            '        CSFSResetOptionState();\n',
            '        CSFSReadOptionsFromBottomView(self);\n'
            '        CSFSResetOptionState();\n',
            'R2'),
    ))

    # ── R3 漏清 seen 变量 ────────────────────────────────────────
    cases.append((
        'R3',
        'reset 漏清 gCSFSSeenStamp（上一批「读到过」渗到这一批）',
        'R3 重置没清 gCSFSSeenStamp',
        lambda s: inject(
            s,
            '    gCSFSSeenStamp   = NO;\n',
            '',
            'R3'),
    ))

    # ── R4 漏清版式 scale ────────────────────────────────────────
    cases.append((
        'R4',
        'reset 漏清版式上下文 gCSFSPageScale（换页后分母变了）',
        'R4 重置没清 gCSFSPageScale',
        lambda s: inject(
            s,
            '    gCSFSPageScale    = 0.0;\n',
            '',
            'R4'),
    ))

    # ══════════════════════════════════════════════════════════════
    # 问题三：手写判据
    # ══════════════════════════════════════════════════════════════

    # ── H1 删掉 image_category 判据 ──────────────────────────────
    cases.append((
        'H1',
        '手写过滤删掉 slCat == 1（退回「凭 stype 就删」）',
        'H1 手写过滤里没有 image_category==1 的判据',
        lambda s: inject(
            s,
            '                                                                            BOOL catSaysHW  = (slCat == 1);\n',
            '                                                                            BOOL catSaysHW  = NO;\n',
            'H1'),
    ))

    # ── H3 退回 v30 的 OR 写法 ───────────────────────────────────
    #
    # 这是**唯一真正导致 33 段正文消失**的形态，必须实打实抓到。
    # 注意它把整个过滤块改写为单层 if + continue，
    # 所以注入后 A_HAND_TAIL 也会被替换掉 —— 一并给出完整新块。
    def d3_or_form(s):
        new_block = (
            '                                                                        if (gCSFSHideWritten) {\n'
            '                                                                            BOOL catSaysHW  = (slCat == 1);\n'
            '                                                                            BOOL stypeSaysHW =\n'
            '                                                                                (stLow.length > 0 &&\n'
            '                                                                                 [stLow containsString:@"handwrit"]);\n'
            '                                                                            if (catSaysHW || stypeSaysHW) {\n'
            '                                                                                handSkipCount++;\n'
            '                                                                                continue;\n'
            '                                                                            }\n'
            '                                                                        }\n'
            '                                                                        if (CSFSBoolValue(CSFSValue(sl, @"hiding"))) {\n'
        )
        i = s.find(A_HAND_HEAD)
        if i < 0:
            print('  [BAD ] D3 找不到手写过滤块起点')
            return None
        # 找块尾：从起点起按花括号配平
        b = s.find('{', i + A_HAND_HEAD.index('{'))
        depth = 0
        j = b
        while j < len(s):
            if s[j] == '{':
                depth += 1
            elif s[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= len(s):
            print('  [BAD ] D3 手写过滤块花括号不配平')
            return None
        # 把整块替换成 OR 写法
        return s[:i] + new_block + s[j + 1:]

    cases.append((
        'H3',
        '手写过滤退回 v30 的 OR 写法（cat || stype → continue）',
        'H3 存在「正文会被误删」的 continue',
        d3_or_form,
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
    # F1 正向求值自检：确认 H3 的求值器真的会算出「会删」
    # ══════════════════════════════════════════════════════════════
    #
    # 如果 UNSAFE_SCENARIO / HASTEXT 之类的占位符没对上，
    # H3 的 eval 会总是 False → 永远绿 → 假检查。
    # 所以这里**直接调用 check_v31 内部的函数**喂它 v30 的形态。
    print('\n--- F1 H3 求值器自检 ---')
    try:
        sys.path.insert(0, HERE)
        import importlib
        cv31 = importlib.import_module('check_v31')
        v30_cond = ('gCSFSHideWritten && (catSaysHW || stypeSaysHW)')
        py, _ = cv31.objc_cond_to_py(v30_cond, cv31.UNSAFE_SCENARIO)
        val = bool(eval(py, {'__builtins__': {}}, {}))
        if val:
            print('  [HIT ] F1 v30 条件在「cat=0/有文字」场景下求值为 True（会删）')
            print('         py = %s' % py)
        else:
            bad += 1
            print('  [MISS] F1 v30 条件居然求值为 False —— H3 求值器已坏，'
                  'H3 会永远绿')
            print('         py = %s' % py)

        # 再验一遍 v31 的真实条件在安全场景下必须是 False（不删）
        v31_cond = 'catSaysHW && !hasTextHW'
        py2, _ = cv31.objc_cond_to_py(v31_cond, cv31.UNSAFE_SCENARIO)
        val2 = bool(eval(py2, {'__builtins__': {}}, {}))
        if not val2:
            print('  [HIT ] F2 v31 条件在安全场景下求值为 False（不删）')
        else:
            bad += 1
            print('  [MISS] F2 v31 条件求值为 True —— 求值器把安全场景误判成删')
            print('         py = %s' % py2)

        # F3：cat=1 且**真的没文字** → v31 必须删（真手写图要被去掉）
        #
        # 注意场景不能沿用 UNSAFE_SCENARIO：那里 catSaysHW=False（cat≠1），
        # 光这一项就足以让 `catSaysHW && !hasTextHW` 恒假，
        # 于是「无文字」这个变量根本没被真正检验到 —— 写错场景的用例
        # 会给出一个看着像通过、其实什么都没验的结论。
        sc = dict(cv31.UNSAFE_SCENARIO)
        sc['catSaysHW'] = True
        sc['slCat'] = 1
        sc['hasTextHW'] = False
        py3, _ = cv31.objc_cond_to_py(v31_cond, sc)
        val3 = bool(eval(py3, {'__builtins__': {}}, {}))
        if val3:
            print('  [HIT ] F3 cat=1 且无文字时 v31 条件为 True（真手写图会被删，正确）')
        else:
            bad += 1
            print('  [MISS] F3 cat=1 且无文字时 v31 条件仍为 False —— '
                  '说明真手写图也删不掉了，功能反向失效')
            print('         py = %s' % py3)
    except Exception as e:
        bad += 1
        print('  [BAD ] F1 求值器自检抛异常：%r' % e)

    total = len(cases) + 3
    print('\n反向验证：%d/%d 命中' % (total - bad, total))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())