# -*- coding: utf-8 -*-
"""check_render_c.py 的注入式反向验证。

为什么需要它（2026-10-28 的教训）：
    v23 升级 check_render_c 的 C3/C2 时，旧判据对着新代码连报两条 FAIL ——
    都是假的。假 FAIL 会被当成「实现有问题」去改实现，
    比漏报更能把人带偏。

    所以每加一条检查，都必须先证明它**在缺陷存在时会报**。
    只证明「当前代码能过」是不够的：
      当前代码能过，可能只是因为这条检查根本没在检查东西。

做法：把源码读进来，用字符串替换注入 6 种已知缺陷，
逐个交给 check_render_c 跑，确认它精确报出**对应的那一条**。

用法：
    python tools/rev_check_render_c.py
退出码：0 全部注入都被抓到；1 有漏网。
"""
import io
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, '..', 'src', 'CamScannerSaveToFiles.m')
CHK = os.path.join(HERE, 'check_render_c.py')


def run_checker(text):
    fd, path = tempfile.mkstemp(suffix='.m')
    os.close(fd)
    try:
        io.open(path, 'w', encoding='utf-8').write(text)
        p = subprocess.run([sys.executable, CHK, path],
                           capture_output=True, text=True, encoding='utf-8',
                           errors='replace')
        return (p.stdout or '') + (p.stderr or '')
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def inject(name, text, old, new):
    """把 old 替换成 new（只替第一处）。返回 (是否替换成功, 新文本)。"""
    if old not in text:
        print('  [SKIP] %s —— 锚点文本不存在，注入失败' % name)
        return False, text
    return True, text.replace(old, new, 1)


def main():
    src = io.open(SRC, encoding='utf-8').read()

    # 0) 基线：原样必须全过。基线不过的话，下面所有结论都不成立。
    base = run_checker(src)
    if 'FAIL' in base and re.search(r'\[FAIL\]', base):
        print('基线本身就有 FAIL，反向验证无意义：')
        print(base)
        return 1
    print('基线：全过')

    cases = []

    # v24 起缩进语句变成
    #   [pPr appendFormat:@"<w:ind%@ w:firstLineChars=\"%ld\" w:firstLine=\"%ld\"/>",
    #       ind, chars, flT];
    # 锚点必须跟着实现走。这里统一取行首那段，不依赖后面的实参列表 ——
    # 实参名一改（v23 是 fl，v24 是 flT）锚点就失效，用例会静默 SKIP。
    # v30：首行缩进那行改成了裸写（去掉了 %@ 那段左右缩进），
    # 所以锚点要从 '...<w:ind%@ w:firstLineChars=' 改成 '...<w:ind w:firstLineChars='。
    #
    # 为什么不写成「两种都试」：两种都试的话，将来实现再变一次，
    # 又会静默 SKIP —— 而 SKIP 只是打印一句，退出码不受影响，
    # 于是「7 例里 2 例没跑」和「7 例全跑」在 CI 上看起来一样。
    # 锚点跟着当前实现走，变了就让它显式 SKIP（能被 gate_local 看见），
    # 这比假装通过安全。
    IND_ANCHOR = '[pPr appendFormat:@"<w:ind w:firstLineChars='

    # 1) <w:jc> 排到 <w:ind> 前面 —— CT_PPrBase 是 sequence，顺序错一项静默失效
    #
    # v36：缩进语句从 12 空格缩进（嵌在 else 分支深处）变成 8 空格，
    # 原先「缩进 + 锚点」的写法因此命中 0 次、用例静默 SKIP。
    # 现在只用锚点本身，不绑定行首缩进 —— 缩进层级再变也不会失效。
    def c1(t):
        return inject('jc 前置',
                      t,
                      IND_ANCHOR,
                      '[pPr appendString:@"<w:jc w:val=\\"both\\"/>"]; ' + IND_ANCHOR)
    cases.append(('C9 pPr 顺序', c1, 'C9 pPr 顺序违规'))

    # 2) 删掉首行缩进 —— 正是 v22 及之前的真实状态。
    #    两种删法都要试：属性名写错（子串仍含 firstLineChars）和整条删掉。
    def c2a(t):
        return inject('缩进属性名错', t,
                      'w:firstLineChars=\\"%ld\\"', 'w:firstLineCharsX=\\"%ld\\"')
    cases.append(('C10 属性名写错', c2a, 'C10 没有首行缩进'))

    def c2b(t):
        return inject('删 firstLine 兜底', t,
                      ' w:firstLine=\\"%ld\\"', '')
    cases.append(('C10 缺 firstLine', c2b, 'C10 缺 w:firstLine'))

    # 3) 缩进 append 到段落变量上（不经过 pPr 变量）—— v19 的真缺陷形态
    def c3(t):
        return inject('缩进落到 pPr 外', t,
                      IND_ANCHOR,
                      '[out appendFormat:@"<w:ind w:firstLineChars=')
    cases.append(('C3 缩进跑到 pPr 外', c3, 'C3 段落变量上直接输出了 pPr 子元素'))

    # 4) <w:pPr> 包裹模板被去掉（属性变成裸输出）
    def c4(t):
        return inject('去掉 pPr 包裹', t,
                      '[out appendFormat:@"<w:pPr>%@</w:pPr>", pPr];',
                      '[out appendString:pPr];')
    cases.append(('C3 无 pPr 包裹', c4, 'C3 出现了段落属性字面量'))

    # 5) rPr 顺序颠倒：把 <w:rFonts> 整条挪到 <w:b/> 之后
    def c5(t):
        m = re.search(r'[ \t]*\[rPr appendFormat:\s*@"<w:rFonts[^;]*;', t, re.S)
        if not m:
            print('  [SKIP] rPr 乱序 —— 找不到 rFonts 语句')
            return False, t
        block = m.group(0)
        t2 = t.replace(block, '', 1)
        anchor = '[rPr appendString:@"<w:b/><w:bCs/>"];'
        if anchor not in t2:
            print('  [SKIP] rPr 乱序 —— 找不到粗体语句')
            return False, t
        return True, t2.replace(anchor, anchor + block, 1)
    cases.append(('C2 rPr 顺序', c5, 'C2 rPr 顺序违规'))

    # 6) 段落起手式被破坏（既没有 <w:p> 初始化，也不以 <w:p> append）
    #
    # 这一条实际报在 C1 上（C1 就是查「首个字面量是不是 <w:p>」），
    # 而不是 C3。所以期望串必须写成 C1 的原文 ——
    # 之前这里写的是 'C3'，而输出里恰好有多条 C3 的 OK 行，
    # 'in' 判断于是永远成立：又一条「注定通过」的假断言。
    def c6(t):
        return inject('段落起手式', t,
                      'NSMutableString *out = [NSMutableString stringWithString:@"<w:p>"];',
                      'NSMutableString *out = [NSMutableString string];')
    cases.append(('C1 段落起手式', c6, 'C1 CSFSRenderPara 首个字符串不是以'))

    passed = 0
    for name, fn, expect in cases:
        ok_inj, text = fn(src)
        if not ok_inj:
            continue
        out = run_checker(text)
        if expect in out and '[FAIL]' in out:
            # 打印命中的那条，便于核对「报的是不是对应那条」
            hit = [l.strip() for l in out.splitlines() if l.strip().startswith('[FAIL]')]
            print('  [ OK ] %-18s → 抓到：%s' % (name, hit[0] if hit else expect))
            passed += 1
        else:
            print('  [FAIL] %-18s → 注入缺陷后检查器没有报 %r' % (name, expect))
            print('         实际输出：')
            for l in out.splitlines():
                print('           ' + l)

    total = len([1 for n, f, e in cases])
    print('反向验证 %d/%d' % (passed, total))
    return 0 if passed == total else 1


if __name__ == '__main__':
    sys.exit(main())
