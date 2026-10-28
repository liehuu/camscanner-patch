# -*- coding: utf-8 -*-
"""check_text_priority.py 的注入式反向验证。

为什么非做不可（记忆里的红线）：
    没做过反向验证的检查 = 没有检查。
    「拿 v21 跑全 FAIL」只证明这些断言在 v21 里不成立，
    不证明它们**真的在比顺序**——存在性检查也会这样全 FAIL。
    所以必须往 v22 里注入具体缺陷，看它能不能精确报出来。
"""
import io, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src', 'CamScannerSaveToFiles.m')
PY = sys.executable


def run(path):
    p = subprocess.run([PY, os.path.join(HERE, 'check_text_priority.py'), path],
                       capture_output=True, text=True, encoding='utf-8')
    return p.returncode, p.stdout


def case(name, mutate, expect_substr):
    src = io.open(SRC, encoding='utf-8').read()
    new = mutate(src)
    if new == src:
        print('  [FAIL] %s：注入没有生效（替换目标没找到）' % name)
        return False
    fd, tmp = tempfile.mkstemp(suffix='.m')
    os.close(fd)
    io.open(tmp, 'w', encoding='utf-8').write(new)
    try:
        rc, out = run(tmp)
    finally:
        os.remove(tmp)
    if rc == 0:
        print('  [FAIL] %s：注入缺陷后仍然全过 —— 这条检查是假的' % name)
        return False
    hit = [ln.strip() for ln in out.splitlines() if 'FAIL' in ln and expect_substr in ln]
    if not hit:
        print('  [FAIL] %s：报错了但不是预期的那条（期望含 %r）' % (name, expect_substr))
        print(out)
        return False
    print('  [ OK ] %s -> %s' % (name, hit[0][:90]))
    return True


def inj_d2(src):
    """把图片判据提到 CSFSSliceImageInfo 最前面 —— 模拟 v21 的顺序。

    注意：这里必须注入 **真正的判据调用** CSFSSTypeLooksImage(sl)，
    不能注入 `CSFSValue(sl, @"stype")`。第一版就是注入错了对象：
    检查已改成按函数名比位置，注入裸 stype 根本不触发，
    于是报「注入缺陷后仍然全过 —— 这条检查是假的」。
    那句报错本身是对的，错的是注入的东西不是它要拦的东西。
    """
    sig = 'static NSDictionary *CSFSSliceImageInfo(id sl) {'
    i = src.find(sig)
    if i < 0:
        return src
    j = i + len(sig)
    return src[:j] + '\n    (void)CSFSSTypeLooksImage(sl);' + src[j:]


def inj_d5(src):
    """在 IMAGE 分支开头先取一次图 —— 让取图排在取文字之前。"""
    sig = 'if ([bt isEqualToString:@"IMAGE"]) {'
    i = src.find(sig)
    if i < 0:
        return src
    j = i + len(sig)
    return src[:j] + '\n    (void)CSFSFindImage(block, 0);' + src[j:]


def inj_d4(src):
    """把白名单过滤加回去。"""
    old = 'if ([bt isEqualToString:@"LINE"]) {'
    new = 'if (![bt isEqualToString:@"PARA"]) {'
    if old not in src:
        return src
    return src.replace(old, new, 1)


def inj_d7(src):
    """抹掉 v22 统计行。"""
    return src.replace('v22 stats: types=', 'v21 stats: types=', 1)


def inj_d9(src):
    """去掉延后判定的条件 —— 退化成「抠不出文字就照旧出图」。"""
    old = 'if (imgTextCount > 0 || sliceTextWinCount > 0) {'
    new = 'if (0) {'
    if old not in src:
        return src
    return src.replace(old, new, 1)


def main():
    print('=== 注入式反向验证 ===')
    results = [
        case('D2 顺序（stype 提前）', inj_d2, 'D2 顺序错'),
        case('D5 顺序（取图提前）', inj_d5, 'D5 顺序错'),
        case('D4 白名单过滤回归', inj_d4, 'D4 仍存在'),
        case('D7 统计行缺失', inj_d7, 'D7 缺少'),
        case('D9 延后判定失效', inj_d9, 'D9 缺少'),
    ]
    bad = results.count(False)
    print('\n通过 %d / 失败 %d' % (len(results) - bad, bad))
    return 0 if bad == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
