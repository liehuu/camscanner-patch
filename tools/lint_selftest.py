#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证 lint_dylib.py B3 的 dl 系列交叉核对逻辑。

本机 Windows 跑不了 xcrun nm，所以对判据做单元验证。
输入数据全部来自 CI run 40271172369 的真实输出：
    75 个未定义符号，其中 _dlsym / _fopen / _fclose 源码里不存在。
"""
import re
import sys


def strip_comments(text):
    """复刻 lint_dylib.py 的 strip_comments（只剥注释，保留字符串）。"""
    out = list(text)
    n = len(text)
    i = 0
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if c in ('"', "'"):
            q = c
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == q:
                    i += 1
                    break
                i += 1
            continue
        i += 1
    return "".join(out)


DL_SYMS = {"_dlsym", "dlsym", "_dlopen", "dlopen", "_dlclose", "_dladdr"}


def judge(missing, src_text):
    """复刻 B3 的 dl 分支。

    返回 (verdict, detail):
      ('pass', ...)   源码无 dl 调用 → 放行
      ('fail', ...)   源码有 dl 调用 → 拒绝
      ('warn', ...)   读不到源码 → 告警
      ('none', ...)   产物本身无 dl 符号
    """
    dl_in_bin = [s for s in missing if s in DL_SYMS]
    if not dl_in_bin:
        return ("none", "产物无 dl 符号")
    if src_text is None:
        return ("warn", "读不到源码")
    if re.search(r"\b(dlopen|dlsym|dlclose|dladdr)\s*\(", strip_comments(src_text)):
        return ("fail", "源码确实调用了 dl 系列")
    return ("pass", "源码无 dl 调用，属编译器自动引入")


CI_SYMBOLS = [
    "_CGRectGetMidX", "_CGRectGetMidY", "_NSClassFromString", "_NSLog",
    "_NSSelectorFromString", "_NSStringFromClass", "_NSStringFromSelector",
    "_OBJC_CLASS_$_NSArray", "_OBJC_CLASS_$_NSFileManager",
    "_OBJC_CLASS_$_NSMutableArray", "_OBJC_CLASS_$_NSNotificationCenter",
    "_OBJC_CLASS_$_NSObject", "_OBJC_EHTYPE_$_NSException",
    "_class_getInstanceMethod", "_dlsym", "_fclose", "_fopen",
    "dyld_stub_binder",
]

CLEAN_SRC = """
static BOOL CSFSHookInstance(Class cls, SEL sel, IMP newImp, IMP *outOrig) {
    Method m = class_getInstanceMethod(cls, sel);
    IMP orig = method_setImplementation(m, newImp);
    return YES;
}
"""

DIRTY_SRC = """
void *h = dlopen("/usr/lib/libsubstrate.dylib", RTLD_LAZY);
void *f = dlsym(h, "MSHookMessageEx");
"""

CASES = [
    # (说明, symbols, src, 期望 verdict)
    ("CI 真实符号集 + 干净源码（当前实际情况）",
     CI_SYMBOLS, CLEAN_SRC, "pass"),
    ("CI 真实符号集 + 源码里真有 dlopen（必须拦）",
     CI_SYMBOLS, DIRTY_SRC, "fail"),
    ("CI 真实符号集 + 读不到源码（应告警而非放行）",
     CI_SYMBOLS, None, "warn"),
    ("产物完全没有 dl 符号",
     ["_NSLog", "_objc_msgSend"], DIRTY_SRC, "none"),
    # 注释里出现 dlopen( 不是违规 —— 这是修正后的正确行为。
    # 本文件头就写着「不做 dlopen」，正文还有「绝对不能写 dlopen(...)」，
    # 如果把注释也算进去，R1 会把这些警示文字判成违规（假阳性），
    # 而下一个人为了「让检查变绿」就会去删掉注释，反而破坏文档。
    ("注释里出现 dlopen( 不算违规（必须放行）",
     CI_SYMBOLS, "// 这里绝对不能写 dlopen(\"/x.dylib\", RTLD_LAZY)\nint x = 1;\n", "pass"),
    ("块注释里出现 dlsym( 不算违规",
     CI_SYMBOLS, "/* 早期版本用过 dlsym(handle, \"foo\") */\nint x = 1;\n", "pass"),
]


def main():
    print("=" * 66)
    print("lint_dylib.py B3 dl 系列交叉核对验证")
    print("=" * 66)
    fails = 0
    for desc, syms, src, expect in CASES:
        verdict, detail = judge(syms, src)
        status = "PASS" if verdict == expect else "FAIL"
        if status == "FAIL":
            fails += 1
        print("[%s] %s" % (status, desc))
        print("       判定=%s（期望 %s）  %s" % (verdict, expect, detail))

    # ── 用真实源码文件验证 R1 的人工告警不会被注释误伤 ──────────────
    real_src = "src/CamScannerSaveToFiles.m"
    import os
    if os.path.isfile(real_src):
        raw = open(real_src, encoding="utf-8", errors="replace").read()
        raw_hit = re.search(r"\b(dlopen|dlsym|dlclose|dladdr)\s*\(", raw) is not None
        code_hit = re.search(r"\b(dlopen|dlsym|dlclose|dladdr)\s*\(",
                             strip_comments(raw)) is not None
        print()
        print("[%s] 真实源码 %s" % (
            "PASS" if (raw_hit and not code_hit) else "CHECK",
            real_src))
        print("       全文搜到 dl*(  = %s（注释里的警示文字）" % raw_hit)
        print("       剥注释后        = %s（真实调用）" % code_hit)
        print("       结论：不剥注释会把注释判成违规，剥掉之后判定准确")
        if raw_hit and not code_hit:
            pass  # 正是我们要证明的
        elif not raw_hit:
            print("       （该文件里连注释都没提 dl*，此用例仅供参考）")
    print()
    if fails:
        print("%d 项不符预期" % fails)
        return 1
    print("全部 %d 项符合预期" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())