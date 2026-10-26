#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
decl_order.py —— 检查 C 语言的「声明早于使用」顺序问题。

为什么需要这个：
  C 没有 Hoisting。函数体内用到某个 static 变量/函数，而它的定义在文件更后面，
  clang 就报 use of undeclared identifier，整条 CI 白跑一轮 3~5 分钟。
  这类错误的共同点是：**纯文本就能判定**，完全不需要编译器。

  真实事故（2026-10-26，run 40270479654）：
    CSFSBeginSaveToFiles() 在 L394 使用 gOrigShareActionWithOperationTpe，
    而该指针定义在 L619 → 6 个 error，arm64 第一轮就挂。

  presyntax.py 的 P1~P6 都查不到这一条：括号是平的、块是配的、
  selector 也是可知的，只有「定义顺序」错了。所以单独做一项。

检查方式：
  1) 收集所有「文件级」定义（顶层行首的 static 定义）→ name → 行号
  2) 收集所有「函数体内」的首次使用行号
  3) 若某名字的首次使用早于定义 → FAIL

  为了让行号可信，先做一次词法清洗：
    - 注释、字符串内容抹成空格（长度/换行不变）
    - 预处理指令整行抹掉
  这样不会把注释里出现的名字算成「使用」。

用法：
  python3 tools/decl_order.py src/CamScannerSaveToFiles.m
退出码：0 通过 / 1 有问题
"""

import re
import sys


def blank_out(src):
    """把注释与字符串内容抹成空格，保持长度与换行不变。

    为什么必须等长：后续所有定位都用「字符下标 → 行号」换算，
    一旦长度变了，报出来的行号就是错的，查起来比不报还费时间。
    """
    out = list(src)
    n = len(src)
    i = 0

    def wipe(a, b):
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        # 行注释
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = i
            while j < n and src[j] != "\n":
                j += 1
            wipe(i, j)
            i = j
            continue
        # 块注释
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            wipe(i, j)
            i = j
            continue
        # 字符串 / 字符字面量
        if c in ('"', "'"):
            quote = c
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == quote:
                    j += 1
                    break
                if src[j] == "\n":
                    break
                j += 1
            # 连同两侧引号一起抹掉
            wipe(i, j)
            i = j
            continue
        i += 1

    # 预处理指令整行抹掉（#import / #define / #pragma 等）
    text = "".join(out)
    lines = text.split("\n")
    for k, ln in enumerate(lines):
        if ln.lstrip().startswith("#"):
            lines[k] = " " * len(ln)
    return "\n".join(lines)


def line_of(text, idx):
    return text.count("\n", 0, idx) + 1


# 文件级 static 定义。三种形态都要覆盖：
#   static BOOL gFlag = NO;
#   static NSInteger gType = 0x7B;
#   static BOOL (*gFn)(id, SEL, NSInteger) = NULL;   ← 由下面的 FNPTR 单独处理
#   static void CSFSFoo(void) {                      ← 函数定义（带左括号）
#   static NSString *const kName = @"x";
#
# 注意 rest 的写法 `[^;{}()]*[^;{}()\s]` + `\s+`：
#   必须「类型部分末尾是非空白、再接至少一个空白」。这条约束专门用来排除
#   `static BOOL (*gFn)(...)` 这类函数指针行 —— 那里 `BOOL` 后紧跟的是 `(`，
#   没有「类型 + 空白 + 名字」的结构，因而不会被误当成「定义了一个叫 BOOL 的变量」。
#   最初写成 `[^;{}()]*?` 就踩了这个坑：报出 BOOL / void 两个假阳性。
STATIC_DEF = re.compile(
    r"^static\s+"
    r"(?P<rest>[^;{}()=]*[^;{}()=\s])"  # 类型部分：末尾非空白，且不含 '='
    r"\s+"
    r"(?P<name>[A-Za-z_]\w*)"          # 名字
    r"\s*(?P<tail>\(|=|;)",
    re.M,
)

# 函数指针形态单独一条，因为类型部分里带括号
STATIC_FNPTR = re.compile(
    r"^static\s+[^;{}]*?\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)\s*\([^)]*\)\s*=",
    re.M,
)


def collect_defs(skel):
    defs = {}
    for m in STATIC_FNPTR.finditer(skel):
        name = m.group("name")
        defs.setdefault(name, line_of(skel, m.start()))
    for m in STATIC_DEF.finditer(skel):
        name = m.group("name")
        # 函数指针已被上面收过，避免把参数名当定义
        if name in defs:
            continue
        defs.setdefault(name, line_of(skel, m.start()))
    return defs


def main():
    if len(sys.argv) < 2:
        print("用法: decl_order.py <file.m>")
        return 2
    path = sys.argv[1]
    src = open(path, encoding="utf-8").read()
    skel = blank_out(src)

    defs = collect_defs(skel)
    if not defs:
        print("[FAIL] 没解析出任何文件级 static 定义，说明匹配规则失效了")
        return 1

    problems = []
    for name, def_line in sorted(defs.items(), key=lambda kv: kv[1]):
        # 找这个名字在「定义行之前」是否被用过
        pattern = re.compile(r"\b" + re.escape(name) + r"\b")
        first_use = None
        for m in pattern.finditer(skel):
            ln = line_of(skel, m.start())
            if ln >= def_line:
                break
            # 同一行内若正好是定义自身，跳过（一般不会，因为定义在后面）
            first_use = ln
            break
        if first_use is not None:
            problems.append((name, first_use, def_line))

    print("=" * 66)
    print("声明顺序检查（C 无 Hoisting）: %s" % path)
    print("=" * 66)
    print("  文件级 static 定义 %d 个" % len(defs))

    if problems:
        print()
        for name, use_line, def_line in problems:
            print("[FAIL] %s" % name)
            print("       首次使用 L%d，但定义在 L%d（晚了 %d 行）"
                  % (use_line, def_line, def_line - use_line))
            print("       clang 会报 use of undeclared identifier / "
                  "implicit-function-declaration")
        print()
        print("共 %d 处声明顺序错误" % len(problems))
        return 1

    print("[ OK ] 所有 static 定义均早于首次使用")
    return 0


if __name__ == "__main__":
    sys.exit(main())