#!/usr/bin/env python3
"""
check_classes.py — 校验目标二进制里确实存在预期的 ObjC 类名。

为什么不能直接用 `nm | grep _OBJC_CLASS_$_Xxx`
──────────────────────────────────────────────────────────────────
本包（扫描全能王 7.26.5）是 Flutter + Swift 混编产物，实测：

  $ nm -gU CamScanner_Lite | grep '_OBJC_CLASS_$_CSShareManager'
  （无输出）

二进制里根本不存在这种经典 ObjC 类符号。三个类名是以**裸 C 字符串**
形式躺在类名区（__objc_classname / __TEXT,__cstring 一带）：

  0x7d48de0  CSShareManager
  0x7d490d7  CSActivityUtil
  0x7d49a07  CSShareModel

若 CI 用符号表来判断，会 100% 误判为「不是目标应用」并把整条流水线拦死 ——
这属于「检查项本身写错」，比不检查更糟：它把真实的构建挡在门外。

为什么也不 `strings | grep -qx`
──────────────────────────────────────────────────────────────────
  - macOS 的 strings 有最小长度限制与截断行为，跨平台不一致
  - 在 set -o pipefail 下，grep 无匹配返回 1 会污染整条管道退出码
  - 无法区分 `CSShareManager` 与 `xxxCSShareManager`

本脚本的做法
──────────────────────────────────────────────────────────────────
字节级精确匹配 b"\\0{name}\\0"：
  - 前后必须有 NUL，保证是**完整的类名**，不会命中子串
  - 纯 Python 标准库，macOS / Linux / Windows 行为完全一致
  - 顺带报告出现次数与首个偏移，便于人工核对

用法：
  python3 check_classes.py <binary> ClassA [ClassB ...]
  python3 check_classes.py --list <binary>       列出候选类名（调试用）

退出码：0 全部存在；1 有缺失；2 用法或文件错误。
"""

import sys

# 判定为「类名」的启发式：ObjC/Swift 内部类名常见形态
import re
CLASSNAME_RE = re.compile(rb"^[A-Za-z_][A-Za-z0-9_]{2,120}$")


def check(binary, names):
    try:
        with open(binary, "rb") as f:
            blob = f.read()
    except OSError as e:
        print("::error::无法读取 %s: %s" % (binary, e))
        return 2

    print("== 类名存在性校验 ==")
    print("  binary: %s (%.1f MB)" % (binary, len(blob) / 1024 / 1024))

    missing = []
    for n in names:
        needle = b"\x00" + n.encode() + b"\x00"
        cnt = blob.count(needle)
        if cnt:
            first = blob.find(needle)
            print("  [ OK ] %-20s 出现 %d 次，首个 @0x%x"
                  % (n, cnt, first + 1))
        else:
            # 额外给一条诊断信息：是不是只作为子串存在（说明类名相近但不对）
            loose = blob.count(n.encode())
            if loose:
                print("  [FAIL] %-20s 没有完整类名，但作为子串出现 %d 次 "
                      "— 可能版本不同或类名已改" % (n, loose))
            else:
                print("  [FAIL] %-20s 完全不存在" % n)
            missing.append(n)

    if missing:
        print("\n::error::缺少预期类名: %s" % ", ".join(missing))
        print("        这不是目标应用，或版本与补丁不匹配。拒绝继续。")
        return 1

    print("\n全部存在，目标校验通过")
    return 0


def list_names(binary, limit=400):
    """列出二进制中看起来像类名的 C 字符串，供排查用。"""
    try:
        with open(binary, "rb") as f:
            blob = f.read()
    except OSError as e:
        print("无法读取 %s: %s" % (binary, e))
        return 2
    found = []
    for m in re.finditer(rb"\x00([A-Za-z_][A-Za-z0-9_]{3,120})\x00", blob):
        s = m.group(1)
        if CLASSNAME_RE.match(s):
            found.append(s.decode("ascii", "replace"))
    seen = set()
    uniq = []
    for s in found:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    print("共 %d 个候选字符串，前 %d 个：" % (len(uniq), limit))
    for s in uniq[:limit]:
        print("  ", s)
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    if argv[1] == "--list":
        if len(argv) < 3:
            print(__doc__)
            return 2
        return list_names(argv[2])
    binary = argv[1]
    names = argv[2:]
    if not names:
        print(__doc__)
        return 2
    return check(binary, names)


if __name__ == "__main__":
    sys.exit(main(sys.argv))