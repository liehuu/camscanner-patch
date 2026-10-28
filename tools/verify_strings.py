# -*- coding: utf-8 -*-
"""在编译产物里核验特征字符串（UTF-8 或 UTF-16LE 任一命中即可）。

⚠ 为什么不只是「strings | grep」：
    这些字符串在 Mach-O 里以 NSString 字面量存放，实际编码是 **UTF-16LE**。
    第一轮排查时用 ASCII 搜不到，误判成「CI 编的是旧代码」，
    白跑了一轮（当时的结论是错的，代码是对的）。

用法：
    python tools/verify_strings.py build/CamScannerSaveToFiles.dylib \
        --need "v22 new block type:" "v22 stats: types=[" ...
"""
import argparse
import hashlib
import io
import sys


def find_any(blob, s):
    for enc in ("utf-16-le", "utf-8"):
        if s.encode(enc) in blob:
            return enc
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dylib")
    ap.add_argument("--need", nargs="+", required=True)
    args = ap.parse_args()

    blob = io.open(args.dylib, "rb").read()
    print("file  : %s" % args.dylib)
    print("size  : %d B" % len(blob))
    print("sha256: %s" % hashlib.sha256(blob).hexdigest())

    miss = []
    for s in args.need:
        enc = find_any(blob, s)
        if enc:
            print("  [ OK ] %-45s %s" % (s, "utf-16-le" if enc == "utf-16-le" else "utf-8"))
        else:
            miss.append(s)
            print("  [MISS] %s" % s)

    print("\n命中 %d / 缺失 %d" % (len(args.need) - len(miss), len(miss)))
    return 0 if not miss else 1


if __name__ == "__main__":
    sys.exit(main())
