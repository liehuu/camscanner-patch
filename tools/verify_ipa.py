#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""核验「只换了 dylib」这件事真的成立。

为什么要单独核验：
    swap_dylib.py 会重打包整个 zip。它的实现只要有一处走偏
    （编码方式变了、时间戳变了、条目顺序变了、多写了 BUFFER 目录项），
    产物就是一个「看起来一样、装上却出问题」的包。
    装到设备上出问题，排查成本远高于这里跑 30 秒。

核验项：
  V1 条目名集合完全一致（零增删、零改名）
  V2 除目标 dylib 外，其余条目逐字节一致
  V3 主二进制 sha256 未变（确认没有被顺手改过）
  V4 IPA 内的 dylib 与 CI 产物 sha256 一致
  V5 目标 dylib 仅出现一次（不会命中错文件）

用法：
    python tools/verify_ipa.py old.ipa new.ipa --expect-dylib <ci dylib> \
        --main-bin Payload/CamScanner_Lite.app/CamScanner_Lite \
        --dylib-entry Payload/CamScanner_Lite.app/Frameworks/CamScannerSaveToFiles.dylib
"""
import argparse
import hashlib
import sys
import zipfile

fails = []


def ok(m):
    print("  [ OK ] " + m)


def bad(m):
    fails.append(m)
    print("  [FAIL] " + m)


def digest(z, name):
    return hashlib.sha256(z.read(name)).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("old")
    ap.add_argument("new")
    ap.add_argument("--expect-dylib", required=True)
    ap.add_argument("--main-bin", default="Payload/CamScanner_Lite.app/CamScanner_Lite")
    ap.add_argument("--dylib-entry",
                    default="Payload/CamScanner_Lite.app/Frameworks/CamScannerSaveToFiles.dylib")
    args = ap.parse_args()

    zo = zipfile.ZipFile(args.old)
    zn = zipfile.ZipFile(args.new)
    no = set(zo.namelist())
    nn = set(zn.namelist())

    # V1
    if no == nn:
        ok("V1 条目名集合完全一致（%d 条）" % len(no))
    else:
        bad("V1 条目集合不一致：多 %s / 少 %s"
            % (sorted(nn - no)[:5], sorted(no - nn)[:5]))

    # V5
    hits = [n for n in nn if n.endswith("CamScannerSaveToFiles.dylib")]
    if len(hits) == 1 and hits[0] == args.dylib_entry:
        ok("V5 目标 dylib 唯一：%s" % hits[0])
    else:
        bad("V5 目标 dylib 不唯一或路径不符：%s" % hits)

    # V2
    diff = []
    same = 0
    for n in sorted(no & nn):
        if n == args.dylib_entry:
            continue
        if hashlib.sha256(zo.read(n)).digest() != hashlib.sha256(zn.read(n)).digest():
            diff.append(n)
        else:
            same += 1
    if diff:
        bad("V2 除 dylib 外还有 %d 个条目被改动：%s" % (len(diff), diff[:5]))
    else:
        ok("V2 除 dylib 外逐字节一致（%d 条）" % same)

    # V3
    if args.main_bin in no and args.main_bin in nn:
        a, b = digest(zo, args.main_bin), digest(zn, args.main_bin)
        if a == b:
            ok("V3 主二进制未变 sha256=%s…" % a[:16])
        else:
            bad("V3 主二进制被改动：%s -> %s" % (a[:16], b[:16]))
    else:
        bad("V3 找不到主二进制 %s" % args.main_bin)

    # V4
    want = hashlib.sha256(open(args.expect_dylib, "rb").read()).hexdigest()
    got = digest(zn, args.dylib_entry)
    if want == got:
        ok("V4 IPA 内 dylib == CI 产物 sha256=%s…" % got[:16])
    else:
        bad("V4 dylib 不一致：期望 %s… 实际 %s…" % (want[:16], got[:16]))

    print("\nOK %d / FAIL %d" % (4 + 1 - len(fails), len(fails)))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
