#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
swap_dylib.py —— 在已注入的 ipa 里「原地替换」Frameworks 下的 dylib 内容。

与 pack_local.py 的区别（关键，别混用）：
  pack_local.py : 输入**未注入**的原始 ipa → 往主二进制里写 LC_LOAD_DYLIB
                  → 若输入已含 dylib 会二次注入，两条加载记录指向同一张
                    方法表，运行时双引擎互相覆盖，必崩。所以它主动拒绝。
  swap_dylib.py : 输入**已注入**的 ipa → 完全不碰主二进制，只把
                  Payload/.../Frameworks/<x>.dylib 这个条目的字节换掉。

为什么这个操作是安全的：
  主二进制里的 LC_LOAD_DYLIB 只有一条，路径是
  @executable_path/Frameworks/<x>.dylib，它加载的是「那个文件」，
  不关心文件内容是谁编的。换内容 = 换实现，加载记录条数不变。

用法：
  python3 tools/swap_dylib.py <injected.ipa> <new.dylib> -o out.ipa
"""

import argparse
import os
import shutil
import sys
import tempfile
import zipfile

DYLIB_REL = "Frameworks/CamScannerSaveToFiles.dylib"
INMEM_LIMIT = 48 * 1024 * 1024


def find_payload_prefix(zf):
    """返回 Payload/<X>.app/ 前缀（末尾带 '/'；不硬编码 app 名）。

    ⚠ 拼接时只能写成 prefix + REL，不能再自己加 '/'：
      v17 第一版写成 prefix + "/" + REL，产生 "Payload/X.app//Frameworks/..."
      双斜杠，zipfile.getinfo 直接 KeyError。zip 条目名是逐字节比对的，
      多余一个分隔符就是另一个名字。
    """
    prefs = set()
    for n in zf.namelist():
        if n.startswith("Payload/") and "/" in n[len("Payload/"):]:
            prefs.add(n[: n.index("/", len("Payload/")) + 1])
    if not prefs:
        raise SystemExit("ERROR: 找不到 Payload/*.app/")
    if len(prefs) > 1:
        raise SystemExit("ERROR: 多个 app 目录: %s" % prefs)
    return prefs.pop()  # 末尾已带 '/'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ipa")
    ap.add_argument("dylib")
    ap.add_argument("-o", "--out", default="")
    a = ap.parse_args()

    out = a.out or (os.path.splitext(a.ipa)[0] + "_swapped.ipa")
    new_dylib = open(a.dylib, "rb").read()
    print("新 dylib: %s (%d B, sha256=%s)" % (
        a.dylib, len(new_dylib),
        __import__("hashlib").sha256(new_dylib).hexdigest()[:16]))

    zin = zipfile.ZipFile(a.ipa, "r")
    prefix = find_payload_prefix(zin)
    target = prefix + DYLIB_REL
    print("Payload 前缀: %s" % prefix)
    print("替换目标   : %s" % target)

    old = zin.getinfo(target).file_size
    print("原 dylib   : %d B" % old)

    names = zin.namelist()

    # 定位主二进制：不能按「prefix 直接子文件且唯一」筛 —— app 根目录下有
    # 上万个资源文件（webp/nib/pag…），必然不唯一（v17 第一版就这么炸的，
    # 而且把整个 namelist 打了出来）。
    # 正确做法：按 **内容特征** 认 Mach-O，不靠路径名 —— 这也是
    # MEMORY 里那条「选文件必须校验内容，不能只信路径名」的直接应用。
    def is_macho(n):
        try:
            if zin.getinfo(n).file_size < 0x1000:
                return False
            with zin.open(n) as f:
                head = f.read(4)
        except Exception:
            return False
        # MH_MAGIC_64 / MH_CIGAM_64 / FAT_MAGIC / FAT_CIGAM
        return head in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")

    root_files = [n for n in names
                  if n.startswith(prefix) and n.count("/") == prefix.count("/")
                  and not n.endswith("/")]
    machos = [n for n in root_files if is_macho(n)]
    print("app 根目录文件 %d 个，其中 Mach-O %d 个: %s"
          % (len(root_files), len(machos), machos))
    if len(machos) != 1:
        raise SystemExit("ERROR: 主二进制定位不唯一，停止")
    main_bin = machos[0]

    # 防呆：确认主二进制里确实只有一条指向该 dylib 的加载记录。
    # 若有两条，说明这个包被二次注入过，运行时会有两个 dylib 改同一张
    # 方法表 —— 那是必崩场景，必须停下来而不是硬着头皮换文件。
    probe = b"CamScannerSaveToFiles.dylib"
    LOADCMD_SCAN = 0x800000  # 8MB 足够覆盖 CamScanner 的 load commands
    with zin.open(main_bin) as f:
        binhdr = f.read(LOADCMD_SCAN)
    cnt = binhdr.count(probe)
    print("主二进制 %s 中 '%s' 出现 %d 次（期望 1）"
          % (main_bin, probe.decode(), cnt))
    if cnt != 1:
        raise SystemExit("ERROR: LC_LOAD_DYLIB 记录数异常，停止以免双注入")

    # 逐条目复制，只替换目标 dylib
    total = len(names)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for i, n in enumerate(names):
            info = zin.getinfo(n)
            if n == target:
                zi = zipfile.ZipInfo(n, date_time=info.date_time)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = info.external_attr
                zout.writestr(zi, new_dylib)
                print("  [替换] %s" % n)
                continue
            if info.file_size <= INMEM_LIMIT:
                zi = zipfile.ZipInfo(n, date_time=info.date_time)
                zi.compress_type = info.compress_type
                zi.external_attr = info.external_attr
                zout.writestr(zi, zin.read(n))
            else:
                # 大条目流式拷贝，避免上百 MB 进内存
                zi = zipfile.ZipInfo(n, date_time=info.date_time)
                zi.compress_type = info.compress_type
                zi.external_attr = info.external_attr
                with zin.open(n) as src, zout.open(zi, "w") as dst:
                    shutil.copyfileobj(src, dst, 4 * 1024 * 1024)
            if (i + 1) % 1000 == 0:
                print("  ... %d/%d" % (i + 1, total))
    zin.close()

    print("\n完成: %s (%d B)" % (out, os.path.getsize(out)))
    print("条目数 原=%d 新=%d" % (total, len(zipfile.ZipFile(out).namelist())))


if __name__ == "__main__":
    main()