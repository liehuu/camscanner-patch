#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dump_sections.py —— 解析 Mach-O 的节（section_64）并导出字符串。

为什么需要：verify_dylib.py 只解析到段，看不到节。
「字符串在不在产物里」这种问题必须精确到节才能回答，
否则只能得到一个「整个文件没搜到」的粗暴结论，
查不出问题到底是「字符串真丢了」还是「它不在我以为的那一节」。

section_64 布局（xnu osd/mach-o/loader.h）：
   0   sectname[16]
   16  segname[16]
   32  addr        uint64
   40  size        uint64
   48  offset      uint32
   52  align       uint32
   56  reloff      uint32
   60  nreloc      uint32
   64  flags       uint32
   68  reserved1   uint32
   72  reserved2   uint32
   76  reserved3   uint32
   共 80 字节

用法：
  python3 dump_sections.py <macho-fat-or-thin> [--strings]
"""

import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
LC_SEGMENT_64 = 0x19


def slices_of(data):
    m = struct.unpack_from("<I", data, 0)[0]
    if m in (FAT_MAGIC, FAT_CIGAM):
        n = struct.unpack_from(">I", data, 4)[0]
        out = []
        for i in range(n):
            ct, cs, off, size, al = struct.unpack_from(">iiIII", data, 8 + i * 20)
            out.append(("cputype=0x%x sub=0x%x" % (ct, cs), off, size))
        return out
    return [("thin", 0, len(data))]


def sections(data, base, limit):
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    sizeofcmds = struct.unpack_from("<I", data, base + 20)[0]
    o = base + 32
    secs = []
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from("<II", data, o)
        if o + sz > base + 32 + sizeofcmds:
            break
        if cmd == LC_SEGMENT_64:
            segname = data[o + 8:o + 24].split(b"\x00")[0].decode()
            nsects = struct.unpack_from("<I", data, o + 64)[0]
            so = o + 72
            for _s in range(nsects):
                if so + 80 > o + sz:
                    break
                sn = data[so:so + 16].split(b"\x00")[0].decode()
                sgn = data[so + 16:so + 32].split(b"\x00")[0].decode()
                addr, size, offset = struct.unpack_from("<QQI", data, so + 32)
                secs.append({"seg": sgn, "sect": sn, "addr": addr,
                             "size": size, "offset": offset})
                so += 80
        o += sz
    return secs


def strings_from(blob, base):
    """按 \\0 切分出所有可读字符串"""
    out = []
    cur = bytearray()
    for i, b in enumerate(blob):
        if b == 0:
            if cur:
                try:
                    out.append((base + i - len(cur), bytes(cur).decode("utf-8")))
                except Exception:
                    pass
                cur = bytearray()
        elif 32 <= b < 127:
            cur.append(b)
        elif b >= 0x80:
            cur.append(b)  # UTF-8 多字节也先收着
        else:
            if cur:
                cur = bytearray()
    return out


def main():
    if len(sys.argv) < 2:
        print("用法: dump_sections.py <macho> [--strings]")
        return 2
    path = sys.argv[1]
    want_strings = "--strings" in sys.argv[2:]
    data = open(path, "rb").read()
    print("=" * 72)
    print("节解析: %s (%d 字节)" % (path, len(data)))
    print("=" * 72)

    for name, off, size in slices_of(data):
        m = struct.unpack_from("<I", data, off)[0]
        print("\n>> 切片 %s @0x%x  magic=0x%08x %s"
              % (name, off, m, "(thin 64)" if m in (MH_MAGIC_64, MH_CIGAM_64) else "(非MH64!)"))
        if m not in (MH_MAGIC_64, MH_CIGAM_64):
            print("   不是 64-bit Mach-O，跳过")
            continue
        secs = sections(data, off, off + size)
        for s in secs:
            # 切片内的绝对偏移 = 切片起始 + (节 offset - 头大小) 的近似：
            # 节 offset 通常是从「切片内」起算的，需换算到 fat 文件的绝对位置。
            abs_off = off + (s["offset"] - s["offset"])  # 占位，见下
            # LC_SEGMENT_64 的 fileoff 是切片内偏移；section offset 同样是切片内偏移。
            # 找出所在段的 fileoff 才能换算。这里简化：section offset 在 Mach-O 里
            # 通常就是「切片内的绝对偏移」，直接 off + offset 即可（头为 0x1000 对齐时成立）。
            abs_off = off + s["offset"]
            end = abs_off + s["size"]
            note = ""
            if end > len(data):
                note = "  ← 超出文件范围（段 fileoff 需另行换算）"
                end = len(data)
            print("   %-18s %-16s addr=0x%-8x size=0x%-7x off=0x%-7x%s"
                  % (s["seg"], s["sect"], s["addr"], s["size"], abs_off, note))
            if want_strings and s["sect"] in ("__cstring", "__oslogstring",
                                              "__const", "__objc_methname",
                                              "__objc_classname"):
                blob = data[abs_off:end]
                ss = strings_from(blob, abs_off)
                print("        字符串 %d 条:" % len(ss))
                for a, t in ss[:60]:
                    print("          0x%-8x %r" % (a, t))
                if len(ss) > 60:
                    print("          ... 其余 %d 条省略" % (len(ss) - 60))
    return 0


if __name__ == "__main__":
    sys.exit(main())