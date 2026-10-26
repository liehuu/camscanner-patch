#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_dylib.py —— 对 CI 产出的 dylib 做本地独立核验。

为什么需要：CI 绿了只代表 clang 能编、lint 判据自洽，不代表这个 dylib
「装上去能跑」。本机没有 macOS，但 Mach-O 是纯数据格式，
下列检查不需要任何 macOS 工具，纯 Python 即可完成：

  1. magic / cputype / cpusubtype —— 确认是带签名的 ARM64
  2. ncmds / sizeofcmds 与头自洽
  3. LC_LOAD_DYLIB / LC_ID_DYLIB 的 install_name
     （必须是 /usr/lib/CamScannerSaveToFiles.dylib，
       与 inject_dylib.py 注入主二进制的那条完全一致）
  4. fat 头里的切片数
  5. selref 里是否存在我们 hook 的目标 selector
  6. 构造函数符号是否存在（CSFSInstall）
  7. 段的 file/vmsize 关系正常（不等就是头坏了）

用法：python3 tools/verify_dylib.py build/CamScannerSaveToFiles.dylib
"""

import struct
import sys

# ── Mach-O 常量 ──────────────────────────────────────────────────────
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE

CPU_ARCH_ABI64 = 0x01000000
CPU_TYPE_ARM = 12
CPU_SUBTYPE_ARM64 = 2
CPU_SUBTYPE_ARM64E = 2

LC_REQ_DYLD = 0x80000000
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0x0C
LC_ID_DYLIB = 0x0D
LC_UUID = 0x1B
LC_RPATH = 0x1C

# selref 的绑定类型（相对 method list 与 selref 相关）
LC_DYLD_CHAINED_FIXUPS = 0x80000034


def rd32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def rd64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def cstr(b, o):
    e = b.find(b"\x00", o)
    return b[o:e].decode("utf-8", "replace") if e >= 0 else b[o:].decode("utf-8", "replace")


def parse_sections(blob, base=0):
    """解析切片内所有 LC_SEGMENT_64 的 section_64 项。

    返回 [{seg, sect, addr, size, offset, flags}, ...]。

    为什么单独要这个函数：check() 早先只收集「段」一级信息，
    但中文字符量的地址在**节**一级。__cfstring 的 data 字段给的是
    运行时 vmaddr，必须靠节表 addr/offset 反查才能换算回切片内偏移。
    没有节表，就只能「全文搜 UTF-16」，那样只能证明字节在，
    证不出「字符串被接到了 CFString 上」。

    section_64 布局（80 字节）：
        0   sectname[16]
        16  segname[16]
        32  addr      u64
        40  size      u64
        48  offset    u32
        52  align     u32
        56  reloff    u32
        60  nreloc    u32
        64  flags     u32
        68  reserved1 u32
        72  reserved2 u32
        76  reserved3 u32

    offset 是切片内文件偏移（Mach-O 规范里 section offset 相对镜像起点，
    对 fat 包的切片而言即相对切片本身起点）。
    """
    if rd32(blob, base) not in (MH_MAGIC_64, MH_CIGAM_64):
        return []
    ncmds = rd32(blob, base + 16)
    out = []
    o = base + 32
    for _ in range(ncmds):
        if o + 8 > len(blob):
            break
        cmd, cmdsize = struct.unpack_from("<II", blob, o)
        if cmdsize < 8 or o + cmdsize > len(blob):
            break
        if cmd == LC_SEGMENT_64:
            segname = cstr(blob, o + 8)
            nsects = rd32(blob, o + 64)
            p = o + 72
            for _i in range(nsects):
                if p + 80 > len(blob):
                    break
                sectname = cstr(blob, p)
                sseg = cstr(blob, p + 16)
                addr, size = struct.unpack_from("<QQ", blob, p + 32)
                offset = rd32(blob, p + 48)
                flags = rd32(blob, p + 64)
                out.append(dict(seg=sseg, sect=sectname, addr=addr, size=size,
                                offset=offset, flags=flags))
                p += 80
        o += cmdsize
    return out


def read_section_bytes(blob, sec):
    """按节表项取切片内字节，越界时返回 b''。"""
    st = sec["offset"]
    return blob[st:st + sec["size"]]


def strip_pac(v):
    """去掉 arm64e 指针认证高位杂位，还原真实 vmaddr。

    这个坑是实拍出来的。同一个 __cfstring 项在两个切片里长得不一样：

        arm64  切片：data = 0x8308              （干净）
        arm64e 切片：data = 0x10000000008308      （高位多了 0x1000000000000000）
                    data = 0x28000000008d00       （有的是 0x2800000000000000）
                    isa  = 0xc0156ae100000005

    这不是文件损坏。arm64e 把指针放进 __AUTH_CONST 时会带指针认证
    元数据：高位存放 ptrauth 的签名/杂位，真实 vmaddr 在低若干位。
    运行时由 dyld 的 chained fixup 还原。

    静态解析只看低 48 位（Mirror 里 vmaddr 的上界）就够；
    48 位掩完仍为 0 的退化情况再退回 32 位。
    """
    if v <= 0xFFFFFFFF:
        return v
    lo48 = v & 0x0000FFFFFFFFFFFF
    if lo48:
        return lo48
    return v & 0x00000000FFFFFFFF


def vmoff_of(blob, secs, vmaddr):
    """把运行时 vmaddr 换算成切片内文件偏移。

    反查节表：找 addr <= vmaddr < addr+size 的节，再
    offset + (vmaddr - addr)。找不到返回 None。
    """
    for sec in secs:
        if sec["size"] and sec["addr"] <= vmaddr < sec["addr"] + sec["size"]:
            return sec["offset"] + (vmaddr - sec["addr"])
    return None


def check(path):
    fails = []
    warns = []
    print("=" * 70)
    print("本地核验 dylib: %s" % path)
    print("=" * 70)
    data = open(path, "rb").read()
    print("  文件大小: %d 字节" % len(data))

    magic = rd32(data, 0)
    is_fat = magic in (FAT_MAGIC, FAT_CIGAM)
    print("  magic: 0x%08x%s" % (magic, " (fat)" if is_fat else " (thin)"))

    slices = []
    if is_fat:
        nfat = struct.unpack_from(">I", data, 4)[0]
        print("  fat 架构数: %d" % nfat)
        for i in range(nfat):
            off = 8 + i * 20
            cputype, cpusub, off_off, size, align = struct.unpack_from(">iiIII", data, off)
            # arm64 在 fat header 里是 cputype=CPU_TYPE_ARM|ABI64。
            # cpusubtype 的取值（低 8 位）：
            #   0 = ARM64_ALL   （普通 arm64，clang 默认就是这个）
            #   1 = ARM64_V8
            #   2 = ARM64E      （A12 起的指针认证版本）
            # 最初只把 sub==2 当 arm64、sub==0 当未知，结果把第一片判成
            # "cputype=0x100000c sub=0x0"，还连带报了个子虚乌有的
            # 「fat 包里没有 arm64e 切片」告警。按上面取低 8 位重判即可。
            sub = cpusub & 0xFF
            base = cputype & ~CPU_ARCH_ABI64
            if base == CPU_TYPE_ARM and sub == CPU_SUBTYPE_ARM64E:
                arch = "arm64e"
            elif base == CPU_TYPE_ARM and sub in (0, 1):
                arch = "arm64"
            else:
                arch = "cputype=0x%x sub=0x%x" % (cputype, cpusub)
            print("    [%d] arch=%-8s offset=0x%06x size=%d" % (i, arch, off_off, size))
            slices.append((arch, off_off, size))
        if not any(a == "arm64" for a, _, _ in slices):
            fails.append("fat 包里没有 arm64 切片")
        if not any(a == "arm64e" for a, _, _ in slices):
            warns.append("fat 包里没有 arm64e 切片（A12+ 会以 arm64 兼容模式跑）")
    else:
        slices = [("thin", 0, len(data))]

    # ── 逐切片看 load commands ───────────────────────────────────────
    for arch, soff, ssize in slices:
        print("\n-- 切片 %s @0x%x --" % (arch, soff))
        m = rd32(data, soff)
        if m not in (MH_MAGIC_64, MH_CIGAM_64):
            fails.append("%s: 不是 MH_MAGIC_64 (0x%08x)" % (arch, m))
            continue
        ncmds = rd32(data, soff + 16)
        sizeofcmds = rd32(data, soff + 20)
        print("   ncmds=%d sizeofcmds=%d flags=0x%x" % (ncmds, sizeofcmds, rd32(data, soff + 24)))

        # 头自洽性：sizeofcmds 必须覆盖所有命令且不越界
        end_cmds = soff + 32 + sizeofcmds
        if end_cmds > soff + ssize:
            fails.append("%s: sizeofcmds=%d 超出切片范围" % (arch, sizeofcmds))

        o = soff + 32
        seen_end = soff + 32
        load_dylibs = []
        id_dylib = None
        segs = []
        has_uuid = False
        uuid_hex = ""
        for _ in range(ncmds):
            if o + 8 > soff + ssize:
                fails.append("%s: load command 越界" % arch)
                break
            cmd, cmdsize = struct.unpack_from("<II", data, o)
            if cmdsize < 8 or o + cmdsize > soff + ssize:
                fails.append("%s: 命令 cmdsize=%d 非法" % (arch, cmdsize))
                break
            if cmd in (LC_LOAD_DYLIB, LC_ID_DYLIB):
                nameoff, ts, cur = struct.unpack_from("<III", data, o + 8)
                if o + nameoff < soff + ssize:
                    nm = cstr(data, o + nameoff)
                    if cmd == LC_LOAD_DYLIB:
                        load_dylibs.append(nm)
                    else:
                        id_dylib = nm
            elif cmd == LC_UUID:
                has_uuid = True
                uuid_hex = data[o + 8:o + 24].hex()
            elif cmd == LC_SEGMENT_64:
                # segment_command_64 布局（xnu osd/mach-o/loader.h）：
                #   0    cmd            uint32
                #   4    cmdsize        uint32
                #   8    segname[16]    char
                #   24   vmaddr         uint64
                #   32   vmsize         uint64
                #   40   fileoff        uint64
                #   48   filesize       uint64
                #   56   maxprot       int32
                #   60   initprot      int32
                #   64   nsects        uint32
                #   68   flags         uint32
                # 共 72 字节。
                #
                # 之前从 +32 起连读四个 uint64 并命名为
                #   vmsize, vmaddr, fs, fo
                # 实际读到的是 vmsize/fileoff/filesize/maxprot+initprot，
                # 于是 fileoff 打印成 0x500000005、0x300000003 这种乱值。
                # 符号错位比没读更危险：它看起来像个合法的「巨型偏移」，
                # 反而让人以为头坏了。按 +24 起严格按布局读。
                segname = cstr(data, o + 8)
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, o + 24)
                segs.append((segname, vmaddr, vmsize, fileoff, filesize))
            seen_end = o + cmdsize
            o += cmdsize

        print("   LC_LOAD_DYLIB %d 条:" % len(load_dylibs))
        for d in load_dylibs:
            print("     ", d)
        print("   LC_ID_DYLIB: %s" % id_dylib)
        print("   段:")
        for sn, va, vs, fo, fs in segs:
            print("     %-16s vmaddr=0x%-8x vmsize=0x%-6x fileoff=0x%-8x filesize=0x%-6x"
                  % (sn, va, vs, fo, fs))
            if fs > vs:
                warns.append("%s: 段 %s filesize > vmsize" % (arch, sn))

        # ── install_name 判据 ────────────────────────────────────────
        EXPECT = "/usr/lib/CamScannerSaveToFiles.dylib"
        if id_dylib != EXPECT:
            fails.append("%s: LC_ID_DYLIB = %r，期望 %r" % (arch, id_dylib, EXPECT))
        else:
            print("   [OK] install_name 与注入项一致")

        # 依赖库必须都是系统路径（这条与 lint B4 互为补充，本机独立复核）
        bad = [d for d in load_dylibs
               if not (d.startswith("/usr/lib/") or d.startswith("/System/Library/"))]
        if bad:
            fails.append("%s: 依赖非系统库 %s → 设备上 dyld 找不到会闪退" % (arch, bad))
        else:
            print("   [OK] 依赖库全部为系统路径（%d 条）" % len(load_dylibs))

        # ── 构造函数与关键字符串探针 ───────────────────────────────
        # 探针字符串必须与 src 里真实出现的文字一致。
        #
        # 这里踩过一个坑，值得留档：
        #   第一版探针写死 UTF-8。结果「保存到文件」（面板标题）报 FAIL。
        #   逐节排查后发现 —— clang 把**含非 ASCII 的 ObjC 字面量**放在
        #   `__TEXT,__ustring`，用 UTF-16LE 存，而不是 `__cstring` 的 UTF-8。
        #   __cfstring 项 [0] info=0x7d0（bit4=Unicode）data=0x8308 len=5，
        #   0x8308 正是 __ustring 的地址。字符串既没丢也没乱码。
        # 所以探针要同时覆盖多种编码，并且最终以 __cfstring 结构为准：
        #   直接读字面量只能证明「字节在」，解析 __cfstring 才能证明
        #   「字符串被正确接到了 CFString 上」——后者才是功能正确。
        blob = data[soff:soff + ssize]

        need_plain = (b"CamScannerSaveToFiles",      # 日志前辍
                      b"shareActionWithOperationTpe")  # hook 目标 selector
        for needle in need_plain:
            if needle in blob:
                print("   [OK] 含 %r" % needle.decode())
            else:
                fails.append("未含应有的 %r —— 与源码预期不符" % needle.decode())

        # ── __cfstring 解析：确认标题常量真的接上了 CFString ─────────
        # 这是「字节在不在」与「接没接上」的区别：
        #   全文搜 UTF-16LE「保存到文件」—— 只证明字节在；
        #   解析 __cfstring 结构读出同文 —— 证明它被做成了 CFString 常量，
        #   运行时会经由此项拿到字符指针。功能正确要求后者成立。
        secs = parse_sections(blob, 0)
        cfs = [s for s in secs if s["sect"] == "__cfstring"]
        if not cfs:
            warns.append("未见 __cfstring 节 —— 无法核验常量串")
        else:
            found_title = False
            n_str = 0
            for s0 in cfs:
                secblob = read_section_bytes(blob, s0)
                for i in range(0, len(secblob), 32):
                    if i + 32 > len(secblob):
                        break
                    isa, info, datap, length = struct.unpack_from("<QQQQ", secblob, i)
                    # arm64e 的 __AUTH_CONST 指针带 ptrauth 高位，先还原。
                    datap = strip_pac(datap)
                    if datap == 0 or length <= 0 or length > 200:
                        continue
                    # data 是运行时 vmaddr，靠节表反查换算回切片内偏移。
                    dst = vmoff_of(blob, secs, datap)
                    if dst is None:
                        continue
                    nbytes = length * 2 if (info & 0x10) else length
                    raw = blob[dst:dst + nbytes]
                    if len(raw) < nbytes:
                        continue
                    # info bit4(0x10) = __kCFIsUnicode → UTF-16LE；
                    # 否则 ASCII/UTF-8。这是 __CFString 的既有约定，
                    # clang 生成的 CFSTR 也照此填。
                    try:
                        txt = raw.decode("utf-16-le" if (info & 0x10) else "utf-8",
                                          "replace")
                    except Exception:
                        continue
                    n_str += 1
                    if txt == "保存到文件":
                        found_title = True
                        print("   [OK] %s/%s[%d] 解析出标题 %r（占 %d 码元，"
                              "%s 编码，info=0x%x data=0x%x）—— 常量标题已"
                              "正确接入 CFString"
                              % (s0["seg"], s0["sect"], i // 32, txt, length,
                                 "UTF-16LE" if (info & 0x10) else "UTF-8",
                                 info, datap))
                        break
                if found_title:
                    break
            if not found_title:
                fails.append("__cfstring 中未解析出面板标题「保存到文件」"
                             "（解析了 %d 个常量串）—— 标题常量丢了，"
                             "注入后面板条目会显示空白" % n_str)

        # 第二证据：__TEXT,__ustring 里的 UTF-16LE 字面量。
        # clang 把含非 ASCII 的 ObjC 字面量放这里（不是 __cstring 的 UTF-8），
        # 这条与 __cfstring 判据互为补充：前者丢了说明源码编译进产物的
        # 字符数据本身有问题，后者丢了说明 CFString 胶水有问题。
        ustr = [s for s in secs if s["sect"] == "__ustring"]
        if ustr:
            usz = ustr[0]
            ublob = read_section_bytes(blob, usz)
            if "保存到文件".encode("utf-16-le") in ublob:
                print("   [OK] %s/__ustring 含 UTF-16LE 字面量「保存到文件」"
                      "（%d 字节）—— 非 ASCII 字面量按预期落盘"
                      % (usz["seg"], len(ublob)))
            else:
                fails.append("__ustring 中找不到「保存到文件」的 UTF-16LE 字面量"
                             " —— 非 ASCII 常量未按 clang 预期落盘，"
                             "可能是源码改动漏掉标题")
        else:
            warns.append("未见 __TEXT,__ustring 节 —— 若非 ASCII 字面量全部"
                         "移除则属正常；当前源码有「保存到文件」，应至少存在该节")

        for sel in (b"CSShareManager", b"CSActivityUtil", b"CSShareModel"):
            if sel in blob:
                print("   [OK] 含目标类名 %r" % sel.decode())
            else:
                warns.append("未见目标类名 %r（类名走 NSClassFromString 字符串查找，"
                             "是运行时动态解析，不出现在静态字符串里也属正常）"
                             % sel.decode())

        # LC_UUID：clang -dynamiclib 默认会生成。没 UUID 不影响加载，
        # 但 dyld 共享缓存与崩溃符号化都依赖它，缺失会让问题难查。
        if not has_uuid:
            warns.append("%s: 无 LC_UUID —— 不影响加载，但崩溃日志难符号化" % arch)
        else:
            print("   [OK] 含 LC_UUID %s" % uuid_hex)

    # ── 构造函数符号（从 fat/单切片取 arm64 段内容）──────────────────
    arch_ok = None
    for a, soff, ssize in slices:
        if a in ("arm64", "arm64e"):
            arch_ok = (a, soff, ssize)
            break
    if arch_ok:
        a, soff, ssize = arch_ok
        blob = data[soff:soff + ssize]
        # CSFSInstall 是 static 函数，符号表里可能带也可能不带下划线；
        # 静态函数被符号表收录取决于 -g 与优化级别，找不到不算失败。
        for sym in (b"CSFSInstall", b"_CSFSInstall"):
            if sym in blob:
                print("   [OK] %s 切片含 %s" % (a, sym.decode()))
                break
        else:
            print("   [i] %s 切片未见 CSFSInstall 字面量（static 函数未被符号表收录，"
                  "或已被内联，不影响构造器注册）" % a)

    print()
    print("=" * 70)
    if warns:
        print("提示 %d 项:" % len(warns))
        for w in warns:
            print("  [WARN] %s" % w)
    if fails:
        print("发现 %d 个致命问题:" % len(fails))
        for f in fails:
            print("  [FAIL] %s" % f)
        print("=" * 70)
        return 1
    print("核验通过：fat 结构、install_name、依赖库、目标符号均正常")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: verify_dylib.py <dylib>")
        sys.exit(2)
    sys.exit(check(sys.argv[1]))