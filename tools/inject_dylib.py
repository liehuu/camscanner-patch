#!/usr/bin/env python3
"""
inject_dylib.py — 向 arm64 Mach-O 主二进制注入一条 LC_LOAD_DYLIB。

不依赖 optool / insert_dylib（这两个在 macOS CI 上是外部依赖，且对新格式的
chained fixups 版本兼容性不一致）。本脚本只做一件事：

  在 32 + sizeofcmds 之后、第一个有文件实体的小节之前，
  找一个 8 字节对齐的空位写入 LC_LOAD_DYLIB，并同步更新
  mach_header_64.ncmds / sizeofcmds。

安全前提（脚本会主动校验，不满足就报错退出，绝不生成半成品）：
  1. 必须是 MH_MAGIC_64 / CPU_TYPE_ARM64 / MH_EXECUTE
  2. headerpad 必须容得下新增的 load command
  3. 不得已存在指向同名 dylib 的 LC_LOAD_DYLIB（幂等）
  4. 新增命令区不得与任何已有 load command 重叠

用法：
  python3 inject_dylib.py <macho> <dylib_install_name>
  python3 inject_dylib.py --check <macho> <dylib_install_name>
"""

import struct
import sys
import os
import re

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
MH_EXECUTE = 0x2
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LOAD_UPWARD_DYLIB = 0x80000023


class MachO:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = bytearray(f.read())
        self._parse_header()

    def _parse_header(self):
        d = self.data
        if len(d) < 32:
            raise SystemExit("FAIL: file too small to be Mach-O")
        self.magic, self.cputype, self.cpusubtype, self.filetype, \
            self.ncmds, self.sizeofcmds, self.flags, self.reserved = \
            struct.unpack_from("<IiiIIII I".replace(" ", ""), d, 0)
        if self.magic != MH_MAGIC_64:
            raise SystemExit("FAIL: not MH_MAGIC_64 (0x%x)" % self.magic)
        if self.cputype != CPU_TYPE_ARM64:
            raise SystemExit("FAIL: not arm64 (cputype=0x%x)" % self.cputype)
        if self.filetype != MH_EXECUTE:
            raise SystemExit("FAIL: not MH_EXECUTE (filetype=%d)" % self.filetype)
        self.hdr_end = 32 + self.sizeofcmds
        self.cmds = []
        p = 32
        for _ in range(self.ncmds):
            if p + 8 > len(d):
                raise SystemExit("FAIL: load command table runs past EOF")
            cmd, cmdsize = struct.unpack_from("<II", d, p)
            if cmdsize < 8 or p + cmdsize > self.hdr_end:
                raise SystemExit("FAIL: bad cmdsize %d at 0x%x" % (cmdsize, p))
            self.cmds.append((p, cmd, cmdsize))
            p += cmdsize

    # ── 已有的 LC_LOAD_DYLIB 名称 ────────────────────────────────────
    def dylib_names(self):
        out = []
        for (p, cmd, cmdsize) in self.cmds:
            if cmd not in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB,
                           LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB):
                continue
            name_off = struct.unpack_from("<I", self.data, p + 8)[0]
            start = p + name_off
            end = self.data.find(b"\x00", start, p + cmdsize)
            if end == -1:
                end = p + cmdsize
            out.append(self.data[start:end].decode("utf-8", "replace"))
        return out

    # ── header 之后的可用空洞 ───────────────────────────────────────
    def headerpad(self):
        """返回 (free_start, free_size)：紧跟 load command 表之后的连续空洞"""
        first_off = None
        for seg in self._segments():
            for sec in seg["sections"]:
                # 只要在文件中有实体（S_ZEROFILL/thread_local 之类的 off 为 0 或不算）
                flags_type = sec["flags"] & 0xFF
                if flags_type in (0x1,):        # S_ZEROFILL / S_GB_ZEROFILL / S_THREAD_LOCAL_ZEROFILL
                    continue
                if sec["offset"] <= 0:
                    continue
                if first_off is None or sec["offset"] < first_off:
                    first_off = sec["offset"]
        # 有些文件还有 __LINKEDIT / 头部自身，用最小的非零 offset 兜底
        if first_off is None:
            first_off = self.hdr_end
        return self.hdr_end, max(0, first_off - self.hdr_end)

    def _segments(self):
        out = []
        for (p, cmd, cmdsize) in self.cmds:
            if cmd != LC_SEGMENT_64:
                continue
            segname = self.data[p + 8:p + 24].split(b"\x00")[0].decode("ascii", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", self.data, p + 24)
            nsects = struct.unpack_from("<I", self.data, p + 64)[0]
            secs = []
            sp = p + 72
            for _ in range(nsects):
                sname = self.data[sp:sp + 16].split(b"\x00")[0].decode("ascii", "replace")
                sseg = self.data[sp + 16:sp + 32].split(b"\x00")[0].decode("ascii", "replace")
                size = struct.unpack_from("<Q", self.data, sp + 40)[0]
                offset = struct.unpack_from("<I", self.data, sp + 48)[0]
                flags = struct.unpack_from("<I", self.data, sp + 64)[0]
                secs.append(dict(name=sname, seg=sseg, size=size, offset=offset, flags=flags))
                sp += 80
            out.append(dict(name=segname, vmaddr=vmaddr, vmsize=vmsize,
                            fileoff=fileoff, filesize=filesize, sections=secs))
        return out


def build_load_dylib(name, timestamp=2):
    raw = name.encode("utf-8") + b"\x00"
    # dylib_command: cmd(4) cmdsize(4) name_offset(4) timestamp(4)
    #                current_version(4) compatibility_version(4)
    hdr = 24
    total = hdr + len(raw)
    total = (total + 7) & ~7
    buf = bytearray(total)
    struct.pack_into("<IIIIII", buf, 0, LC_LOAD_DYLIB, total, hdr,
                     timestamp, 0x10000, 0x10000)
    buf[hdr:hdr + len(raw)] = raw
    return bytes(buf)


def main(argv):
    check_only = False
    args = [a for a in argv[1:] if not a.startswith("--")]
    if "--check" in argv:
        check_only = True
    if len(args) != 2:
        raise SystemExit(__doc__)
    macho_path, install_name = args

    # ─────────────────────────────────────────────────────────────────
    # install_name 健全性校验（这是真实事故的防线，不是洁癖）
    #
    # 事故：在 Windows 的 Git Bash 里执行
    #     python inject_dylib.py bin /usr/lib/CamScannerSaveToFiles.dylib
    # MSYS2 会把以 / 开头的参数当作路径自动转换，写进二进制的实际变成
    #     C:/Users/xxx/.../PortableGit/usr/lib/CamScannerSaveToFiles.dylib
    # 命令表结构完全正常、ncmds 也对，但 dyld 在设备上永远找不到这个库：
    # 要么启动即闪退（库标了必须加载），要么补丁静默失效。
    # 这种错误「编译能过、注入能过、签名能过」，只有真机跑才炸 ——
    # 所以必须在写盘前就拦死。
    # ─────────────────────────────────────────────────────────────────
    if re.match(r"^[A-Za-z]:[\\/]", install_name) or install_name.startswith("/c/"):
        raise SystemExit(
            "FAIL: install_name 被错误转换为本地 Windows 路径:\n"
            "      %s\n"
            "      在 Git Bash 下请用单引号包裹或用 MSYS_NO_PATHCONV=1 重试。\n"
            "      正确值应形如: /usr/lib/Foo.dylib" % install_name)

    if not (install_name.startswith("/") or
            install_name.startswith("@rpath/") or
            install_name.startswith("@executable_path/") or
            install_name.startswith("@loader_path/")):
        raise SystemExit(
            "FAIL: install_name 非法: %s\n"
            "      必须是绝对路径或以 @rpath/ @executable_path/ @loader_path/ 开头"
            % install_name)

    # 路径里不允许出现反斜杠、空格、换行（dyld 解析会截断且难以排查）
    for bad in ("\\", "\n", "\r", "\t"):
        if bad in install_name:
            raise SystemExit("FAIL: install_name 含非法字符 %r: %s"
                             % (bad, install_name))
    if " " in install_name:
        raise SystemExit("FAIL: install_name 含空格，dyld 解析不可靠: %s" % install_name)

    mo = MachO(macho_path)
    existing = mo.dylib_names()
    free_start, free_size = mo.headerpad()
    need = len(build_load_dylib(install_name))

    print("== Mach-O 检查 ==")
    print("  file            :", macho_path)
    print("  ncmds           :", mo.ncmds)
    print("  sizeofcmds      : 0x%x" % mo.sizeofcmds)
    print("  header end      : 0x%x" % free_start)
    print("  headerpad free  : %d bytes" % free_size)
    print("  need            : %d bytes" % need)

    if install_name in existing:
        print("== 已注入，无需操作 ==")
        return 0

    if need > free_size:
        raise SystemExit("FAIL: 头部空洞不足（need=%d, free=%d）" % (need, free_size))

    # 对齐到 8 字节
    pad = (8 - (free_start % 8)) % 8
    write_at = free_start + pad
    if write_at + need > free_start + free_size:
        raise SystemExit("FAIL: 对齐后空间不足")

    # 与已有命令不重叠（free_start 已经是表尾，天然不重叠，这里做一次断言）
    for (p, cmd, cmdsize) in mo.cmds:
        if write_at < p + cmdsize and p < write_at + need:
            raise SystemExit("FAIL: 新增命令与已有 load command 重叠 @0x%x" % p)

    print("  write at        : 0x%x" % write_at)

    if check_only:
        print("== --check 通过，未写入 ==")
        return 0

    blob = build_load_dylib(install_name)
    mo.data[write_at:write_at + len(blob)] = blob
    # 更新 header
    struct.pack_into("<I", mo.data, 16, mo.ncmds + 1)
    struct.pack_into("<I", mo.data, 20, mo.sizeofcmds + len(blob))

    with open(macho_path, "wb") as f:
        f.write(mo.data)

    # ─────────────────────────────────────────────────────────────────
    # 回读校验：写盘后重新解析，确认 dyld 真正会读到的字符串就是期望值。
    # 「我传的字符串是对的」和「二进制里存的是对的」是两件事，
    # 只有回读能证明后者。
    # ─────────────────────────────────────────────────────────────────
    mo2 = MachO(macho_path)
    names2 = mo2.dylib_names()
    if install_name not in names2:
        raise SystemExit(
            "FAIL: 回读校验失败，二进制中的加载项不是期望值。\n"
            "      期望: %s\n"
            "      实际新增项: %s"
            % (install_name, [n for n in names2 if n not in existing]))
    if mo2.ncmds != mo.ncmds + 1:
        raise SystemExit("FAIL: 回读 ncmds 不符: %d != %d"
                         % (mo2.ncmds, mo.ncmds + 1))

    print("== 注入完成 ==")
    print("  ncmds      ->", mo.ncmds + 1)
    print("  sizeofcmds -> 0x%x" % (mo.sizeofcmds + len(blob)))
    print("  install_name -> %s" % install_name)
    print("  回读校验   -> OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))