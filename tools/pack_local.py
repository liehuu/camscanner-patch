#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pack_local.py —— 在本机把编好的 dylib 注入原始 ipa，不依赖 macOS 任何工具。

为什么要有这个脚本：
  完整链路（编译 → 注入 → 重签 → 重打包）在 CI 上要 8 分钟、产物 266MB，
  来回下载在网络差的时候会卡死（真实遇到：下载停在 64MB 不动）。
  但拆开看，只有「编译」非 macOS 不可；「注入」是 Mach-O 字节编辑，
  「重打包」是 zip 拷贝，两者都是纯 Python 能做的。
  于是把流水线改成：
      CI 只编 dylib（82KB 产物，秒下）
      → 本机注入 + 重打包（分钟级，零下载）
  签名则整体交给 LiveContainer：导入时 LC 会用自己的证书重签整个 .app，
  所以本地不必 codesign（本机也没有 codesign）。

与原 workflow 的差异（刻意保留，均为等效）：
  1. 注入的加载项直接写 @executable_path/Frameworks/<dylib>。
     CI 是写 /usr/lib/... 再用 install_name_tool 改指到 Frameworks；
     这里一步到位，省掉那个改写步骤（改写要动 Mach-O 的 LC_LOAD_DYLIB
     字符串长度，本地没有 install_name_tool，重复实现不划算）。
  2. 不跑 codesign / ad-hoc 签名。LiveContainer 导入时会重签；
     对「只想装进 LC」的场景，ad-hoc 签名只是结构自洽，没有实质作用。
  3. 保留 _CodeSignature 目录（与 CI 侧决定一致）。它的 CMS 在 Mach-O
     被改动后必然失效，但 LC 重签会重算整个 bundle 的 seal 并覆盖。

用法：
  python3 tools/pack_local.py <orig.ipa> <dylib> [-o out.ipa]
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

APP_IN_IPA = "Payload/CamScanner_Lite.app"
APP_BIN_IN_IPA = APP_IN_IPA + "/CamScanner_Lite"
DYLIB_IN_IPA = APP_IN_IPA + "/Frameworks/CamScannerSaveToFiles.dylib"
LOAD_PATH = "@executable_path/Frameworks/CamScannerSaveToFiles.dylib"

# 单条目超过这个大小就不进内存，改走临时文件（CamScanner 主二进制可达上百 MB）
INMEM_LIMIT = 48 * 1024 * 1024


def read_entry(zf, name):
    """读一个 zip 条目；大条目落临时文件，返回 (bytes_or_None, tmp_path_or_None)。"""
    info = zf.getinfo(name)
    if info.file_size <= INMEM_LIMIT:
        return zf.read(name), None
    tmp = tempfile.NamedTemporaryFile(delete=False)
    with zf.open(name) as src:
        shutil.copyfileobj(src, tmp, 4 * 1024 * 1024)
    tmp.close()
    return None, tmp.name


def copy_entry(zin, zout, name, replacement=None):
    """把 zip 条目原样拷到新 zip，保留 external_attr（权限/symlink）。

    replacement 给定时，写它的内容而不是原条目内容。
    之所以不能简单 zin.read + zout.write：那样会把 ZipInfo 的
    external_attr（可执行位、symlink 标记、权限位）丢掉，
    CamScanner 这种包里有可执行文件与软链，丢了就跑不起来。
    """
    info = zin.getinfo(name)
    mode = info.external_attr >> 16
    is_link = (mode & 0o170000) == 0o120000

    tmp_to_clean = None
    try:
        if replacement is not None:
            payload = replacement
        elif is_link:
            # 软链条目：zip 里存的就是链接目标字符串，按字节原样搬过去。
            payload = zin.read(name)
        else:
            data, tmp_path = read_entry(zin, name)
            if tmp_path is not None:
                tmp_to_clean = tmp_path
                with zout.open(info, "w") as dst, open(tmp_path, "rb") as src:
                    shutil.copyfileobj(src, dst, 4 * 1024 * 1024)
                return
            payload = data
        with zout.open(info, "w") as dst:
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
            dst.write(payload)
    finally:
        if tmp_to_clean:
            try:
                os.remove(tmp_to_clean)
            except OSError:
                pass


def macho_is_arm64_exec(data):
    if len(data) < 32:
        return False
    magic, cputype, _, = struct.unpack_from("<III", data, 0)
    return magic == 0xFEEDFACF and (cputype & 0x01000000) and (cputype & 0xFF) == 0x0C


def find_load_dylib_paths(data):
    """列出主二进制里所有 LC_LOAD_DYLIB 的路径字符串，用于注入前后核对。"""
    if len(data) < 32:
        return []
    ncmds = struct.unpack_from("<I", data, 16)[0]
    o = 32
    out = []
    for _ in range(ncmds):
        if o + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, o)
        if cmdsize < 8 or o + cmdsize > len(data):
            break
        if cmd in (0x0C, 0x8000001F, 0x80000018, 0x80000023, 0x0D):
            nameoff = struct.unpack_from("<I", data, o + 8)[0]
            if o + nameoff < o + cmdsize:
                e = data.find(b"\x00", o + nameoff, o + cmdsize)
                if e < 0:
                    e = o + cmdsize
                out.append(data[o + nameoff:e].decode("utf-8", "replace"))
        o += cmdsize
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ipa", help="原始未注入的 ipa")
    ap.add_argument("dylib", help="CI 编出的 build/CamScannerSaveToFiles.dylib")
    ap.add_argument("-o", "--out", default="")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    injector = os.path.join(here, "inject_dylib.py")
    if not os.path.isfile(injector):
        print("ERROR: 找不到 %s" % injector, file=sys.stderr)
        return 1

    orig = os.path.abspath(args.ipa)
    dylib = os.path.abspath(args.dylib)
    out = os.path.abspath(args.out) if args.out else os.path.join(
        root, "dist", "CamScanner_7.26.5_SaveToFiles_local.ipa")

    if not os.path.isfile(dylib):
        print("ERROR: dylib 不存在: %s" % dylib, file=sys.stderr)
        print("先从 CI 下载 CamScannerSaveToFiles-dylib 产物并解出 fat dylib。",
              file=sys.stderr)
        return 1

    with zipfile.ZipFile(orig) as zf:
        names = set(zf.namelist())
        if APP_BIN_IN_IPA not in names:
            print("ERROR: %s 下没有 %s" % (orig, APP_BIN_IN_IPA), file=sys.stderr)
            for n in sorted(names)[:20]:
                print("   ", n)
            return 1
        if DYLIB_IN_IPA in names:
            print("ERROR: 输入 ipa 已含 %s —— 这是注入过的包，二次注入必崩"
                  % DYLIB_IN_IPA, file=sys.stderr)
            return 1

        has_sig = any(n.startswith(APP_IN_IPA + "/_CodeSignature/") for n in names)
        print("输入包 %d 个条目；_CodeSignature: %s"
              % (len(names), "有（将被 LC 重签覆盖）" if has_sig else "无"))

        # ── 1. 取主二进制出来 ──────────────────────────────────────────
        workdir = tempfile.mkdtemp(prefix="pack_local_")
        try:
            binpath = os.path.join(workdir, "CamScanner_Lite")
            data, tmp_path = read_entry(zf, APP_BIN_IN_IPA)
            if tmp_path:
                shutil.move(tmp_path, binpath)
            else:
                with open(binpath, "wb") as f:
                    f.write(data)
            print("主二进制 %d 字节" % os.path.getsize(binpath))

            before = find_load_dylib_paths(open(binpath, "rb").read())
            dup = [p for p in before if "CamScannerSaveToFiles" in p]
            if dup:
                print("ERROR: 主二进制已有加载项 %s —— 输入包被注入过" % dup,
                      file=sys.stderr)
                return 1
            print("注入前加载项 %d 条，无 CamScannerSaveToFiles（干净）" % len(before))

            # ── 2. 注入 ───────────────────────────────────────────────
            print("== 注入 %s ==" % LOAD_PATH)
            r = subprocess.run([sys.executable, injector, binpath, LOAD_PATH],
                               capture_output=True, text=True)
            sys.stdout.write(r.stdout)
            if r.returncode != 0:
                sys.stderr.write(r.stderr)
                print("ERROR: 注入失败", file=sys.stderr)
                return 1
            print("== 校验 ==")
            r = subprocess.run([sys.executable, injector, "--check",
                                binpath, LOAD_PATH],
                               capture_output=True, text=True)
            sys.stdout.write(r.stdout)
            if r.returncode != 0:
                sys.stderr.write(r.stderr)
                print("ERROR: 校验失败", file=sys.stderr)
                return 1
            after = find_load_dylib_paths(open(binpath, "rb").read())
            if LOAD_PATH not in after:
                print("ERROR: 注入后未见 %s，实际加载项 %r"
                      % (LOAD_PATH, after), file=sys.stderr)
                return 1
            print("   注入后加载项 %d 条，含 %s" % (len(after), LOAD_PATH))

            # ── 3. 流式重打包 ─────────────────────────────────────────
            os.makedirs(os.path.dirname(out), exist_ok=True)
            if os.path.exists(out):
                os.remove(out)
            newbin = open(binpath, "rb").read()
            n_copied = 0
            with zipfile.ZipFile(orig) as zin, \
                 zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    name = item.filename
                    if name.endswith("/"):
                        continue
                    if name == APP_BIN_IN_IPA:
                        copy_entry(zin, zout, name, replacement=newbin)
                        n_copied += 1
                        continue
                    copy_entry(zin, zout, name)
                    n_copied += 1
                # dylib 落到 Frameworks/。@executable_path 指向
                # .app/MacOS/<可执行> 所在目录，即 .app 根；
                # @executable_path/Frameworks/x.dylib = .app/Frameworks/x.dylib。
                zi = zipfile.ZipInfo(DYLIB_IN_IPA)
                zi.external_attr = 0o100644 << 16
                with zout.open(zi, "w") as dst, open(dylib, "rb") as src:
                    shutil.copyfileobj(src, dst, 4 * 1024 * 1024)
            print("重打包完成：拷贝 %d 个条目 + 新增 dylib" % n_copied)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # ── 4. 自检产物 ──────────────────────────────────────────────────
    print()
    print("== 产物自检 ==")
    ok = True
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        if APP_BIN_IN_IPA not in names:
            print("   [FAIL] 产物无主二进制")
            ok = False
        else:
            head = zf.read(APP_BIN_IN_IPA)[:4]
            magic = struct.unpack("<I", head)[0]
            print("   [OK] 主二进制 magic=0x%08x" % magic)
            if magic != 0xFEEDFACF and magic != 0xCFFAEDFE:
                print("   [FAIL] 主二进制 magic 异常")
                ok = False
        if DYLIB_IN_IPA in zf.namelist():
            sz = zf.getinfo(DYLIB_IN_IPA).file_size
            print("   [OK] Frameworks/ 下 dylib %d 字节" % sz)
            if sz < 100000:
                print("   [FAIL] dylib 太小，不像 fat dylib")
                ok = False
        else:
            print("   [FAIL] Frameworks/ 下没有 dylib")
            ok = False
        sig_left = [n for n in names if n.startswith(APP_IN_IPA + "/_CodeSignature/")]
        print("   [i] _CodeSignature 条目 %d 个（LC 导入时会重签覆盖）"
              % len(sig_left))

    size = os.path.getsize(out)
    print()
    print("产物: %s" % out)
    print("大小: %d 字节 (%.1f MB)" % (size, size / 1048576))
    if not ok:
        print("自检未通过，不要交付")
        return 1
    print("自检通过：可直接导入 LiveContainer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
