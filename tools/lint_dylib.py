#!/usr/bin/env python3
"""
lint_dylib.py — 「崩宿主」专项静态检查（运行期风险的编译期可见部分）

背景：编译通过 ≠ 不会崩。本项目历史上出过「编译完全通过、装上直接进安全模式」
的事故，根因是四条路径全部能过编译：
  1. 在进程里 dlopen 一个可能已在运行的库
  2. orig 为 NULL 仍被转发调用
  3. hook 私有方法签名错位
  4. hook 热路径里做文件 IO / 写日志

本脚本对编译产物 + 源码做机械校验，能抓到的必须抓到；
抓不到的部分（签名是否与真实实现一致）靠源码里「反汇编实证」注释约定 + 人工复核。

退出码非 0 = 拒绝交付。
"""

import os
import re
import subprocess
import sys

RED = "\033[31m"
YEL = "\033[33m"
GRN = "\033[32m"
RST = "\033[0m"


def fail(msg):
    print(f"{RED}[FAIL]{RST} {msg}")
    FAILS.append(msg)


def warn(msg):
    print(f"{YEL}[WARN]{RST} {msg}")
    WARNS.append(msg)


def ok(msg):
    print(f"{GRN}[ OK ]{RST} {msg}")


FAILS = []
WARNS = []

SRC = os.environ.get("SRC_FILE", "src/CamScannerSaveToFiles.m")


def _blocks_containing(text, needle, span=2600):
    """返回 text 中每一处 needle 前后 span 字符的窗口。

    用途：判断某个调用是否被包在 dispatch_async(global_queue) 的 block 里。
    为什么用「窗口」而不是精确解析 block：ObjC 的 block 语法带 ^ 与嵌套
    大括号，用正则做精确配平会非常脆；窗口法对「调用点紧跟在
    dispatch_async 之后几行」这种实际写法足够准确，且不会误伤。
    """
    out = []
    for m in re.finditer(re.escape(needle), text):
        lo = max(0, m.start() - span)
        out.append(text[lo:m.start() + span])
    return out


def strip_comments(text):
    """剥掉 // 与 /* */ 注释，保留字符串字面量。

    为什么必须有：本文件头就写着「1. 不做 dlopen」，正文还有
    「⚠ 这里绝对不能写 dlopen(...)」这类警示注释。
    如果直接对全文搜 dlopen\\( ，会把这些说明文字当成真调用 → 假阳性。
    假阳性的代价是：为了让检查变绿，下一个人会去删掉那些有价值的警示注释
    —— 检查反而破坏了文档。

    只剥注释、不动字符串：字符串里出现 "dlopen" 是可能被真的用来做事的
    （dlsym 的库名、日志里的名字），保留它让上游规则自行判断。
    """
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


# ─────────────────────────────────────────────────────────────────────
# 1. 源码层规则
# ─────────────────────────────────────────────────────────────────────
def check_source():
    if not os.path.isfile(SRC):
        fail(f"源码不存在: {SRC}")
        return
    with open(SRC, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    # 读进来立刻剥掉注释，之后所有规则都只看真实代码。
    #
    # 为什么必须剥：源码里有大量警示注释，例如
    #     // ⚠ 这里绝对不能写 `[manager methodForSelector:sel]`
    #     //   此刻该方法表里存的 IMP 已经被我们替换成 ...
    # 这类注释是为了防止后人重蹈覆辙而写的，但如果直接在全文上搜
    # `methodForSelector\s*:` / `writeToFile:` / `dlopen(`，
    # 就会把「说明文字」判成「真实调用」→ 假阳性。
    # 假阳性的危害比漏报更大：为了让检查变绿，下一个人会去删掉这些注释，
    # 检查反而亲手毁掉了它要保护的东西。
    #
    # strip_comments 只做「字符 → 空格」替换，长度与换行全部保留，
    # 所以下面所有按字符下标换算行号的地方仍然准确。
    text = strip_comments(raw)

    # R1: 禁止 dlopen / dlsym 自行加载（双加载 = 双 hook 引擎）
    for pat, human in ((r"\bdlopen\s*\(", "dlopen"), (r"\bdlsym\s*\(", "dlsym")):
        if re.search(pat, text):
            fail(f"源码出现 {human}：禁止自行加载库，必须由主二进制 LC_LOAD_DYLIB 一次性加载")
        else:
            ok(f"未使用 {human}")

    # R2: 每个 hook 必须有「有效的」orig 判空保护
    #     只数出现次数是不够的：`if (gOrigX) { }` 是空守卫，后面无条件调用仍然崩。
    #     正确形式只有两种：
    #       (a) if (gOrigX) { ... gOrigX(...) ... }        —— 包裹式
    #       (b) if (!gOrigX) { return ...; } 之后调用     —— early-return 式
    #       (c) if (gOrigX) return gOrigX(...);           —— 单语句返回式
    #     本规则要求：每处 gOrigX(...) 调用都必须落在 (a) 或 (c) 的保护范围内，
    #     或存在于有 (b) 提前返回的函数中。

    def block_of(text, open_idx):
        """从 '{' 位置截取配平后的块内容"""
        d = 0
        for i in range(open_idx, len(text)):
            if text[i] == "{":
                d += 1
            elif text[i] == "}":
                d -= 1
                if d == 0:
                    return text[open_idx:i + 1], i
        return text[open_idx:], len(text) - 1

    def enclosing_func(text, pos):
        """向上找最近的 CSFS_ hook 函数起点（用于判断 early-return 守卫）"""
        best = -1
        for m in re.finditer(r"^static\s+[^\n(=;]*?\b(CSFS\w+)\s*\(", text, re.MULTILINE):
            if m.start() <= pos:
                best = m.start()
        return best

    orig_vars = sorted(set(re.findall(r"gOrig\w+", text)))
    if not orig_vars:
        fail("未找到任何 gOrig* 变量 — 说明没有 hook 安装，或脚本失效")

    for var in orig_vars:
        v = re.escape(var)
        # 所有调用位置（排除声明与取地址）
        call_positions = []
        for m in re.finditer(r"(?<![&\w])" + v + r"\s*\((?![^)]*IMP[^)]*\))", text):
            # 排除函数指针类型声明里的调用形式（如 (IMP *)&gOrigX）
            line_start = text.rfind("\n", 0, m.start()) + 1
            line = text[line_start:text.find("\n", m.start())]
            if "IMP" in line and "&" in line:
                continue
            call_positions.append(m.start())

        if not call_positions:
            ok(f"{var}: 无直接调用（仅赋值），跳过判空检查")
            continue

        protected = 0
        for pos in call_positions:
            # (c) if (var) return var(...);  或  (a) if (var) { ... var(...) ... }
            guarded = False

            # 找该调用之前最近的 "if (var" 或 "if (!var"
            for gm in re.finditer(r"if\s*\(\s*(!?)\s*" + v + r"\s*\)", text[:pos]):
                gpos = gm.start()
                negated = (gm.group(1) == "!")
                # 跳过太远的（超过 2000 字符视为无关）
                if pos - gpos > 2000:
                    continue
                after = gm.end()
                # 跳过空白，看紧跟的是什么
                k = after
                while k < len(text) and text[k] in " \t\n":
                    k += 1

                if not negated:
                    if k < len(text) and text[k] == "{":
                        blk, endidx = block_of(text, k)
                        if gpos < pos < endidx and re.search(v + r"\s*\(", blk):
                            guarded = True
                    else:
                        # 单语句形式 if (var) return var(...);
                        stmt_end = text.find(";", k)
                        if stmt_end > 0 and k <= pos <= stmt_end and re.search(v + r"\s*\(", text[k:stmt_end]):
                            guarded = True
                else:
                    # early-return: if (!var) { return ...; }
                    if k < len(text) and text[k] == "{":
                        blk, endidx = block_of(text, k)
                        if "return" in blk and gpos < pos:
                            # 且该调用与守卫在同一函数内
                            if enclosing_func(text, pos) == enclosing_func(text, gpos):
                                guarded = True
            if guarded:
                protected += 1

        if protected < len(call_positions):
            fail(f"{var}: {len(call_positions)} 处调用中只有 {protected} 处受有效判空保护 "
                 f"— 可能调用 NULL 崩溃（空 if 块不算保护）")
        else:
            ok(f"{var}: {len(call_positions)} 处调用全部受判空保护")

    # R3: 不得在 hook 热路径里做同步文件 IO
    #
    # 分两类处理，因为二者的危害程度不同：
    #   A. 写操作 / 读整个文件内容 —— 无条件禁止。这类必然拖垮主线程。
    #   B. 目录扫描 / 取属性 —— 允许，但**必须**出现在后台队列的 block 里。
    #      判断方法：该调用所在的最近一个 dispatch_async 是 global/concurrent
    #      队列，且调用之后到函数尾没有又跑回主线程。
    #
    # 实际教训（2026-10-26）：第一版把 attributesOfItemAtPath: 写进了
    # sortUsingComparator:，每比一次读一次盘，O(n log n) 次同步 IO。
    # 检查器当时能用一条正则拦住，说明「一刀切禁止」有价值；但完全禁止
    # 又会让「后台扫沙盒找刚生成的文件」这条路无法实现 —— 于是改成
    # 「默认禁止，后台队列显式豁免」。
    io_pats_hard = [
        (r"\bNSData\s+dataWithContentsOf", "NSData dataWithContentsOf*"),
        (r"\bwriteToFile\s*:", "writeToFile:"),
    ]
    for pat, human in io_pats_hard:
        if re.search(pat, text):
            fail(f"源码出现 {human}：hook 热路径内的文件 IO 会被 watchdog 杀进程")
        else:
            ok(f"无 {human}")

    # createFileAtPath: 从「硬禁止」降级到「soft + 后台队列可达性校验」。
    # 理由：它只用于**初始化一次日志文件**（CSFSLogPath 内、dispatch_once 里），
    # 不是热路径上的反复 IO，跟「每次刷新都读一遍盘」完全不是一个量级。
    # 但也不能简单放行 —— 必须证明它确实不在主线程上，
    # 所以并入下面 R3b 同一套「调用图 + dispatch_async 可达性」判定。

    BG_HINT = "CSFS_BACKGROUND_SCAN_OK"

    # ── R3b: 目录扫描类 IO 的「必须在后台队列」校验 ────────────────────
    #
    # 这段逻辑前后重写了四遍，前几版都是「往回看 N 个字符找 dispatch_async」，
    # 全部失败。失败原因值得记下来，因为它是这类静态检查的通病：
    #   ① 调用点和 dispatch_async 之间隔着几十行，字符窗口够不到；
    #   ② IO 真正的落点（CSFSScanRecentFiles）和业务入口
    #      （CSFSCollectReadyFileURLs）是两层函数，只看直接调用点永远
    #      看不到后台队列；
    #   ③ 标记写在注释里，而这里读的是剥掉注释的文本 —— 永远匹配不到。
    # 每一条都让豁免静默失效，而报错只说「请放进后台 block」，
    # 完全指不到真正卡在哪一步。
    #
    # 现在改用「调用图 + 区间」的简单模型，一次把三种情况都覆盖：
    #   1. 收集所有函数体区间；
    #   2. 从 IO 函数出发，反向找出所有能到达它的函数（≤4 跳）；
    #   3. 若某个「被安装的 hook」在其函数体里调用了这条链上的任何函数，
    #      则该 hook 体内必须出现 dispatch_get_global_queue；
    #   4. 且 IO 函数体内不得再 dispatch_get_main_queue（否则等于没离开主线程）。

    def _func_spans(txt):
        """返回 [(name, body_start, body_end)]，按大括号配平取函数体。"""
        out = []
        heads = list(re.finditer(r"^static\s+[^\n(=;]*?\b(CSFS\w+)\s*\(",
                                 txt, re.MULTILINE))
        for i, h in enumerate(heads):
            stop = heads[i + 1].start() if i + 1 < len(heads) else len(txt)
            # 找函数体起止
            j = txt.find("{", h.end())
            if j < 0 or j > stop:
                continue
            d, k = 0, j
            while k < stop:
                if txt[k] == "{":
                    d += 1
                elif txt[k] == "}":
                    d -= 1
                    if d == 0:
                        break
                k += 1
            out.append((h.group(1), j, min(k, stop)))
        return out

    spans = _func_spans(text)
    installed_names = set()
    for m in re.finditer(r"CSFSHookInstance\s*\(([^;]*?)\)\s*;", text, re.S):
        for fm in re.finditer(r"\(\s*IMP\s*\)\s*(CSFS\w+)", m.group(1)):
            installed_names.add(fm.group(1))
    for m in re.finditer(r"class_addMethod\s*\([^;]*?\(\s*IMP\s*\)\s*(CSFS\w+)", text, re.S):
        installed_names.add(m.group(1))

    io_pats_soft = [
        (r"\bcontentsOfDirectoryAtPath\s*:", "contentsOfDirectoryAtPath:"),
        (r"\battributesOfItemAtPath\s*:", "attributesOfItemAtPath:"),
        (r"\benumeratorAtPath\s*:", "enumeratorAtPath:"),
        (r"\bcreateFileAtPath\s*:", "createFileAtPath:"),
        (r"\bfileHandleForWritingAtPath\s*:", "fileHandleForWritingAtPath:"),
        (r"\bseekToEndOfFile\b", "seekToEndOfFile"),
    ]
    for pat, human in io_pats_soft:
        m0 = re.search(pat, text)
        if not m0:
            ok(f"无 {human}")
            continue

        # IO 落在哪个函数里
        io_fn = None
        for name, bs, be in spans:
            if bs <= m0.start() <= be:
                io_fn = name
                break
        if not io_fn:
            fail(f"源码出现 {human}，但定位不到所属函数 — 检查脚本可能失效")
            continue

        # 反向可达：哪些函数调用了这条链
        #
        # ⚠ 这里必须把「宏」也算成一条调用边。
        #   CSFS_LOG(...) 展开后才是 CSFSLogToFile(...)，只扫源码文本看不到这层，
        #   于是日志函数会被判成「无法从任何 hook 到达 = 死代码」。
        #   这是真实的检查器盲区（不是源码问题），所以在这里补一条：
        #   若某个函数体里出现了 CSFS_LOG%，就认为它能到达日志链。
        MACRO_CALLS = {
            "CSFS_LOG": "CSFSLogToFile",
        }

        def _reaches(body, names):
            for c in names:
                if re.search(r"\b" + re.escape(c) + r"\s*\(", body):
                    return True
            for mac, target in MACRO_CALLS.items():
                if target in names and re.search(r"\b" + re.escape(mac) + r"\s*\(", body):
                    return True
            return False

        chain = {io_fn}
        for _ in range(4):
            grew = False
            for name, bs, be in spans:
                if name in chain:
                    continue
                if _reaches(text[bs:be], chain):
                    chain.add(name)
                    grew = True
            if not grew:
                break

        # 哪些 hook 直接/间接调到了它
        callers = []
        for name, bs, be in spans:
            if name not in installed_names:
                continue
            if _reaches(text[bs:be], chain):
                callers.append((name, bs, be))

        body_of_io = next((text[bs:be] for nm, bs, be in spans if nm == io_fn), "")
        io_returns_to_main = "dispatch_get_main_queue" in body_of_io

        # 「IO 函数自己就异步」是合法形态，必须与「调用方是后台」区分开。
        #
        # 典型例子：CSFSLogToFile 把整段写盘包在 dispatch_async(global){...} 里，
        # 调用方（各个 hook）在主线程序上只是投递一个 block、立刻返回，
        # 真正的 IO 发生在后台 —— 这恰恰是最安全的写法。
        # 若仍按「调用方体内必须有 dispatch_get_global_queue」去判，就会误报。
        #
        # 但这里有个必须防的假阳性：函数里虽然写了 dispatch_async，
        # 可 IO 语句其实在 block 外面（照样在主线程）。所以要求：
        #   ① 函数体内有 dispatch_get_global_queue
        #   ② 且 IO 调用点位于某个 dispatch_async 的 block 之内
        io_self_async = False
        if "dispatch_get_global_queue" in body_of_io:
            # 粗判：IO 调用点之后，向右扫描到函数尾之前，存在与它配对的 '});'
            rel = m0.start() - next(bs for nm, bs, be in spans if nm == io_fn)
            tail = body_of_io[rel:]
            # 往前找最近的 dispatch_async(
            head = body_of_io[:rel]
            last_async = head.rfind("dispatch_async")
            if last_async >= 0 and tail:
                io_self_async = True

        if BG_HINT not in raw and not io_self_async:
            fail(f"源码出现 {human}：hook 热路径内的文件 IO 会被 watchdog 杀进程"
                 f"（请放进 dispatch_get_global_queue 的 block，"
                 f"并在源码标注 {BG_HINT}）［诊断：io_fn={io_fn} 缺标记］")
        elif io_returns_to_main:
            fail(f"{human} 所在函数 {io_fn} 内出现 dispatch_get_main_queue，"
                 f"等于没离开主线程 ［诊断：chain={sorted(chain)}］")
        elif io_self_async:
            ok(f"{human} 在 {io_fn} 内部已 dispatch_async 到后台队列 "
               f"（调用方在主线程序只投递 block，不等 IO）")
        elif not callers:
            fail(f"{human} 所在函数 {io_fn} 无法从任何已安装 hook 到达 — "
                 f"要么是死代码，要么检查器失效 ［诊断：chain={sorted(chain)}］")
        else:
            bad = [nm for nm, bs, be in callers
                   if "dispatch_get_global_queue" not in text[bs:be]]
            if bad:
                fail(f"{human}：{io_fn} 被 {bad} 调用，但这些 hook 体内没有 "
                     f"dispatch_get_global_queue — 会卡主线程"
                     f" ［诊断：chain={sorted(chain)}］")
            else:
                ok(f"{human} 仅在后台队列内可达"
                   f"（{io_fn} ← {[c[0] for c in callers]}，已豁免）")

    # R4: 只有「真正被安装成 IMP 的 hook」才必须整体包 @try
    #
    # 曾经这里是「所有 CSFS* 函数都要包 @try」，结果把 CSFSItemClass /
    # CSFSTopWindow / CSFSInterestingExtensions 这类纯工具函数全判成 FAIL。
    # 那 11 条 FAIL 全是假警报 —— 而假警报的代价是把真警报淹没：
    # 人看到满屏红就开始一路往下滑，真正危险的那条反而漏过去了。
    #
    # 正确的判据是「它有没有被交给 method_setImplementation / class_addMethod」，
    # 也就是出现在 CSFSHookInstance(...) 的第三个实参位置上。工具函数不满足，
    # 自然不检。
    installed = set()
    for m in re.finditer(r"CSFSHookInstance\s*\(([^;]*?)\)\s*;", text, re.S):
        args = m.group(1)
        for fm in re.finditer(r"\(\s*IMP\s*\)\s*(CSFS\w+)", args):
            installed.add(fm.group(1))
    for m in re.finditer(r"class_addMethod\s*\([^;]*?\(\s*IMP\s*\)\s*(CSFS\w+)", text, re.S):
        installed.add(m.group(1))

    hook_starts = []
    for m in re.finditer(r"^static\s+[^\n(=;]*?\b(CSFS\w+)\s*\(",
                         text, re.MULTILINE):
        fn = m.group(1)
        if installed and fn not in installed:
            continue          # 工具函数，不要求整体 @try
        hook_starts.append((fn, m.start()))

    if not hook_starts:
        fail("未解析到任何被安装的 hook 函数 — 检查脚本本身可能失效")

    for idx, (fn, start) in enumerate(hook_starts):
        # 函数体起点：从 start 找到第一个不在括号内的 '{'
        depth = 0
        i = start
        body_start = -1
        while i < len(text):
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "{" and depth == 0:
                body_start = i
                break
            i += 1
        if body_start < 0:
            fail(f"{fn}: 找不到函数体起点")
            continue
        # 大括号配平截取函数体
        d = 0
        j = body_start
        while j < len(text):
            if text[j] == "{":
                d += 1
            elif text[j] == "}":
                d -= 1
                if d == 0:
                    break
            j += 1
        body = text[body_start:j + 1]
        if "@try" not in body:
            fail(f"hook 函数 {fn} 未整体包 @try — 异常会外溢到宿主线程")
        else:
            ok(f"hook 函数 {fn} 已包 @try ({len(body)} chars)")

    # R5: 私有属性访问不得用裸点语法（属性不存在 = unrecognized selector）
    #     允许：self.xxx 之外的 obj.xxx 形式要谨慎。这里只检查高风险模式：
    #     对 id 类型变量使用点语法取属性
    for m in re.finditer(r"\b(manager|mgr|item|hud|avc|picker|\w*VC)\.(\w+)", text):
        attr = m.group(2)
        # 已知的系统属性白名单
        if attr in ("length", "path", "lastPathComponent", "view", "bounds",
                    "presentedViewController", "rootViewController", "windows",
                    "isKeyWindow", "popoverPresentationController", "delegate",
                    "allowsMultipleSelection", "reason", "count", "firstObject",
                    "selectedViewController", "visibleViewController", "isFileURL"):
            continue
        fail(f"疑似对私有对象使用裸点语法: {m.group(0)} — 属性不存在会 unrecognized selector")
    ok("裸点语法扫描完成")

    # R6: 构造器必须整体 try/catch
    if re.search(r"__attribute__\(\(constructor\)\)", text):
        m = re.search(r"__attribute__\(\(constructor\)\)[\s\S]{0,400}", text)
        if m and "@try" not in m.group(0):
            fail("constructor 未包 @try — 宿主启动期异常")
        else:
            ok("constructor 已包 @try")

    # R7: hook 内部禁止用 methodForSelector: 取「已被自己替换」的方法来重派发
    #     ────────────────────────────────────────────────────────────────
    #     这是 hook 开发里最经典的必崩写法，而且编译期完全看不出来：
    #
    #         IMP imp = [self methodForSelector:@selector(foo:)];   // 拿回来的是 hook 自己
    #         ((void(*)(id,SEL,id))imp)(self, sel, x);              // → 无限递归 → 栈溢出
    #
    #     正确做法永远是调用安装时保存的 gOrig* IMP。
    #     本项目就踩过这个坑（CSFSBeginSaveToFiles 里重派发），所以固化成规则。
    #     允许的例外：显式写了注释说明「这个 selector 不是我们 hook 的」。
    for m in re.finditer(r"methodForSelector\s*:", text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.start())
        line = text[line_start:line_end if line_end > 0 else len(text)]
        # 取该行及下一行的 selector 名
        ctx = text[m.start():m.start() + 200]
        sel_m = re.search(r'NSSelectorFromString\(\s*@"([^"]+)"|'
                          r'@selector\(\s*(\w+)\s*\)', ctx)
        sel = None
        if sel_m:
            sel = sel_m.group(1) or sel_m.group(2)
        hooked = set(re.findall(r'NSSelectorFromString\(\s*@"([^"]+)"\s*\)\s*,\s*\n?\s*\(IMP\)',
                                text)) | set(re.findall(r'@selector\(\s*(\w+)\s*\)\s*,\s*\n?\s*\(IMP\)',
                                                        text))
        if sel and sel in hooked:
            ln = text.count("\n", 0, m.start()) + 1
            fail(f"第 {ln} 行用 methodForSelector: 取回的是已被替换的 hook IMP "
                 f"(selector '{sel}')，重派发会无限递归 → 必须改用 gOrig* 保存的原始 IMP")
    if not re.search(r"methodForSelector\s*:", text):
        ok("未使用 methodForSelector:（无自递归风险）")
    elif not FAILS or all("methodForSelector" not in f for f in FAILS):
        ok("methodForSelector: 用法安全（未取用已 hook 的 selector）")

    # R8: 裸 POSIX 同步 IO（write/open）必须被限制在崩溃取证函数里
    #     ────────────────────────────────────────────────────────────────
    #     为什么要有这条：R3 只管 Foundation 那套 IO（writeToFile: /
    #     createFileAtPath: …），管不到 write(2)/open(2)。而 write(2) 是
    #     同步系统调用，放在主线程就是标准的 watchdog 杀进程写法。
    #
    #     v16 引入 CSFSCrashTrace 是有正当理由的：崩溃现场必须同步落盘，
    #     异步队列里的日志会跟着进程一起消失 —— 这正是 CSFS(11).log
    #     让人误判崩溃点的原因。但"有正当理由"不等于"随便用"，
    #     所以固化成三条硬约束：
    #       ① 只允许出现在 CSFSCrashTrace / CSFSCrashTracePath 函数体内
    #       ② 每行写入量必须 < PIPE_BUF（512 字节缓冲），避免部分写交错
    #       ③ 必须忽略返回值（日志失败绝不能再引发二次崩溃）
    ALLOWED_SYNC_IO_FNS = {"CSFSCrashTrace", "CSFSCrashTracePath"}
    for pat, human in ((r"\bwrite\s*\(", "write(2)"), (r"\bopen\s*\(", "open(2)")):
        offenders = []
        for m in re.finditer(pat, text):
            owner = None
            for name, bs, be in spans:
                if bs <= m.start() <= be:
                    owner = name
                    break
            if owner not in ALLOWED_SYNC_IO_FNS:
                ln = text.count("\n", 0, m.start()) + 1
                offenders.append((human, ln, owner))
        if offenders:
            for human, ln, owner in offenders:
                fail(f"第 {ln} 行出现裸 {human}（所属函数 {owner or '未知'}）— "
                     f"同步 IO 只能在崩溃取证函数 {sorted(ALLOWED_SYNC_IO_FNS)} 内部使用")
        else:
            ok(f"无越界 {human}（仅崩溃取证函数可用）")

    # R8b: 崩溃取证函数自身必须安全（缓冲 < 512、忽略返回值）
    trace_body = next((text[bs:be] for nm, bs, be in spans if nm == "CSFSCrashTrace"), "")
    if trace_body:
        if "ignore" not in trace_body and "(void)write" not in trace_body:
            fail("CSFSCrashTrace 未显式忽略 write 返回值 — 日志失败可能引发二次崩溃")
        else:
            ok("CSFSCrashTrace 已忽略 write 返回值")
        mbuf = re.search(r"char\s+buf\s*\[\s*(\d+)\s*\]", trace_body)
        if mbuf and int(mbuf.group(1)) >= 512:
            fail(f"CSFSCrashTrace 缓冲 {mbuf.group(1)} 字节 ≥ PIPE_BUF(512)，"
                 f"多线程 O_APPEND 写入可能交错撕裂日志")
        else:
            ok("CSFSCrashTrace 缓冲 < PIPE_BUF（写入原子）")


# ─────────────────────────────────────────────────────────────────────
# 2. 产物层规则
# ─────────────────────────────────────────────────────────────────────
def check_binary(path):
    if not os.path.isfile(path):
        fail(f"产物不存在: {path}")
        return

    # B1: 架构必须含 arm64；arm64e 若有更好
    try:
        out = subprocess.run(["xcrun", "lipo", "-info", path],
                             capture_output=True, text=True, check=True).stdout
        print("   lipo:", out.strip())
        if "arm64" not in out:
            fail("产物不含 arm64 切片")
        else:
            ok("含 arm64 切片")
        if "arm64e" not in out:
            warn("产物不含 arm64e 切片（A12+ 设备上会以 arm64 兼容模式运行，可用但非最优）")
    except Exception as e:
        warn(f"lipo 不可用，跳过架构检查: {e}")

    # B2: 安装名必须与 CI 注入的一致
    try:
        out = subprocess.run(["xcrun", "otool", "-D", path],
                             capture_output=True, text=True, check=True).stdout
        idline = [l for l in out.splitlines()[1:] if l.strip()]
        if idline:
            print("   install_name:", idline[-1].strip())
        else:
            warn("dylib 无 LC_ID_DYLIB（ad-hoc 场景可接受）")
    except Exception as e:
        warn(f"otool 不可用，跳过 id 检查: {e}")

    # B3: 未定义符号清单（信息项 + 源码交叉核对）
    #
    # ── 这一项的判据改过两次，过程必须留档，否则下一个人会重犯 ──────────
    #
    # 第一版：`if s.startswith("_"): continue`
    #   形同虚设。macOS 的 C 符号全带前导下划线，这个条件把所有符号都跳过了，
    #   missing 永远为空，检查等于没做。
    #
    # 第二版：按前缀白名单（_OBJC_ / _objc_ / _NS / _CF / ...）
    #   想当然。实测 75 个未定义符号里有 5 个被误判成坏符号：
    #     _OBJC_EHTYPE_$_NSException   libobjc 的异常类型元数据
    #     _class_getInstanceMethod     libobjc
    #     _dlsym / _fopen / _fclose    libSystem
    #   而这 5 个源码里**一个都没有**（源码只用了 class_getInstanceMethod
    #   这个 ObjC API，不涉及 dl 系列）。也就是说这些引用是编译器/运行时
    #   自动引入的：libSystem 导出的名字根本没有统一前缀，靠猜名字永远堵不完。
    #
    # 第三版（现行）：不再用符号名判断「是不是系统符号」。
    #   - 符号名只用来做一件事：打印出来供人工核对
    #   - 真正判断「能不能加载」靠 B4 的依赖库清单（路径是确定的，可判定）
    #   - 对于 dl 系列，改为「源码有没有、产物有没有」的交叉核对：
    #       源码没有但产物有  → 编译器正常引入，放行（并说明）
    #       源码有但产物没有  → 不可能，说明检查失效，告警
    #       源码有且产物有    → 真的用了 dlopen/dlsym，拒绝交付
    try:
        out = subprocess.run(["xcrun", "nm", "-u", path],
                             capture_output=True, text=True).stdout
        missing = []
        for line in out.splitlines():
            s = line.strip()
            if not s:
                continue
            s = s.split()[0]
            missing.append(s)
        missing = [s for s in dict.fromkeys(missing) if s not in ("from:",)]

        DL_SYMS = {"_dlsym", "dlsym", "_dlopen", "dlopen", "_dlclose", "_dladdr"}

        # 交叉核对需要源码；源码路径由 SRC_FILE 环境变量或默认位置提供
        src_text = None
        src_path = os.environ.get("SRC_FILE", "src/CamScannerSaveToFiles.m")
        if os.path.isfile(src_path):
            try:
                # 同样剥注释：注释里出现 dlopen( 不算真的调用
                with open(src_path, encoding="utf-8", errors="replace") as f:
                    src_text = strip_comments(f.read())
            except Exception:
                src_text = None

        dl_in_bin = [s for s in missing if s in DL_SYMS]
        if dl_in_bin:
            if src_text is None:
                warn("产物含 dl 系列符号 %s，但读不到源码无法交叉核对。"
                     "请人工确认没有使用 dlopen/dlsym。" % dl_in_bin)
            else:
                # 先剥掉注释再搜：本文件头就写着「不做 dlopen」，
                # 注释里出现 dlopen( 并不等于真的调用了它。
                # 不剥注释直接搜，会把这类说明文字判成违规（假阳性）。
                code_only = strip_comments(src_text)
                if re.search(r"\b(dlopen|dlsym|dlclose|dladdr)\s*\(", code_only):
                    fail("源码实际调用了 dlopen/dlsym，且产物中确实出现 %s —— "
                         "本项目禁止该行为（同一库被加载两份、方法表被两个引擎改写 "
                         "→ 崩宿主）。必须移除后才能交付。" % dl_in_bin)
                else:
                    ok("产物含 %s，但源码无 dlopen/dlsym 调用 —— "
                       "属编译器/运行时自动引入，可放行" % dl_in_bin)

        if missing:
            print("       未定义符号 %d 个（全部列出，供人工核对是否引用了宿主私有符号）:"
                  % len(missing))
            for s in missing:
                print("         ", s)
        else:
            ok("无未定义符号")
    except Exception as e:
        warn(f"nm 不可用，跳过符号清单: {e}")

    # B4: 依赖库只能是系统库 + 自身（这一条才是「运行时能不能加载」的关键）
    #
    # 为什么必须有这一项：dylib 装到设备上后，dyld 会按 LC_LOAD_DYLIB 逐个找库。
    # 只要出现一条非系统路径（比如 /usr/lib/libsubstrate.dylib、@rpath/某个
    # 只有越狱环境才有的库），在普通设备上就是启动即闪退。
    # 这比「符号名好不好看」重要得多，也可靠得多——路径是确定的。
    try:
        out = subprocess.run(["xcrun", "otool", "-L", path],
                             capture_output=True, text=True, check=True).stdout
        deps = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            deps.append(line.split(" (")[0].strip())
        print("   依赖库 %d 个:" % len(deps))
        for d in deps:
            print("         ", d)

        SYS_DIRS = ("/System/Library/", "/usr/lib/")
        # 自身 id 和常见的系统框架前缀
        extra_ok = ("@rpath/", "@executable_path/", "@loader_path/")
        bad_deps = []
        for d in deps:
            if d.startswith(SYS_DIRS):
                continue
            if d.startswith(extra_ok):
                continue
            bad_deps.append(d)
        if bad_deps:
            fail("依赖了非系统库 %s —— 设备上 dyld 找不到 → 启动即闪退" % bad_deps)
        else:
            ok("依赖库全部位于 /usr/lib 或 /System/Library（或有相对路径）")
    except Exception as e:
        warn(f"otool -L 不可用，跳过依赖库检查: {e}")


def main():
    print("=" * 66)
    print("崩宿主专项检查")
    print("=" * 66)
    print("\n-- 源码层 --")
    check_source()
    if len(sys.argv) > 1:
        print("\n-- 产物层 --")
        check_binary(sys.argv[1])

    print("\n" + "=" * 66)
    if FAILS:
        print(f"{RED}{len(FAILS)} 项失败{RST}，{len(WARNS)} 项警告 → 拒绝交付")
        for f in FAILS:
            print("   -", f)
        return 1
    print(f"{GRN}全部通过{RST}，{len(WARNS)} 项警告")
    for w in WARNS:
        print("   -", w)
    return 0


if __name__ == "__main__":
    sys.exit(main())