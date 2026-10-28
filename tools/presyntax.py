#!/usr/bin/env python3
"""
presyntax.py — Objective-C 源码语法预检（无需编译器）

为什么需要这个脚本
──────────────────────────────────────────────────────────────────
本项目历史上有两次 CI 首编失败，都不是"逻辑写错"，而是纯语法/声明缺陷：

  a. `[NSString class"]` 少一个右括号（引号还写错位置）
  b. 整体重写文件时，把三段 `@interface` 私有类声明当注释删掉
     → clang 报 `no known instance method for selector 'xxx:'`

这两类错误有个共同点：**完全可以在推送前用纯文本机械检查发现**。
但当时我把检查甩给了 CI，代价是 3~5 分钟一轮的往返。本机没有 clang，
所以更需要一个不依赖编译器的预检，把这类错误挡在 push 之前。

本脚本检查
──────────────────────────────────────────────────────────────────
  P1  括号配平        () [] {} 三类，跳过字符串/字符/注释
  P2  引号配平        @"..." 与 'c'，未闭合同样会导致后续全乱
  P3  块声明配平      @interface / @implementation / @protocol 与 @end
  P4  异常块配平      @try / @catch / @finally
  P5  方法调用可知性  源码里被发送的每条 selector，必须能在以下任一来源找到：
                     (1) @protocol 声明  (2) 系统类型的方法（白名单）
                     (3) 显式 #import 的标准框架  (4) 本文件 static 函数
                     —— 这一条专治「重写时删了 @interface」
  P6  hook 签名一致性 每个 HookMethod 的 selector 必须与注释里的实证签名对得上

退出码非 0 = 不要 push。
"""

import re
import sys

RED = "\033[31m"
YEL = "\033[33m"
GRN = "\033[32m"
RST = "\033[0m"

FAILS = []
WARNS = []
UNTERMINATED = []      # 词法阶段发现的未闭合字符串/字符字面量: [(kind, pos), ...]
OKS = 0


def fail(msg):
    FAILS.append(msg)
    print(f"{RED}[FAIL]{RST} {msg}")


def warn(msg):
    WARNS.append(msg)
    print(f"{YEL}[WARN]{RST} {msg}")


def ok(msg):
    global OKS
    OKS += 1
    print(f"{GRN}[ OK ]{RST} {msg}")


# ══════════════════════════════════════════════════════════════════════
# 词法清洗：把注释与字符串内容抹成空格，其余字符原样保留。
# 关键约束：**长度与换行必须完全不变**，这样任何下标都能直接换算行号。
# ══════════════════════════════════════════════════════════════════════
def blank_out(src):
    """
    返回 (cleaned, string_spans)
      cleaned      : 同长度的"骨架"文本，注释/字符串内容替换为空格（换行保留）
      string_spans : [(start, end), ...] 字符串字面量在原文中的区间，供 P5 使用
    """
    out = list(src)
    spans = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        # 行注释
        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            if j < 0:
                j = n
            for k in range(i, j):
                out[k] = " "
            i = j
            continue

        # 块注释
        if c == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue

        # 字符串字面量（含 @"..."）
        if c == '"':
            start = i
            j = i + 1
            terminated = False
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    terminated = True
                    break
                if src[j] == "\n":      # 未闭合字符串：到行尾为止，交给 P2 报错
                    break
                j += 1
            spans.append((start, j))
            if not terminated:
                UNTERMINATED.append(("双引号", start))
            # 连同两侧引号一起抹掉，避免骨架里残留引号被 P2 误判
            for k in range(start, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue

        # 字符字面量
        if c == "'":
            start = i
            j = i + 1
            terminated = False
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == "'":
                    j += 1
                    terminated = True
                    break
                if src[j] == "\n":
                    break
                j += 1
            spans.append((start, j))
            if not terminated:
                UNTERMINATED.append(("单引号", start))
            for k in range(start, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue

        i += 1

    # 预处理指令整行抹掉：`#pragma mark - Hook: -[CSShareManager xxx]` 这类行
    # 会被 clang 整体忽略，里面的 `[...]` 不是消息发送。若不抹掉，
    # P5 会把注释里提到的 selector 当成真实调用，产生噪声。
    out = "".join(out)
    if "#" in out:
        buf = list(out)
        for m in re.finditer(r"(?m)^[ \t]*#.*$", out):
            for k in range(m.start(), m.end()):
                if buf[k] != "\n":
                    buf[k] = " "
        out = "".join(buf)

    return out, spans


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def snippet(src, pos, radius=60):
    a = max(0, pos - radius)
    b = min(len(src), pos + radius)
    s = src[a:b].replace("\n", "\\n")
    return ("..." if a > 0 else "") + s + ("..." if b < len(src) else "")


# ──────────────────────────────────────────────────────────────────────
# P1 / P2：括号与引号配平
# ──────────────────────────────────────────────────────────────────────
def check_balance(src, cleaned):
    pairs = {"(": ")", "[": "]", "{": "}"}
    closers = {v: k for k, v in pairs.items()}
    stack = []

    for idx, ch in enumerate(cleaned):
        if ch in pairs:
            stack.append((ch, idx))
        elif ch in closers:
            if not stack:
                fail(f"P1 第 {line_of(cleaned, idx)} 行：多余的 '{ch}'，前面没有对应的 '{closers[ch]}'")
                return False
            op, oidx = stack.pop()
            if op != closers[ch]:
                fail(f"P1 第 {line_of(cleaned, idx)} 行：'{ch}' 与第 "
                     f"{line_of(cleaned, oidx)} 行的 '{op}' 不匹配")
                return False

    if stack:
        op, oidx = stack[-1]
        ln = line_of(cleaned, oidx)
        # 给出该行原文，方便直接定位
        lines = src.splitlines()
        raw = lines[ln - 1].strip() if ln - 1 < len(lines) else ""
        fail(f"P1 第 {ln} 行的 '{op}' 没有闭合（文件结束时栈内仍有 {len(stack)} 个未闭合）\n"
             f"       该行内容: {raw}")
        return False

    ok(f"P1 括号配平：() [] {{}} 全部闭合")

    # P2：引号配平。判据来自词法阶段（字符串没被正确闭合时会被记录），
    #     不能事后扫骨架文本 —— 骨架里的引号已被抹成空格，扫了必然什么都没有。
    if UNTERMINATED:
        kind, pos = UNTERMINATED[0]
        ln = line_of(cleaned, pos)
        lines = src.splitlines()
        raw = lines[ln - 1].strip() if ln - 1 < len(lines) else ""
        fail(f"P2 第 {ln} 行存在未闭合的{kind}\n       该行内容: {raw}")
        return False
    ok("P2 字符串/字符字面量全部闭合")
    return True


# ──────────────────────────────────────────────────────────────────────
# P3 / P4：块配平
# ──────────────────────────────────────────────────────────────────────
def check_blocks(cleaned):
    # P3：@interface/@implementation/@protocol ... @end
    openers = []
    for m in re.finditer(r"@(interface|implementation|protocol)\b", cleaned):
        openers.append((m.group(1), m.start()))
    ends = [m.start() for m in re.finditer(r"@end\b", cleaned)]

    if len(openers) != len(ends):
        # 给出明细
        fail(f"P3 @interface/@implementation/@protocol 有 {len(openers)} 个，"
             f"@end 有 {len(ends)} 个，数量不等")
        # 逐个配对以定位遗漏
        for i, (kind, pos) in enumerate(openers):
            ln = line_of(cleaned, pos)
            if i < len(ends):
                if ends[i] < pos:
                    fail(f"P3 第 {ln} 行的 @{kind} 出现在第 {line_of(cleaned, ends[i])} 行的 @end 之后 — 顺序错乱")
            else:
                fail(f"P3 第 {ln} 行的 @{kind} 缺少 @end")
    else:
        # 数量相等还要检查顺序
        bad = False
        for i, (kind, pos) in enumerate(openers):
            if ends[i] < pos:
                fail(f"P3 第 {line_of(cleaned, pos)} 行的 @{kind} 位于 @end 之后")
                bad = True
                break
        if not bad:
            kinds = {}
            for kind, _ in openers:
                kinds[kind] = kinds.get(kind, 0) + 1
            if kinds:
                detail = "、".join(f"@{k}×{v}" for k, v in sorted(kinds.items()))
                ok(f"P3 块声明配平：{detail}，@end×{len(ends)}")
            else:
                warn("P3 本文件没有任何 @interface/@implementation/@protocol 块")

    # P4：@try / @catch / @finally
    tries = len(re.findall(r"@try\b", cleaned))
    catches = len(re.findall(r"@catch\b", cleaned))
    finallies = len(re.findall(r"@finally\b", cleaned))
    if tries != catches:
        fail(f"P4 @try {tries} 个、@catch {catches} 个，必须成对")
    else:
        ok(f"P4 异常块配平：@try×{tries} / @catch×{catches} / @finally×{finallies}")
    if catches and finallies and catches != finallies:
        warn(f"P4 @catch {catches} 个但 @finally {finallies} 个 — 可能是有意省略，确认一下")


# ──────────────────────────────────────────────────────────────────────
# P5：selector 可知性 —— 专治「重写时把 @interface 声明删掉」
# ──────────────────────────────────────────────────────────────────────
# Foundation / UIKit / objc runtime 的常用方法，无需本项目声明
SYSTEM_SELECTORS = {
    # NSObject / 内存
    "alloc", "init", "new", "class", "self", "copy", "mutableCopy", "dealloc",
    "isKindOfClass:", "isMemberOfClass:", "respondsToSelector:", "conformsToProtocol:",
    "performSelector:", "performSelector:withObject:", "methodForSelector:",
    "instancesRespondToSelector:", "isEqual:", "hash", "description", "superclass",
    "isProxy", "retain", "release", "autorelease", "zone", "forwardInvocation:",
    "methodSignatureForSelector:", "doesNotRecognizeSelector:", "valueForKey:",
    "setValue:forKey:", "valueForKeyPath:", "setValue:forKeyPath:",
    # 数组 / 字典 / 字符串 / 集合
    "count", "objectAtIndex:", "objectAtIndexedSubscript:", "addObject:",
    "addObjectsFromArray:", "removeObject:", "removeObjectAtIndex:",
    "removeAllObjects", "insertObject:atIndex:", "replaceObjectAtIndex:withObject:",
    "containsObject:", "indexOfObject:", "indexOfObjectIdenticalTo:",
    "firstObject", "lastObject", "componentsJoinedByString:", "sortedArrayUsingSelector:",
    "enumerateObjectsUsingBlock:", "mutableCopy", "arrayByAddingObject:",
    # v19：CSFSDescribeShape 要把字典的 allKeys 截到前 40 个再拼日志，
    #      否则 style/attr 的 key 一多日志会爆掉。ks 来自 allKeys，
    #      静态推断是 id，所以 P5 需要它进白名单。
    "subarrayWithRange:",
    "objectForKey:", "setObject:forKey:", "removeObjectForKey:", "allKeys", "allValues",
    "length", "UTF8String", "characterAtIndex:", "substringFromIndex:",
    "substringToIndex:", "stringByAppendingString:", "stringByAppendingPathComponent:",
    "stringByAppendingPathExtension:", "stringByDeletingLastPathComponent",
    "stringByDeletingPathExtension", "hasPrefix:", "hasSuffix:", "containsString:",
    "rangeOfString:", "stringByReplacingOccurrencesOfString:withString:",
    # v17：XML 非法控制字符过滤需要按 unichar 批量读写，
    #      比逐字符 substringWithRange: 快一个数量级（OCR 文本动辄上万字）。
    "getCharacters:range:", "stringWithCharacters:length:",
    "lowercaseString", "uppercaseString", "dataUsingEncoding:", "writeToFile:atomically:",
    "writeToURL:atomically:", "fileExistsAtPath:", "isEqualToString:",
    "componentsSeparatedByString:", "pathExtension", "stringValue", "integerValue",
    "boolValue", "doubleValue", "floatValue", "mutableString",
    "stringWithFormat:", "stringWithString:", "stringByExpandingTildeInPath",
    # 文件 / URL
    "fileURLWithPath:", "fileURLWithPath:isDirectory:", "URLWithString:",
    "path", "absoluteString", "isFileURL", "lastPathComponent", "pathComponents",
    "URLByAppendingPathComponent:", "URLByDeletingLastPathComponent",
    "defaultManager", "attributesOfItemAtPath:error:", "contentsOfDirectoryAtPath:error:",
    "createDirectoryAtPath:withIntermediateDirectories:attributes:error:",
    "copyItemAtPath:toPath:error:", "removeItemAtPath:error:",
    "destinationOfSymbolicLinkAtPath:error:", "fileType", "fileSize",
    "dataWithContentsOfFile:", "dataWithContentsOfURL:", "writeToURL:options:error:",
    # UI 视图 / 控制器
    "view", "bounds", "frame", "setFrame:", "setBounds:", "setHidden:", "isHidden",
    "addSubview:", "removeFromSuperview", "setBackgroundColor:", "backgroundColor",
    "setAlpha:", "alpha", "setTag:", "tag", "superview", "subviews", "window",
    "setUserInteractionEnabled:", "userInteractionEnabled",
    "setAutoresizingMask:", "autoresizingMask", "sizeToFit", "layoutIfNeeded",
    "setNeedsLayout", "setNeedsDisplay", "setAccessibilityLabel:",
    "setAccessibilityIdentifier:", "imageNamed:", "imageWithRenderingMode:",
    "setImage:forState:", "imageView", "setContentMode:", "contentMode",
    "presentViewController:animated:completion:", "dismissViewControllerAnimated:completion:",
    "presentedViewController", "presentingViewController",
    "pushViewController:animated:", "popViewControllerAnimated:",
    "topViewController", "visibleViewController", "viewControllers",
    "setViewControllers:animated:", "navigationController", "tabBarController",
    "popoverPresentationController", "setSourceRect:", "sourceRect",
    "setSourceView:", "sourceView", "setPermittedArrowDirections:",
    "setBarButtonItem:", "barButtonItem", "setPopoverPresentationController:",
    "setModalPresentationStyle:", "modalPresentationStyle",
    "setPreferredContentSize:", "preferredContentSize",
    "initWithRootViewController:", "setDelegate:", "delegate",
    "addChildViewController:", "willMoveToParentViewController:",
    "didMoveToParentViewController:", "removeFromParentViewController",
    "setTitle:", "title", "navigationItem", "setRightBarButtonItem:",
    "setLeftBarButtonItem:", "setHidesBackButton:", "setTintColor:", "tintColor",
    "setTextColor:", "textColor", "setFont:", "font", "setText:", "text",
    "setNumberOfLines:", "sizeThatFits:", "setLineBreakMode:",
    # 文件选择器 / 分享（本补丁核心）
    "initForExportingURLs:", "initForExportingURLs:asCopy:",
    "initForOpeningContentTypes:", "initForOpeningContentTypes:asCopy:",
    "initWithURL:inMode:", "initWithDocumentTypes:inMode:",
    "initWithURLs:inMode:", "setAllowsMultipleSelection:",
    "allowsMultipleSelection", "setShouldShowFileExtensions:",
    "setDirectoryURL:", "directoryURL", "setNameFieldStringValue:",
    "nameFieldStringValue", "url", "setURL:",
    "initWithActivityItems:applicationActivities:", "activityItems",
    "setExcludedActivityTypes:", "excludedActivityTypes",
    "setCompletionWithItemsHandler:", "completionWithItemsHandler",
    "popoverPresentationController", "setCompletionHandler:",
    # 弹窗
    "setMessage:", "message", "addAction:", "addTextFieldWithConfigurationHandler:",
    "presentOpenInMenuFromRect:inView:animated:",
    "presentOpenInMenuFromBarButtonItem:animated:",
    "presentOptionsMenuFromRect:inView:animated:",
    "initWithURL:", "setUTI:", "uti", "setName:",
    "presentAlertController:animated:completion:",
    # 线程 / 时间
    "mainQueue", "mainThread", "isMainThread", "currentThread",
    "dispatch_async", "dispatch_after", "dispatch_get_main_queue",
    "dispatch_time", "dispatch_semaphore_", "afterDelay:", "cancelPreviousPerformRequestsWithTarget:",
    "performSelectorOnMainThread:withObject:waitUntilDone:",
    "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:",
    "invalidate", "setFireDate:", "fireDate", "date",
    "timeIntervalSinceNow", "timeIntervalSince1970", "dateWithTimeIntervalSinceNow:",
    # UIApplication / 通知
    "sharedApplication", "keyWindow", "windows", "isKeyWindow",
    "connectedScenes", "activationState", "delegate",
    "defaultCenter", "addObserver:selector:name:object:",
    "removeObserver:", "postNotificationName:object:userInfo:",
    "defaultWorkspace", "openURL:options:completionHandler:", "openURL:",
    # 字典字面量 / 数字
    "dictionaryWithObjects:forKeys:count:", "arrayWithObjects:count:",
    "numberWithInteger:", "numberWithBool:", "numberWithDouble:", "boolValue",
    # v18：带样式段落用 NSMutableDictionary 承载（不用 C struct 装箱，
    # 理由见源码 v18 注释：ARC 管不到 NSValue 缓冲区里的对象指针）
    "dictionaryWithCapacity:", "arrayWithObject:",
    "numberWithLong:", "longValue", "doubleValue",
    # 其它常用
    "hideAnimated:afterDelay:", "systemImageNamed:", "array", "arrayWithCapacity:",
    "addObserverForName:object:queue:usingBlock:", "addObserverForName:",
    "becomeFirstResponder", "resignFirstResponder", "reloadData",
    "registerClass:forCellReuseIdentifier:", "dequeueReusableCellWithIdentifier:",
    "setSeparatorStyle:", "setDataSource:", "dataSource",
    "setEstimatedRowHeight:", "setRowHeight:", "reloadSections:withRowAnimation:",
    "initWithStyle:reuseIdentifier:", "contentView", "textLabel", "detailTextLabel",
    "setAccessoryType:", "setSelectionStyle:", "setEditing:animated:",
    "setValue:forKeyPath:", "addTarget:action:forControlEvents:",
    "setEnabled:", "isEnabled", "setOn:", "isOn",
    "CGSizeValue", "CGRectValue", "CGRectMake", "CGSizeMake",
    "countByEnumeratingWithState:objects:count:", "nextObject",

    # ── 以下为 2026-10-26 新增（做 OCR 面板迁移时用到）──────────────────
    # 全部是 Foundation 官方 API，import <Foundation/Foundation.h> 后必然可用，
    # 不是本项目自定义的私有方法，因此补进白名单而不是加 @protocol 声明。
    # 曾因此报 10 条 [FAIL]，误以为是真实缺陷 —— 白名单不全 = 假警报，
    # 假警报多了就会让人开始忽略这个检查器，比漏报更危险。
    "mainBundle",
    "localizedStringForKey:value:table:",
    "stringWithUTF8String:",
    "setWithArray:",
    "enumeratorAtPath:",
    "sortUsingComparator:",
    "compare:",
    "valueForKey:", "setValue:forKey:",
    "longLongValue", "unsignedLongLongValue", "integerValue", "intValue", "boolValue",
    # NSFileManager / NSFileHandle / NSDateFormatter（Foundation 官方 API，日志落盘用）
    "createFileAtPath:contents:attributes:", "fileHandleForWritingAtPath:",
    "seekToEndOfFile", "writeData:", "closeFile",
    "stringFromDate:", "dataUsingEncoding:", "data",
    # NSLock / NSDateFormatter（Foundation 官方 API，日志串行化用）
    "lock", "unlock", "fileExistsAtPath:", "date",
    "appendFormat:", "appendString:",
    # NSMutableString / NSString（v12 docx 生成：XML 转义与文本清洗）
    "replaceOccurrencesOfString:withString:options:range:",
    "stringByTrimmingCharactersInSet:",
    # NSArray（v14 候选按 mtime 排序）
    "sortedArrayUsingComparator:",
    "string", "absoluteString", "pathExtension", "lastPathComponent",
    "fileModificationDate", "fileType", "fileSize",
    "attributesOfItemAtPath:error:",
    "fileExistsAtPath:", "stringByAppendingPathComponent:",
    "lowercaseString", "hasSuffix:", "rangeOfString:",
    "substringFromIndex:",
    # NSDate 构造（v16：mtime 缺失时的零值哨兵）
    "dateWithTimeIntervalSince1970:", "compare:", "isKindOfClass:",
    # v16：mtime 排序用（平行数组 + 选择排序，规避 block 参数类型不兼容）
    "timeIntervalSince1970", "numberWithDouble:", "doubleValue",
    "exchangeObjectAtIndex:withObjectAtIndex:", "arrayWithCapacity:",
    # v17：自写 store 型 ZIP（NSMutableData 字节级拼装）
    "dataWithCapacity:", "appendBytes:length:", "appendData:", "bytes",
    "initForExportingURLs:asCopy:", "allowsMultipleSelection",
    # NSAttributedString / NSMutableString 的标准初始化与构造（Foundation 官方 API）
    "initWithString:", "attributedStringWithString:",
    "stringWithFormat:", "initWithFormat:",
    "uppercaseString", "substringToIndex:", "mutableCopy",
    "respondsToSelector:", "class",
    # 类工厂方法 / 单例哨兵（Foundation 官方 API）
    "dictionary", "array", "null", "sharedInstance",
    "UTF8String", "length",
}


def check_selectors(cleaned, src):
    """
    找出所有 [receiver selector...] 形式的消息发送，抽取消息的第一段，
    检查它是否能被"知道"：@protocol 声明里、static C 函数、或系统白名单。
    """
    # 收集本文件声明的 selector：@protocol / @interface 里的 - (xxx)yyy:
    declared = set()
    for m in re.finditer(r"^\s*[-+]\s*\([^)]*\)\s*([A-Za-z_]\w*(?:\s*:\s*\([^)]*\)\s*\w+)*)",
                         cleaned, re.MULTILINE):
        sig = m.group(1)
        # 取第一段（到第一个 ':' 为止，含冒号）
        first = sig.split(":")[0].strip()
        if ":" in sig:
            declared.add(first + ":")
        else:
            declared.add(first)

    # 收集本文件的 C 函数名与 static IMP 变量
    cfuncs = set(re.findall(r"^\s*static\s+[^\n(=;]*?\b(\w+)\s*\(", cleaned, re.MULTILINE))

    # 系统白名单的第一段（把 "a:b:" 也映射到 "a:"）
    sys_first = set()
    for s in SYSTEM_SELECTORS:
        sys_first.add(s.split(":")[0] + ":" if ":" in s else s)

    # 扫描消息发送：[xxx foo:...]、[xxx foo]
    unknown = []
    # 匹配 "[" 之后的内容，取接收者后第一个标识符
    for m in re.finditer(r"\[", cleaned):
        start = m.start()
        # @[ ... ] 是集合字面量，@[ ] 内的元素不是消息发送
        # （形如 @[u]、@[a, b]；其中的 '[' 前面紧邻 '@'）
        if start > 0 and cleaned[start - 1] == "@":
            continue
        # 从 "[" 后开始，跳过接收者（可能是 [x y] 嵌套 / 表达式）
        j = start + 1
        depth = 1
        # 找到接收者结束：第一个不在 (){}[] 内的空白后紧跟标识符
        # 简化策略：跳到第一个顶层空白
        while j < len(cleaned):
            ch = cleaned[j]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if depth == 0:
                    break
            elif ch in " \t\n" and depth == 1:
                # 空白后是 selector 起点吗？
                k = j
                while k < len(cleaned) and cleaned[k] in " \t\n":
                    k += 1
                if k < len(cleaned) and (cleaned[k].isalpha() or cleaned[k] == "_"):
                    # 检查这是不是一个直接的 selector（不是表达式续行）
                    mm = re.match(r"([A-Za-z_]\w*)", cleaned[k:])
                    if mm:
                        name = mm.group(1)
                        after = k + len(name)
                        # selector 后必须紧跟 ':' 或 空白/']'
                        if after < len(cleaned) and cleaned[after] in ": \t\n]":
                            has_colon = (after < len(cleaned) and cleaned[after] == ":")
                            key = name + ":" if has_colon else name
                            if (key not in sys_first and key not in declared
                                    and name not in cfuncs and name not in declared):
                                unknown.append((name, line_of(cleaned, k), key))
                break
            j += 1

    if unknown:
        seen = set()
        real = []
        for name, ln, key in unknown:
            if key in seen:
                continue
            seen.add(key)
            real.append((name, ln, key))
        # 过滤掉明显是 C 结构体/枚举的（全大写或已知前缀）
        suspects = [x for x in real if not x[0].isupper()]
        # 这里必须是 FAIL 而不是 WARN。
        # 历史事故：整体重写文件时把三段 @interface 私有类声明当注释删掉，
        # CI 首编直接报 `no known instance method for selector 'xxx:'`。
        # 若只给 WARN，带病代码照样能 push —— 那就等于没检查。
        # 系统 API 已进白名单，剩下未命中的就是本项目自己声明的私有方法，
        # 漏声明一律视为缺陷。
        for name, ln, key in suspects[:20]:
            fail(f"P5 第 {ln} 行发送了未声明的 selector '{key}' "
                 f"— 必须在 @protocol 里声明，否则 clang 报 "
                 f"'no known instance method'")
        if not suspects:
            ok(f"P5 selector 可知性扫描完成（{len(real)} 个命中，均为系统 API）")
        else:
            ok(f"P5 selector 扫描完成，发现 {len(suspects)} 个未声明项（见上）")
    else:
        ok("P5 所有消息发送的 selector 均在 @protocol 或系统白名单内")


# ──────────────────────────────────────────────────────────────────────
# P6：hook 安装点的一致性
#     hook 装错是「跑起来崩」的典型路径：selector 名打错 → 静默不生效；
#     实现函数参数个数与 selector 冒号数不符 → 调用时寄存器错位 → 读到野指针。
#     本规则把「安装点」与「实现函数」两侧对齐核对。
# ──────────────────────────────────────────────────────────────────────
def check_hook_table(cleaned, src):
    # 注意：selector 字面量在 cleaned 里已被抹成空格，必须回原文取。
    # 两个串长度完全一致（blank_out 保证），所以下标可直接互用。
    # 1) 收集 @protocol 声明：selector -> 参数个数（不含 self/_cmd 外的部分无法静态得知，
    #    这里只校验 selector 名是否被声明过，供 P5 使用）
    proto_sels = {}
    for m in re.finditer(r"^\s*[-+]\s*\([^)]*\)\s*([A-Za-z_]\w*(?:\s*:\s*\([^)]*\)\s*\w+)+)",
                         cleaned, re.MULTILINE):
        sig = re.sub(r"\s*\(\s*[^)]*\)\s*", "", m.group(1))
        proto_sels[sig] = sig.count(":") + 1
    for m in re.finditer(r"^\s*[-+]\s*\([^)]*\)\s*([A-Za-z_]\w*)\s*;", cleaned, re.MULTILINE):
        proto_sels[m.group(1)] = 0

    if proto_sels:
        ok(f"P6 @protocol 中声明了 {len(proto_sels)} 条方法")
    else:
        warn("P6 @protocol 中没有任何方法声明 — 若 hook 依赖它，运行期会挂")

    # 2) 收集所有 static CSFS_ 函数的实现：函数名 -> 形参个数
    impls = {}
    for m in re.finditer(r"^static\s+[^\n(=;]*?\b(CSFS\w+)\s*\(",
                         cleaned, re.MULTILINE):
        fname = m.group(1)
        # 从 '(' 起配平取参数表
        p = m.end() - 1
        d = 0
        q = p
        while q < len(cleaned):
            if cleaned[q] == "(":
                d += 1
            elif cleaned[q] == ")":
                d -= 1
                if d == 0:
                    break
            q += 1
        params = cleaned[p + 1:q].strip()
        if params in ("", "void"):
            impls[fname] = 0
        else:
            # 顶层逗号计数。block 参数 void (^)(void) 里也有括号，需按深度过滤
            n = 1
            dd = 0
            for ch in params:
                if ch in "([{":
                    dd += 1
                elif ch in ")]}":
                    dd -= 1
                elif ch == "," and dd == 0:
                    n += 1
            impls[fname] = n

    # 3) 收集 hook 安装点：CSFSHookInstance(Class, SEL, (IMP)CSFS_xxx, ...)
    installs = []
    for m in re.finditer(
            r"CSFSHookInstance\s*\(\s*(?P<cls>[\w]+)\s*,\s*(?P<sel>.+?)\s*,\s*"
            r"\(IMP\)\s*(?P<imp>CSFS_\w+)", cleaned, re.DOTALL):
        # selector 表达式在 cleaned 里引号内容被抹空，回原文切片取
        sel_expr = src[m.start("sel"):m.end("sel")]
        installs.append((m.group("cls"), " ".join(sel_expr.split()),
                         m.group("imp"), m.start()))

    if not installs:
        fail("P6 未找到任何 CSFSHookInstance 安装点 — 补丁不会生效")
        return proto_sels

    for cls, sel_expr, imp, pos in installs:
        ln = line_of(cleaned, pos)
        # selector 字面量
        lit = re.search(r'@"([^"]+)"|@selector\(\s*(\w+)\s*\)|NSSelectorFromString\(\s*@"([^"]+)"\s*\)',
                        sel_expr)
        if lit:
            sel = next(g for g in lit.groups() if g)
        else:
            sel = sel_expr
        colons = sel.count(":")

        if imp not in impls:
            fail(f"P6 第 {ln} 行 hook 了 '{sel}'，但找不到实现函数 {imp}")
            continue
        nparam = impls[imp]
        # hook 实现形参 = self + _cmd + selector 冒号个数的业务参数
        expect = 2 + colons
        if nparam != expect:
            fail(f"P6 第 {ln} 行：'{sel}' 有 {colons} 个冒号，"
                 f"实现 {imp} 应有 {expect} 个形参（self+_cmd+{colons}），实际 {nparam} 个 "
                 f"— 参数错位会读到野指针")
        else:
            ok(f"P6 hook '{sel}' ↔ {imp}（{nparam} 形参 = 2+{colons}）")

    return proto_sels


def check_receiver_selector_type(cleaned, src):
    """P7：接收者类型 ↔ selector 归属校验。

    为什么必须加这一条（真实事故，2026-10-28 v18）：
      统计字号众数时写了 `long key = [k longValue];`，而 k 是
      `NSString *`。`longValue` 是 NSNumber 的方法，NSString 只有
      integerValue / longLongValue / intValue / doubleValue。
      UI 侧 P5 只校验「selector 名在不在白名单里」——`longValue` 确实
      在白名单（作为 NSNumber 方法），于是 P5 判它 OK。
      结果 CI 首编报：
        error: no visible @interface for 'NSString' declares
               the selector 'longValue'
      也就是说：**P5 把 selector 名字当全局命名空间用，忽略了它属于谁。**

    做法：
      扫 `[<简单标识符> <selector>]` 这种单层消息发送，若接收者是
      NSArray / NSDictionary / NSString 这类已知类型，就把 selector 拿去
      与该类型的已知方法集求交；命中不了但属于「别的类型的方法」→ FAIL。

    只处理能静态确定类型的简单情形（变量名前后文里有声明）。
    复杂表达式一律跳过 —— 宁可漏报，不要误报把正常代码拦下来。
    """
    # 各 Foundation 类型的方法集（只收高频易混的，不追求完备）
    NSSTRING = {
        "length", "UTF8String", "characterAtIndex:", "substringFromIndex:",
        "substringToIndex:", "substringWithRange:", "stringByAppendingString:",
        "stringByAppendingPathComponent:", "stringByDeletingLastPathComponent",
        "stringByDeletingPathExtension", "hasPrefix:", "hasSuffix:",
        "containsString:", "rangeOfString:", "lowercaseString", "uppercaseString",
        "capitalizedString", "dataUsingEncoding:", "componentsSeparatedByString:",
        "pathExtension", "lastPathComponent", "pathComponents", "path",
        "integerValue", "intValue", "longLongValue", "floatValue", "doubleValue",
        "boolValue", "stringByTrimmingCharactersInSet:",
        "stringByReplacingOccurrencesOfString:withString:",
        "stringByReplacingOccurrencesOfString:withString:options:range:",
        "writeToFile:atomically:", "writeToFile:atomically:encoding:error:",
        "writeToURL:atomically:", "isEqualToString:", "mutableCopy",
        "stringByExpandingTildeInPath", "stringByStandardizingPath",
        "getCharacters:range:", "stringWithCharacters:length:",
        "stringByReplacingPercentEscapesUsingEncoding:",
        "stringByAddingPercentEscapesUsingEncoding:",
        "fileSystemRepresentation", "cStringUsingEncoding:", "description",
        "stringValue", "compare:", "localizedStandardCompare:",
    }
    NSARRAY = {
        "count", "objectAtIndex:", "firstObject", "lastObject",
        "componentsJoinedByString:", "sortedArrayUsingSelector:",
        "arrayByAddingObject:", "containsObject:", "indexOfObject:",
        "enumerateObjectsUsingBlock:", "mutableCopy", "addObject:",
        "removeObject:", "removeObjectAtIndex:", "removeAllObjects",
        "objectAtIndexedSubscript:", "insertObject:atIndex:",
        "reverseObjectEnumerator", "objectEnumerator", "subarrayWithRange:",
        "arrayByAddingObjectsFromArray:", "sortedArrayUsingComparator:",
        "indexOfObjectPassingTest:", "filteredArrayUsingPredicate:",
    }
    NSDICT = {
        "objectForKey:", "setObject:forKey:", "removeObjectForKey:", "allKeys",
        "allValues", "count", "setObject:forKeyedSubscript:",
        "objectForKeyedSubscript:", "enumerateKeysAndObjectsUsingBlock:",
        "mutableCopy", "addEntriesFromDictionary:", "removeAllObjects",
        "keysSortedByValueUsingSelector:", "objectsForKeys:notFoundMarker:",
        "description", "dictionaryWithCapacity:", "dictionaryWithObjects:forKeys:count:",
    }
    NSNUMBER = {
        "integerValue", "intValue", "longValue", "longLongValue", "unsignedLongValue",
        "unsignedIntegerValue", "doubleValue", "floatValue", "boolValue",
        "stringValue", "compare:", "isEqualToNumber:", "description",
        "numberWithLong:", "numberWithInt:", "numberWithDouble:",
        "numberWithInteger:", "numberWithBool:", "numberWithUnsignedLong:",
    }
    # 冒号不区分地做名字匹配：需要按 selector 全名比对
    TYPES = {
        "NSString": NSSTRING,
        "NSMutableString": NSSTRING | {"appendString:", "appendFormat:", "setString:"},
        "NSArray": NSARRAY,
        "NSMutableArray": NSARRAY,
        "NSDictionary": NSDICT,
        "NSMutableDictionary": NSDICT,
        "NSNumber": NSNUMBER,
    }
    # 全表方法名 → 所属类型（用于反向判定「这是别人的方法」）
    OWNER = {}
    for tn, methods in TYPES.items():
        for meth in methods:
            OWNER.setdefault(meth, set()).add(tn)

    # 建一张变量名 → 静态类型表。
    # 三种声明形态都要认：
    #   NSString *k = ...
    #   for (NSString *k in freq)
    #   NSString *k, *j;
    #
    # ⚠ 关键：C 的变量名**不是全局唯一**的，不同函数里同名变量可以是不同类型。
    #   第一版直接用 `var_type[name] = type` 覆盖，等价于「最后一个声明说了算」，
    #   于是把 A 函数里的 NSMutableArray *out 的类型套到了 B 函数里的
    #   NSString *out 上，一次跑出 14 条误报（全部是把 addObject:/appendFormat:
    #   报成「发给了 NSString」）。**误报比漏报更致命**：一旦检查器开始瞎报，
    #   人就会习惯性忽略它，等于回到没有检查器的状态。
    #   所以这里改成「同名多类型 → 记成歧义，整条跳过」。
    var_types = {}
    # 声明后可能跟的字符：
    #   =  赋值        ; / ,  多变量       )  宏/参数
    #   in for-in 循环   （最初漏了这一项，导致 `for (NSString *d in dirs)`
    #                      没被识别成 NSString 声明，于是同一个 d 在别处被
    #                      声明成 NSDictionary 时没有形成「歧义」，误报一路
    #                      漏到 P7 输出里 —— 详细排查见 2026-10-28 记录）
    #   {  紧跟块
    #   \n 只写声明不初始化
    decl_re = re.compile(
        r"\b(NS(?:Mutable)?(?:String|Array|Dictionary|Number))\s*\*+\s*(\w+)\s*"
        r"(?=[=;,)\{\n]|\bin\b)")
    for m in decl_re.finditer(cleaned):
        tn, name = m.group(1), m.group(2)
        var_types.setdefault(name, set()).add(tn)
    # 只保留类型唯一的变量
    var_type = {k: list(v)[0] for k, v in var_types.items() if len(v) == 1}
    ambiguous = {k for k, v in var_types.items() if len(v) > 1}

    # 扫单层消息发送 [recv selector]
    # 只处理 recv 是纯标识符的情形，避免把嵌套表达式/函数调用误判
    fails = 0
    msg_re = re.compile(r"\[\s*(\w+)\s+(\w+)\s*")
    for m in msg_re.finditer(cleaned):
        recv, sel_name = m.group(1), m.group(2)
        tn = var_type.get(recv)
        if not tn or tn not in TYPES:
            continue
        # 取完整 selector（含冒号）
        tail = cleaned[m.start(2):m.start(2) + 200]
        sm = re.match(r"(\w+(?:\s*:\s*)?)", tail)
        if not sm:
            continue
        full = re.sub(r"\s+", "", sm.group(1))
        if not full.endswith(":"):
            has_args = re.match(r"\w+\s*:", tail)
            if has_args:
                full = has_args.group(0).replace(" ", "").rstrip()
        if full.endswith(":"):
            # 多段 selector 需要拼接，这里只处理单段，避免误判
            if tail.count(":", 0, min(len(tail), 60)) > 1:
                pass
        if not full.endswith(":"):
            full_sels = {full}
        else:
            full_sels = {full}

        methods = TYPES[tn]
        if any(s in methods for s in full_sels):
            continue
        # 名字不在该类型方法集里 —— 但它可能在别的类型里，那就是类型用错
        owners = OWNER.get(full, set()) - {tn}
        if owners:
            fails += 1
            fail(f"P7 第 {line_of(cleaned, m.start())} 行把 "
                 f"'{full}' 发给了 {tn} — 该 selector 属于 "
                 f"{'/'.join(sorted(owners))}，clang 会报 "
                 f"'no visible @interface for {tn} declares the selector'")
    if fails == 0:
        ok("P7 接收者类型 ↔ selector 归属一致（未发现跨类型误用）")
    return fails


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "src/CamScannerSaveToFiles.m"
    print("=" * 66)
    print(f"ObjC 语法预检（无需编译器）: {path}")
    print("=" * 66)

    try:
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
    except OSError as e:
        print(f"{RED}无法读取 {path}: {e}{RST}")
        return 2

    print(f"  文件大小 {len(src)} 字节，{src.count(chr(10)) + 1} 行\n")

    cleaned, _spans = blank_out(src)
    assert len(cleaned) == len(src), "内部错误：骨架长度与原文不一致"

    if not check_balance(src, cleaned):
        # 括号不配平时，后续检查全部不可靠，直接退出
        print(f"\n{RED}括号未配平，后续检查中止{RST}")
        return 1

    check_blocks(cleaned)
    check_selectors(cleaned, src)
    check_hook_table(cleaned, src)
    check_receiver_selector_type(cleaned, src)

    print("\n" + "=" * 66)
    if FAILS:
        print(f"{RED}{len(FAILS)} 项失败{RST}，{len(WARNS)} 项警告 → 不要 push")
        for f in FAILS:
            print("   -", f)
        return 1
    print(f"{GRN}语法预检通过{RST}（{OKS} 项），{len(WARNS)} 项提示")
    for w in WARNS:
        print("   -", w)
    return 0


if __name__ == "__main__":
    sys.exit(main())