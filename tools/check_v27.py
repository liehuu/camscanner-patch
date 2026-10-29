#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_v27.py —— v27「开关多来源合并」的静态判据。

为什么需要：v24/v25 两轮都说「修好了开关」，用户实测两次都是「勾了跟没勾一样」。
两轮的真因都不是「没读」，而是**读到的第一份就信了**：

    v25 的 CSFSPullOptions 里
        if (!hw && !st && !hi) return NO;    // 有字段就往下走
        ...
        return YES;                          // ← 一拿到就 YES
    而 CSFSReadOptionsFromBottomView 里
        if (CSFSPullOptions(bottomView.originalData, ...)) return;   // ← 直接短路
        id ctx = ...allPages...                                       // ← 永远到不了

  于是 v25 新增的 context.allPages 分支一次都没执行过，
  行为与 v24 逐字节等价 —— 用户看到的当然还是「没生效」。
  编译器、lint、check_v24 全都看不见这类缺陷：代码完全合法，只是永远走不到。

本检查器断言四件在源码里可直接判定的事：
  F1 CSFSReadOptionsFromBottomView 里三个来源都不允许出现「命中即 return」
  F2 每处来源调用都必须把返回值落进变量（不许裸调 CSFSPullOptions(...)）
  F3 合并必须是 OR 语义：gCSFSHideXxx 只能被置 YES，不能被直接赋成某一份的值
  F4 有 FINAL 汇总日志，能一眼看出三个来源各自读到什么

用法：
  python3 tools/check_v27.py src/CamScannerSaveToFiles.m
退出码：0 通过 / 1 有问题
"""

import re
import sys

fails = []
oks = []


def ok(m):
    oks.append(m)


def fail(m):
    fails.append(m)


def extract_func(src, name):
    """从源码里抠出一个 static 函数的完整**定义**（按大括号配平）。

    注意要跳过前置声明：
        static void CSFSReadOptionsFromBottomView(id bottomView);   ← 声明
        static void CSFSReadOptionsFromBottomView(id bottomView) {  ← 定义
    第一版只 find 第一个同名位置，结果从声明处往后找 '{'，
    一直找到几十行外的另一个函数，判据全部读到错的内容 ——
    F2/F4 因此连报两条假 FAIL。教训：抠函数必须确认「括号后接的是 { 还是 ;」。
    """
    pos = 0
    while True:
        idx = src.find(name + '(', pos)
        if idx < 0:
            return None
        # 找到参数表结束的 ')'
        p = src.find('(', idx)
        depth = 0
        i = p
        while i < len(src):
            c = src[i]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if i >= len(src):
            return None
        # 跳过 ')' 与 '{' 之间的空白/属性
        j = i + 1
        while j < len(src) and src[j] in ' \t\r\n':
            j += 1
        if j < len(src) and src[j] == ';':
            # 前置声明，继续往后找定义
            pos = j
            continue
        brace = src.find('{', i)
        if brace < 0:
            return None
        depth = 0
        i = brace
        while i < len(src):
            c = src[i]
            if c == '"' or c == "'":
                q = c
                i += 1
                while i < len(src):
                    if src[i] == '\\':
                        i += 2
                        continue
                    if src[i] == q:
                        break
                    i += 1
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return src[idx:i + 1]
            i += 1
        return None


def strip_comments(s):
    """只抹注释，**保留字符串内容**。

    v23 踩过「检查器命中注释里的示例」的坑，所以要抹注释；
    但这里 F4 判的正是日志格式串里的 'FINAL hideWritten='，
    字符串必须留着。第一版把字符串一起抹了，F4 立刻假 FAIL ——
    「抹太多」和「抹太少」都是判据错，要按这条检查到底看不看字面量来定。
    """
    out = list(s)
    n = len(s)
    i = 0
    while i < n:
        if s[i] == '/' and i + 1 < n and s[i + 1] == '/':
            j = i
            while j < n and s[j] != '\n':
                j += 1
            for k in range(i, j):
                out[k] = ' '
            i = j
            continue
        if s[i] == '/' and i + 1 < n and s[i + 1] == '*':
            j = s.find('*/', i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, min(j, n)):
                if out[k] != '\n':
                    out[k] = ' '
            i = j
            continue
        if s[i] == '"' or s[i] == "'":
            # 跳过字符串/字符字面量，但**不抹内容**
            q = s[i]
            j = i + 1
            while j < n:
                if s[j] == '\\':
                    j += 2
                    continue
                if s[j] == q:
                    j += 1
                    break
                if s[j] == '\n':
                    break
                j += 1
            i = j
            continue
        i += 1
    return ''.join(out)


def main():
    if len(sys.argv) < 2:
        print('用法: check_v27.py <file.m>')
        return 2
    src = open(sys.argv[1], encoding='utf-8').read()

    reader = extract_func(src, 'CSFSReadOptionsFromBottomView')
    pull = extract_func(src, 'CSFSPullOptions')

    if reader is None:
        fail('F1 找不到 CSFSReadOptionsFromBottomView，判据失效')
    if pull is None:
        fail('F2 找不到 CSFSPullOptions，判据失效')

    if reader is not None:
        body = strip_comments(reader)

        # ── F1 三个来源都不许「命中即 return」
        #
        # 缺陷形态（v25 真实存在）：
        #     if (CSFSPullOptions(x, @"...")) return;
        # 只要这一行在，后面的来源就是死代码。
        short_circuit = re.search(
            r'if\s*\(\s*CSFSPullOptions\s*\([^;]*\)\s*\)\s*return\s*;', body)
        if short_circuit:
            fail('F1 存在「命中即 return」的短路写法 —— 后面的来源成为死代码：'
                 + re.sub(r'\s+', ' ', short_circuit.group(0))[:100])
        else:
            ok('F1 三个来源都无「命中即 return」短路')

        # ── F2 每处来源调用都必须把返回值落进变量
        #
        # v27 的判据是 re.findall(r'\bgot[123]\s*=')，期望 3 处。
        # v28 把来源重排成 model / allPages / originalData / self 四个，
        # 变量名随之变成 gotModel/gotPages/gotOrig/gotSelf —— 判据立刻假 FAIL。
        # 这跟 check_v24 的 E10 是同一个病：**判据绑在会变的外壳上**
        # （v27 那次绑的是版本号字面量 'v24 stats:'，这次绑的是变量名）。
        #
        # 按实质写：调用了几次，就必须有几次被赋值接住。
        # 差一处就说明有一份来源的结果被丢掉了 —— 那正是 v25 死代码的成因：
        # 结果没落变量，调用方也就无法知道「这份到底跑没跑过」。
        n_call = len(re.findall(r'\bCSFSPullOptions\s*\(', body))
        n_assign = len(re.findall(
            r'\b[A-Za-z_]\w*\s*=\s*CSFSPullOptions\s*\(', body))
        if n_call < 3:
            fail('F2 只找到 %d 处 CSFSPullOptions 调用，期望至少 3 个来源' % n_call)
        elif n_assign != n_call:
            fail('F2 %d 处来源调用里只有 %d 处把返回值落进了变量 —— '
                 '被丢掉的返回值意味着无法判断那份来源是否真的跑过'
                 % (n_call, n_assign))
        else:
            ok('F2 %d 处来源调用全部把返回值落进了变量' % n_call)

        # ── F4 FINAL 汇总日志
        if re.search(r'FINAL\s+hideWritten=', body):
            ok('F4 有 FINAL 汇总日志，可直接看出合并结果')
        else:
            fail('F4 缺少 FINAL 汇总日志 —— 合并结果不可观测')

    if pull is not None:
        body = strip_comments(pull)

        # ── F3 两个 hide* 开关必须是 OR 语义
        #
        # 为什么只管 hide*：它们的语义是「删掉某类内容」，
        # 合并取 OR —— 任一来源说删就删。若写成直接赋值，
        # 后一份同步落后的 NO 会把前一份的 YES 抹掉，用户勾了照样不删。
        #
        # handWrittenToImage 语义是「保留手写成图」，方向相反，
        # 取 OR 反而会把用户这次「手写转文字」的选择永久压成 YES，
        # 等于悄悄关掉 v22 实测可用的那条路。所以它允许直接赋值，
        # 单独断言它「有赋值且带 resolved 标记」。
        assign_raw = re.findall(
            r'gCSFS(?:HideWritten|HideStamp)\s*=\s*'
            r'(?!YES\b|NO\b|true\b|false\b)[A-Za-z_(\[]',
            body)
        if assign_raw:
            fail('F3 存在「直接赋值」写法 %d 处 —— 后一份来源会把前一份的 YES 覆盖掉，'
                 'hide* 必须先判真再置 YES' % len(assign_raw))
        else:
            ok('F3 hide* 合并是 OR 语义（只置 YES，不直接赋值）')

        set_yes = re.findall(
            r'gCSFS(?:HideWritten|HideStamp)\s*=\s*YES\s*;', body)
        if len(set_yes) >= 2:
            ok('F3 hide* 两个开关都有置 YES 的路径（%d 处）' % len(set_yes))
        else:
            fail('F3 hide* 只有 %d 处置 YES，期望 2 处 —— 有开关永远无法被打开' % len(set_yes))

        # handToImage 方向相反：必须是「按来源取值」而不是 OR
        #
        # 判定顺序很重要：先查「误用 OR」这个具体错形，再查「有没有赋值」。
        # 第一版把「找不到赋值」放前面，于是注入 OR 变体后
        # 'if (h) gCSFSHandToImage = YES;' 不匹配「按来源取值」的两种写法，
        # 直接掉进「找不到赋值路径」—— 报错了，但报的不是注入的那个错。
        # 反向验证的意义是「精确命中」，报错文案不对等于没验证到。
        if re.search(r'if\s*\(\s*h\s*\)\s*\{?\s*gCSFSHandToImage\s*=\s*YES\s*;', body) or \
           re.search(r'gCSFSHandToImage\s*\|\|=\s*', body) or \
           re.search(r'gCSFSHandToImage\s*=\s*gCSFSHandToImage\s*\|\|', body):
            fail('F3 handToImage 被 OR 成 YES —— 会把用户这次的「手写转文字」压掉，'
                 '它语义与 hide* 相反，不能取 OR')
        elif re.search(r'gCSFSHandToImage\s*=\s*h\s*;', body):
            ok('F3 handToImage 按语义单独处理（取最后一份明确值，不 OR）')
        elif re.search(r'gCSFSHandToImage\s*=\s*CSFSBoolValue\s*\(\s*hi\s*\)', body):
            ok('F3 handToImage 按语义单独处理（直接取本来源的值）')
        else:
            fail('F3 找不到 handToImage 的赋值路径')

    print('=== check_v27 ===')
    for m in oks:
        print('  [ OK ] ' + m)
    for m in fails:
        print('  [FAIL] ' + m)
    print('\nOK %d / FAIL %d' % (len(oks), len(fails)))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())