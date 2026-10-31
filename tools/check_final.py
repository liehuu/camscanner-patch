#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_final —— 终版：诊断代码必须清除，且功能不许被误伤

背景：v37 的版式已与手机预览逐行对齐，用户决定「暂时用这版作为可使用的版本」，
要求把诊断代码去掉出终版。

「诊断代码」在本文档里有明确定义 —— 不是所有日志都算诊断：

  算诊断（必须删）
    ① 结构勘探 dump：v21/v25/v33 DIAG、v11 diag
       开发期靠它把字段名、层级、单位一次性定死；定死之后它只在刷日志。
    ② 崩溃取证：CSFSCrashTrace + [CRASH-TRACE]
       定位闪退时用的同步 write(2)；闪退已解决，留着是裸系统调用。
    ③ 启动自证 toast：每次冷启动 3 秒后弹「[补丁v5] 已加载 ✓」
       源码注释自己写着「诊断结束后这行可以删掉」。终版每次启动都弹，
       这是最刺眼的一条。
    ④ 只服务于 ①~③ 的开关变量与死代码：diagDone / paraDiagDone /
       layoutDiagDone / imgDiagDone / diagnosticPtr / CSFSDescribeDeep /
       CSFSBriefValue

  不算诊断（必须留）
    · 异常与失败日志（`… threw:` / WARN）—— 出问题时唯一的现场
    · 每段/每批的决策与结果（v35 overflow / v36 ind none / v21 stats）
      —— 用户每次反馈都附 CSFS.log，删了就等于瞎
    · 业务 toast（已保存到「文件」等）
    · CSFS_LOG 框架本身

所以本检查器分两组：F 组证明诊断已清除，V 组证明清除时没连带删坏。

为什么 F 组不能只查「文件里没有 DIAG 这个词」：
  ① 注释里也会出现（`v21 DIAG slice dict(11)` 曾被当成证据引用）；
  ② 反过来，删了日志但留下开关变量，代码里照样是诊断结构。
  所以判据一律在 strip_comments 之后的代码上做，且日志与变量分开查。

跑法：python3 tools/check_final.py src/CamScannerSaveToFiles.m
"""
import re
import sys

OK = 0
FAIL = 0
FAILED = []


def ok(m):
    global OK
    OK += 1
    print('  [ OK ] %s' % m)


def fail(m):
    global FAIL
    FAIL += 1
    FAILED.append(m)
    print('  [FAIL] %s' % m)


def strip_comments(s):
    """去掉 // 与 /* */ 注释，保留字符串字面量内容。

    必须保留字符串：判据要查的正是 @"…" 里的日志文案。
    必须去注释：注释里出现过 `v21 DIAG` 这类引用，不去掉会误判。
    """
    out = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == '"':
            out.append(c)
            i += 1
            while i < n:
                if s[i] == '\\':
                    out.append(s[i:i + 2])
                    i += 2
                    continue
                out.append(s[i])
                if s[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == '/' and i + 1 < n:
            if s[i + 1] == '/':
                j = s.find('\n', i)
                i = n if j < 0 else j
                continue
            if s[i + 1] == '*':
                j = s.find('*/', i + 2)
                i = n if j < 0 else j + 2
                continue
        out.append(c)
        i += 1
    return ''.join(out)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'src/CamScannerSaveToFiles.m'
    raw = open(path, encoding='utf-8').read()
    code = strip_comments(raw)
    # 源码里的 XML 都在 @"…" 里，引号带反斜杠转义；比对前还原成裸引号
    flat = code.replace('\\"', '"')

    # ══════════════════════════════════════════════════════════════
    # F 组：诊断代码已清除
    # ══════════════════════════════════════════════════════════════
    m_diag = re.search(r'\b(?:v21|v25|v33)\s+DIAG\b|\bv11\s+diag\b', code)
    if m_diag:
        ln = code.count('\n', 0, m_diag.start()) + 1
        fail('F1 仍有结构勘探 dump（第 %d 行「%s」）—— '
             '字段名/单位已定死，这类日志只会刷屏'
             % (ln, m_diag.group(0)))
    else:
        ok('F1 无结构勘探 dump（v21/v25/v33 DIAG、v11 diag 均已清除）')

    if 'CSFSCrashTrace' in code or 'CRASH-TRACE' in code:
        fail('F2 仍有崩溃取证（CSFSCrashTrace / [CRASH-TRACE]）—— '
             '裸同步 write(2)，终版不应存在')
    else:
        ok('F2 崩溃取证已清除（无 CSFSCrashTrace / [CRASH-TRACE]）')

    m_banner = re.search(r'CSFSShowLoadedBanner|已加载\s*✓', code)
    if m_banner:
        fail('F3 仍有启动自证 toast（%s）—— 每次冷启动都弹，终版必须去掉'
             % m_banner.group(0))
    else:
        ok('F3 无启动自证 toast（冷启动不再弹「已加载」）')

    # 签名：必须收成单参数。绑「BOOSt *」而不是绑参数名，
    # 这样改个名字骗不过去。
    if re.search(r'CSFSParseSlice\s*\(\s*id\s+sl\s*,\s*BOOL\s*\*', code):
        fail('F4 CSFSParseSlice 仍带诊断指针参数 —— '
             '出参只服务于「dump 一次」，应随诊断一起删除')
    elif not re.search(r'CSFSParseSlice\s*\(\s*id\s+sl\s*\)', code):
        fail('F4 找不到 CSFSParseSlice(id sl) 定义 —— 签名被改成了别的形态，需人工复核')
    else:
        ok('F4 CSFSParseSlice 已是单参数（id sl），无诊断出参')

    dead = [nm for nm in ('CSFSDescribeDeep', 'CSFSBriefValue')
            if nm in code]
    if dead:
        fail('F5 死代码仍在：%s —— 它们只被已删除的 DIAG 调用'
             % '、'.join(dead))
    else:
        ok('F5 无死代码（CSFSDescribeDeep / CSFSBriefValue 已清）')

    if 'v37 final loaded' not in flat:
        fail('F6 版本横幅不是终版标识 —— 装完分不清是哪一版，'
             '应为「CamScannerSaveToFiles v37 final loaded」')
    else:
        ok('F6 版本横幅为终版标识（v37 final）')

    # ══════════════════════════════════════════════════════════════
    # V 组：清诊断时不许误伤功能
    # ══════════════════════════════════════════════════════════════
    # ⚠ 必须用正则钉到宏名本身：子串 `#define CSFS_LOG` 会被
    #   `#define CSFS_LOGX(` 满足 —— 改名骗过检查，正是子串匹配的经典坑
    #   （rev_check_final 的 I7 一注入就暴露了它，所以这里不能退回 find）。
    if not re.search(r'#define\s+CSFS_LOG\s*\(', code) or \
            'static void CSFSLogToFile(NSString *msg) {' not in code:
        fail('V1 CSFS_LOG 框架被删了 —— 日志是唯一排障手段，'
             '出问题时只能靠 CSFS.log 定位')
    else:
        ok('V1 CSFS_LOG 框架完整（宏 + 写盘实现都在）')

    if 'w:right="800"' not in flat or 'w:left="800"' not in flat:
        fail('V2 页边距不是 800 —— 删诊断时把 v37 的版心成果带回去了，'
             '每行字数会重新对不上预览')
    else:
        ok('V2 页边距左右仍为 800（v37 版心成果未被误伤）')

    if 'static const double kCSFSContentTwips = 10306.0;' not in code:
        fail('V3 版心常量不是 10306.0 —— 与 pgMar 不同源，'
             '会出现「判据在跑、分支从不触发」')
    else:
        ok('V3 版心常量 10306.0 与页边距自洽')

    keep = ['已保存到', '没有可导出的文件']
    miss = [k for k in keep if k not in flat]
    if miss:
        fail('V4 业务 toast 被误删：%s —— 用户看不到导出结果'
             % '、'.join(miss))
    else:
        ok('V4 业务 toast 完整（已保存到「文件」、没有可导出的文件）')

    leftovers = re.findall(r'\b(?:paraDiagDone|layoutDiagDone|imgDiagDone|blankDiag|diagDone)\b',
                           code)
    if leftovers:
        fail('V5 诊断开关变量残留：%s —— 删了日志却留着开关，'
             '代码里仍是诊断结构' % '、'.join(sorted(set(leftovers))))
    else:
        ok('V5 无诊断开关变量残留（diagDone / paraDiagDone / … 均已清）')

    print('-' * 66)
    print('check_final 通过：OK %d / FAIL %d' % (OK, FAIL))
    if FAIL:
        for m in FAILED:
            print('  - %s' % m)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
