#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gate_local.py —— 本地一键跑完 CI「Pre-syntax check」里的全部门禁。

为什么需要这个（2026-10-28 真实事故）：
  本地自检时凭记忆敲了 6 个检查器，漏了 decl_order.py。
  于是 v25 带着「CSFSCaptureLayoutContext 使用早于声明 12 行」推上去，
  CI 一次 3 分钟往返，挂在第 5 步，后面 12 步全部 skipped。

  问题不在「忘了跑某一个」，而在「本地清单与 CI 清单是两份」。
  两份清单必然会漂移，而漂移的那一刻没有任何提示。

做法：
  不维护第二份清单。直接解析 .github/workflows/build.yml 里
  「Pre-syntax check」那一步的 run 脚本，抽出所有 `python3 tools/xxx ...` 行，
  按原顺序原参数执行 —— CI 加了一项，本地自动多跑一项。

  CI 用 python3，Windows 上可能没有 python3 别名，所以统一替换成当前解释器。

用法：
  python tools/gate_local.py            # 跑全量
  python tools/gate_local.py --list     # 只列出会跑哪些命令，不执行
退出码：0 全过 / 1 有失败
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "build.yml")

# 只认这一步。名字改了要跟着改，改不动就让脚本报错，不要静默跳过。
STEP_NAME = "Pre-syntax check"


def extract_commands():
    """从 build.yml 里抠出 Pre-syntax check 步骤的所有 python3 tools/... 调用。"""
    with open(WORKFLOW, encoding="utf-8") as f:
        lines = f.read().split("\n")

    start = None
    for i, ln in enumerate(lines):
        if ln.strip().startswith("- name:") and STEP_NAME in ln:
            start = i
            break
    if start is None:
        raise RuntimeError("build.yml 里找不到步骤「%s」，解析规则已失效" % STEP_NAME)

    # 步骤的 run: | 块，到下一个同级 `- name:` 或文件末为止
    body = []
    in_run = False
    for ln in lines[start + 1:]:
        if re.match(r"^\s{6}- name:", ln):
            break
        if re.match(r"^\s+run:\s*\|", ln):
            in_run = True
            continue
        if in_run:
            # 同级的下一个 step 键（缩进回到 6 空格且非空行）
            if ln.strip() and not ln.startswith(" " * 10):
                break
            body.append(ln)

    cmds = []
    for ln in body:
        s = ln.strip()
        if s.startswith("#") or not s:
            continue
        m = re.match(r"^python3\s+tools/(\S+)\s*(.*)$", s)
        if m:
            cmds.append((m.group(1), m.group(2).strip()))
    if not cmds:
        raise RuntimeError("步骤「%s」里没解析出任何 python3 tools/ 调用" % STEP_NAME)
    return cmds


def main():
    list_only = "--list" in sys.argv
    try:
        cmds = extract_commands()
    except Exception as e:  # noqa: BLE001
        print("[FAIL] %s" % e)
        return 1

    print("=" * 68)
    print("本地门禁 —— 命令清单来自 build.yml 的「%s」步骤（%d 项）" % (STEP_NAME, len(cmds)))
    print("=" * 68)

    if list_only:
        for script, args in cmds:
            print("  tools/%-34s %s" % (script, args))
        return 0

    failures = []
    for idx, (script, args) in enumerate(cmds, 1):
        path = os.path.join(ROOT, "tools", script)
        if not os.path.exists(path):
            print("[%2d/%2d] %-40s [MISSING]" % (idx, len(cmds), script))
            failures.append((script, "文件不存在"))
            continue
        cmd = [sys.executable, path] + ([args] if args else [])
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        out = (p.stdout or "") + (p.stderr or "")
        if p.returncode == 0:
            # 摘要行通常是最后一段里的 OK x / FAIL y
            summary = ""
            for ln in reversed(out.strip().split("\n")):
                t = ln.strip()
                if t and ("OK" in t or "通过" in t or "验证" in t or "精确命中" in t):
                    summary = t
                    break
            print("[%2d/%2d] %-40s [ OK ] %s" % (idx, len(cmds), script, summary[:60]))
        else:
            print("[%2d/%2d] %-40s [FAIL] rc=%d" % (idx, len(cmds), script, p.returncode))
            for ln in out.strip().split("\n"):
                if "FAIL" in ln or "错误" in ln or "Error" in ln:
                    print("        " + ln.strip()[:150])
            failures.append((script, "rc=%d" % p.returncode))

    print()
    if failures:
        print("门禁未通过：%d / %d 项失败" % (len(failures), len(cmds)))
        for script, why in failures:
            print("  - %s (%s)" % (script, why))
        return 1
    print("门禁全部通过（%d 项）" % len(cmds))
    return 0


if __name__ == "__main__":
    sys.exit(main())