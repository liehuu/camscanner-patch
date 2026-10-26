#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api_push.py —— 走 GitHub Git Data API 推送，绕开 github.com 的 git 传输通道。

为什么需要这个：
  本机网络环境下 https://github.com/... 的 git smart-HTTP 通道会被代理拒
  （CONNECT tunnel failed, response 502），但 https://api.github.com 完全正常（200）。
  二者走的是不同的上游，所以只要把「传输层」从 git 换成 REST API 就能推。

  典型症状（本次真实遇到）：
    fatal: unable to access 'https://github.com/liehuu/xxx.git/':
           CONNECT tunnel failed, response 502
  而同一时刻 curl https://api.github.com/ 返回 200。

做法（Git Data API 的标准流程）：
  1. GET  /repos/{o}/{r}/git/ref/heads/{branch}     取当前 commit sha（分支可能还不存在）
  2. GET  /repos/{o}/{r}/git/commits/{sha}          取它的 tree sha
  3. 对每个改动文件 POST /git/blobs                建 blob
  4. POST /git/trees                                建新 tree（base_tree = 上一步的 tree）
  5. POST /git/commits                              建 commit
  6. PATCH /git/refs/heads/{branch}                 移动分支（不存在则 POST 创建）

用法：
  python3 tools/api_push.py --repo liehuu/camscanner-patch --branch main \
          --message-file /tmp/msg.txt --all
  python3 tools/api_push.py ... --files a.txt b.txt
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"


def get_token():
    """从 git credential 取已缓存的 GitHub token，避免把 token 写进命令行历史。"""
    try:
        p = subprocess.run(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n\n",
            capture_output=True, text=True, timeout=20,
        )
        for line in p.stdout.splitlines():
            if line.startswith("password="):
                return line[len("password="):]
    except Exception as e:
        print("读取凭据失败: %s" % e, file=sys.stderr)
    return None


class Gh:
    def __init__(self, token):
        self.token = token

    def req(self, method, path, payload=None, ok=(200, 201)):
        url = API + path
        data = None
        headers = {
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "camscanner-patch-api-push",
        }
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        r = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(r, timeout=90) as resp:
                body = resp.read()
                return resp.status, (json.loads(body) if body else {})
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            if e.code in ok:
                try:
                    return e.code, json.loads(body)
                except Exception:
                    return e.code, {}
            print("HTTP %d %s %s\n%s" % (e.code, method, path, body[:1200]), file=sys.stderr)
            raise


def git(*args):
    p = subprocess.run(["git"] + list(args), capture_output=True, timeout=60)
    return p.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="owner/name")
    ap.add_argument("--branch", default="main")
    ap.add_argument("--message", default="")
    ap.add_argument("--message-file", default="")
    ap.add_argument("--files", nargs="*", default=[], help="要提交的文件（相对路径）")
    ap.add_argument("--all", action="store_true", help="提交工作区所有已跟踪的改动 + 新增文件")
    ap.add_argument("--from-head", action="store_true",
                    help="推送本地 HEAD commit 的完整文件清单（用于本地已 commit、"
                         "或远端分叉后按内容 superset 重建线性历史）")
    ap.add_argument("--token", default="")
    args = ap.parse_args()

    token = args.token or get_token()
    if not token:
        print("ERROR: 拿不到 token", file=sys.stderr)
        return 1
    gh = Gh(token)

    # ── 收集要提交的文件 ────────────────────────────────────────────────
    if args.from_head:
        # 本地 HEAD 已有完整 commit 时，工作树反而是干净的（--all 会报
        # 「没有要提交的文件」），所以需要从 HEAD 直接取清单。
        # 两种典型场景：
        #   a. 本地已 commit，要把它同步到远端；
        #   b. 本机 git smart-HTTP 通道不通，之前每次都只用 API 推工作树，
        #      于是远端留下若干「没有对应本地 commit」的提交，历史分叉。
        #      此时若本地 HEAD 的内容是远端内容的超集（已验证过关键文件
        #      逐个 SAME），按 HEAD 清单整体重建一次即可，远端仍是线性的。
        files = git("ls-tree", "-r", "HEAD", "--name-only", "-z").decode(
            "utf-8", "replace").split("\0")
        files = [f for f in files if f]
        if not files:
            print("HEAD 下没有文件", file=sys.stderr)
            return 1
        print("按本地 HEAD 清单推送 %d 个文件" % len(files))
    elif args.all:
        # git status --porcelain 的格式：XY <path>；重命名是 "R  old -> new"
        files = []
        for line in git("status", "--porcelain").decode("utf-8", "replace").splitlines():
            if not line.strip():
                continue
            path = line[3:].strip()
            if " -> " in path:
                path = path.split(" -> ", 1)[1]
            path = path.strip('"')
            files.append(path)
    else:
        files = list(args.files)

    if not files:
        # 这个分支踩过两次同一个坑：先 `git commit` 再跑 `--all`，
        # 于是工作树是干净的、api_push 报「没有要提交的文件」，
        # 而本地 HEAD 明明还没有同步到远端。
        # 直接拿 HEAD 清单补推，并明确告知调用方发生了什么。
        if not args.files:
            files = git("ls-tree", "-r", "HEAD", "--name-only", "-z").decode(
                "utf-8", "replace").split("\0")
            files = [f for f in files if f]
            if files:
                print("工作区干净（或未指定 --files），改按本地 HEAD 清单推 %d 个文件"
                      % len(files))
        if not files:
            print("没有要提交的文件")
            return 0

    msg = args.message
    if args.message_file:
        msg = open(args.message_file, encoding="utf-8").read().rstrip("\n")
    # --from-head 且未显式给消息时，直接沿用本地 HEAD 的提交说明。
    # 远端重建出来的 commit message 与本地一致，事后回读才好对齐。
    if not msg and (args.from_head or not args.files):
        msg = git("log", "-1", "--pretty=%B").decode("utf-8", "replace").rstrip("\n")
    if not msg:
        print("ERROR: 需要 --message 或 --message-file", file=sys.stderr)
        return 1

    print("== 1. 取当前分支 head ==")
    parent = None
    try:
        st, ref = gh.req("GET", "/repos/%s/git/ref/heads/%s" % (args.repo, args.branch), ok=(200, 404))
        if st == 200:
            parent = ref["object"]["sha"]
            print("   父 commit: %s" % parent[:12])
        else:
            print("   分支 %s 不存在，将新建（init commit）" % args.branch)
    except urllib.error.HTTPError:
        print("   分支查询失败，按新建处理")

    base_tree = None
    if parent:
        st, c = gh.req("GET", "/repos/%s/git/commits/%s" % (args.repo, parent))
        base_tree = c["tree"]["sha"]
        print("   base tree: %s" % base_tree[:12])

    print("== 2. 创建 blob（%d 个文件）==" % len(files))
    entries = []
    for f in files:
        if not os.path.isfile(f):
            print("   SKIP（不存在）: %s" % f)
            continue
        raw = open(f, "rb").read()
        st, blob = gh.req("POST", "/repos/%s/git/blobs" % args.repo, {
            "content": base64.b64encode(raw).decode("ascii"),
            "encoding": "base64",
        })
        entries.append({
            "path": f.replace("\\", "/"),
            "mode": "100755" if (raw[:2] == b"#!" and f.endswith((".sh", ".py"))) else "100644",
            "type": "blob",
            "sha": blob["sha"],
        })
        print("   %-45s %7d B  %s" % (f, len(raw), blob["sha"][:10]))

    if not entries:
        print("没有任何文件被提交")
        return 1

    print("== 3. 创建 tree ==")
    payload = {"tree": entries}
    if base_tree:
        payload["base_tree"] = base_tree
    st, tree = gh.req("POST", "/repos/%s/git/trees" % args.repo, payload)
    print("   tree: %s" % tree["sha"][:12])

    print("== 4. 创建 commit ==")
    cpayload = {"message": msg, "tree": tree["sha"]}
    if parent:
        cpayload["parents"] = [parent]
    st, commit = gh.req("POST", "/repos/%s/git/commits" % args.repo, cpayload)
    print("   commit: %s" % commit["sha"][:12])

    print("== 5. 更新分支 ref ==")
    if parent:
        st, _ = gh.req("PATCH", "/repos/%s/git/refs/heads/%s" % (args.repo, args.branch), {
            "sha": commit["sha"], "force": True,
        })
        print("   已快进分支 %s" % args.branch)
    else:
        st, _ = gh.req("POST", "/repos/%s/git/refs" % args.repo, {
            "ref": "refs/heads/%s" % args.branch, "sha": commit["sha"],
        })
        print("   已创建分支 %s" % args.branch)

    # ── 6. 让本地 git 与远端对齐（只改本地记录，不联网）────────────────
    # 用建木提交的方式让本地 HEAD 与远端一致：fetch 走不通，
    # 所以在本地重建同样的 commit 对象需要 tree/blob，这里只更新 ref 指针是做不到的。
    # 因此打印远端 sha，交由调用方决定是否 reset。
    print()
    print("远端 commit: %s" % commit["sha"])
    return 0


if __name__ == "__main__":
    sys.exit(main())