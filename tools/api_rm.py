# -*- coding: utf-8 -*-
"""删除远端仓库里的临时文件（Git Data API 版）。

为什么需要单独一个工具：
    api_push.py 只能「写」文件，没法「删」—— Git Data API 删除路径的方式是
    在 tree 里显式给 sha=null，而 --from-head/--all 只会列出存在的文件。
    这一次就是 --all 误把工作区 4 个临时文件推上了 main：
        tmp_old19.m  tmp_v20.m  tmp_v22msg.txt（还有一个目录项 SKIP）
    原因是 `git commit` 之后工作树已干净，--all 只剩未跟踪文件可推 ——
    它推的正好是不该推的那一批。

用法：
    python tools/api_rm.py --repo liehuu/camscanner-patch --branch main \
        --message "chore: 清理误推的临时文件" tmp_old19.m tmp_v20.m tmp_v22msg.txt
"""
import argparse
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from api_push import get_token  # noqa: E402

API = "https://api.github.com"


def call(token, method, path, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        API + path, data=data, method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = r.read().decode("utf-8")
        return json.loads(raw) if raw.strip() else {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--branch", default="main")
    ap.add_argument("--message", required=True)
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()

    token = get_token()
    if not token:
        print("ERROR: 拿不到 token", file=sys.stderr)
        return 1

    ref = call(token, "GET", "/repos/%s/git/ref/heads/%s" % (args.repo, args.branch))
    head = ref["object"]["sha"]
    commit = call(token, "GET", "/repos/%s/git/commits/%s" % (args.repo, head))
    base_tree = commit["tree"]["sha"]
    print("父 commit: %s\nbase tree: %s" % (head[:12], base_tree[:12]))

    tree = [{"path": p, "mode": "100644", "type": "blob", "sha": None}
            for p in args.paths]
    new_tree = call(token, "POST", "/repos/%s/git/trees" % args.repo,
                    {"base_tree": base_tree, "tree": tree})
    print("tree: %s" % new_tree["sha"][:12])

    new_commit = call(token, "POST", "/repos/%s/git/commits" % args.repo,
                      {"message": args.message, "tree": new_tree["sha"],
                       "parents": [head]})
    print("commit: %s" % new_commit["sha"][:12])

    call(token, "PATCH", "/repos/%s/git/refs/heads/%s" % (args.repo, args.branch),
         {"sha": new_commit["sha"], "force": False})
    print("已更新分支 %s\n远端 commit: %s" % (args.branch, new_commit["sha"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
