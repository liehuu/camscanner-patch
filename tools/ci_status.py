# -*- coding: utf-8 -*-
"""查 CI 运行状态（本机没有 gh，github.com 的 git 通道也不通，只有 api 通）。"""
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from api_push import get_token  # noqa: E402

REPO = "liehuu/camscanner-patch"


def get(path):
    req = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Authorization": "Bearer " + get_token(),
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def main():
    d = get("/repos/%s/actions/runs?per_page=5" % REPO)
    for w in d.get("workflow_runs", []):
        print("%-12s %-10s %-10s %s  %s" % (
            w["id"], w["status"], w["conclusion"] or "-",
            w["head_sha"][:8], w["created_at"]))
    if len(sys.argv) > 1:
        rid = sys.argv[1]
        j = get("/repos/%s/actions/runs/%s/jobs" % (REPO, rid))
        for job in j.get("jobs", []):
            print("-- job %s: %s %s" % (job["name"], job["status"], job["conclusion"] or "-"))
            for st in job.get("steps", []):
                print("   %-45s %-10s %s" % (st["name"][:45], st["status"],
                                             st["conclusion"] or "-"))


if __name__ == "__main__":
    main()
