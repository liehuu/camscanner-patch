# -*- coding: utf-8 -*-
"""下载某次 CI run 的 dylib 产物。

⚠ 302 陷阱（本项目真实踩过）：
    artifact 下载接口会 302 跳到 objects.githubusercontent.com（Azure Blob），
    而 urllib 默认会带着 Authorization 头一起跟过去 —— Azure 见到一个
    它不认识的 Bearer token 直接 401，报错还看不出是跳转导致的。
    所以必须让 redirect handler 丢弃这个头。

用法：
    python tools/dl_artifact.py <run_id> <out_dir> [artifact_name]
"""
import json
import os
import sys
import urllib.request
import zipfile
import io

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from api_push import get_token  # noqa: E402

REPO = "liehuu/camscanner-patch"
API = "https://api.github.com"


class NoAuthRedirect(urllib.request.HTTPRedirectHandler):
    """跨主机跳转时丢掉 Authorization —— 见文件头 302 陷阱。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = urllib.request.HTTPRedirectHandler.redirect_request(
            self, req, fp, code, msg, headers, newurl)
        if new is not None:
            for h in ("Authorization", "authorization"):
                try:
                    new.remove_header(h)
                except Exception:
                    pass
            # remove_header 在某些 Python 版本上不清理 unredirected_hdrs
            new.unredirected_hdrs.pop("Authorization", None)
        return new


def api_get(path):
    req = urllib.request.Request(
        API + path,
        headers={"Authorization": "Bearer " + get_token(),
                 "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    run_id, out_dir = sys.argv[1], sys.argv[2]
    want = sys.argv[3] if len(sys.argv) > 3 else "CamScannerSaveToFiles-dylib"

    arts = api_get("/repos/%s/actions/runs/%s/artifacts" % (REPO, run_id))
    target = None
    for a in arts.get("artifacts", []):
        print("found artifact: %s (%d B, expired=%s)"
              % (a["name"], a["size_in_bytes"], a["expired"]))
        if a["name"] == want:
            target = a
    if not target:
        print("ERROR: 没找到产物 %s" % want)
        return 1

    opener = urllib.request.build_opener(NoAuthRedirect)
    req = urllib.request.Request(
        API + "/repos/%s/actions/artifacts/%s/zip" % (REPO, target["id"]),
        headers={"Authorization": "Bearer " + get_token(),
                 "Accept": "application/vnd.github+json"})
    with opener.open(req, timeout=300) as r:
        blob = r.read()
    print("zip %d B" % len(blob))

    os.makedirs(out_dir, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for n in z.namelist():
            print("  %s (%d B)" % (n, z.getinfo(n).file_size))
        z.extractall(out_dir)
    print("OK -> %s" % out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
