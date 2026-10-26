#!/usr/bin/env bash
# push.sh —— 一键建仓库 + 推送 + 触发 CI
#
# 用法：
#   ./push.sh <GITHUB_PAT>
#
# PAT 权限只需 Repository permissions → Contents: Read and write
# （classic token 则勾 repo 即可）
#
# 做的事：
#   1. 用 API 创建私有仓库 liehuu/camscanner-patch（已存在则跳过）
#   2. 推送 main
#   3. 打印 Actions 页面地址
#
# 不会把 token 写进 .git/config 或任何文件（只在本次进程内用）。

set -euo pipefail

PAT="${1:-}"
if [ -z "${PAT}" ]; then
    echo "用法: $0 <GITHUB_PAT>" >&2
    exit 1
fi

OWNER="liehuu"
REPO="camscanner-patch"
API="https://api.github.com"

auth=(-H "Authorization: Bearer ${PAT}"
      -H "Accept: application/vnd.github+json"
      -H "X-GitHub-Api-Version: 2022-11-28")

echo "== 1. 校验 token =="
ME="$(curl -fsS "${auth[@]}" "${API}/user" | python -c "import sys,json;print(json.load(sys.stdin)['login'])")"
echo "   登录身份: ${ME}"

echo "== 2. 创建仓库 ${OWNER}/${REPO} =="
code="$(curl -s -o /tmp/repo_create.json -w '%{http_code}' -X POST "${auth[@]}" \
    "${API}/user/repos" \
    -d "{\"name\":\"${REPO}\",\"private\":true,\"description\":\"CamScanner 7.26.5 save-to-files patch (injected dylib)\",\"has_issues\":false,\"has_wiki\":false}")"
if [ "${code}" = "201" ]; then
    echo "   已创建私有仓库"
elif [ "${code}" = "422" ]; then
    echo "   仓库已存在，继续"
else
    echo "   创建失败 HTTP ${code}:"; cat /tmp/repo_create.json; exit 1
fi

echo "== 3. 推送 main =="
# 用 token 拼临时 URL，不落盘到 config
REMOTE="https://x-access-token:${PAT}@github.com/${OWNER}/${REPO}.git"
git remote set-url origin "${REMOTE}"
git push -u origin main --force
# 推完立刻把远端地址还原成不含 token 的形式，避免 token 残留
git remote set-url origin "https://github.com/${OWNER}/${REPO}.git"
echo "   推送完成，远端已还原为无 token 地址"

echo
echo "== 完成 =="
echo "仓库:  https://github.com/${OWNER}/${REPO}"
echo "Actions: https://github.com/${OWNER}/${REPO}/actions"
echo
echo "下一步：到 Actions 页面点 'Build CamScanner SaveToFiles IPA' → Run workflow"
echo "        并在 in/ 放原始 ipa，或用 ipa_url 传直链。"