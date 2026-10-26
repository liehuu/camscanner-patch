#!/usr/bin/env bash
# push.sh —— 建仓库 + 推送 + 打印 Actions 地址
#
# 用法（两种都支持）：
#   ./push.sh                     从 git credential 里取已缓存的 GitHub 凭据（推荐）
#   ./push.sh <GITHUB_PAT>        显式传 token
#
# 设计要点：token 绝不落进 .git/config。
#   早期版本用 `git remote set-url origin https://x-access-token:TOKEN@...`，
#   即使用完再 set-url 还原，token 仍会在 .git/config 里留下过期快照，
#   而且一旦推送被中断就还原不到。这里改用 credential.helper 的临时注入：
#     git -c credential.helper='!f() { echo username=x-access-token; echo password=$TOK; }; f' push
#   只在这一次进程的参数里出现，不写盘。

set -euo pipefail

OWNER="liehuu"
REPO="camscanner-patch"
API="https://api.github.com"

PAT="${1:-}"
if [ -z "${PAT}" ]; then
    echo "== 未传 token，尝试读取 git 已缓存的 GitHub 凭据 =="
    PAT="$(printf 'protocol=https\nhost=github.com\n\n' | git credential fill 2>/dev/null | sed -n 's/^password=//p' || true)"
    if [ -z "${PAT}" ]; then
        echo "ERROR: 本机没有缓存的 GitHub 凭据，请显式传 PAT：$0 <GITHUB_PAT>" >&2
        exit 1
    fi
    echo "   已取得缓存凭据（长度 ${#PAT}）"
fi

auth=(-H "Authorization: Bearer ${PAT}"
      -H "Accept: application/vnd.github+json"
      -H "X-GitHub-Api-Version: 2022-11-28")

# 用 python 解析 JSON，避免依赖 jq（Git Bash 默认没有）
jget() { python -c "import sys,json;d=json.load(sys.stdin);print(d.get('$1',''))" 2>/dev/null || true; }

echo "== 1. 校验 token =="
ME="$(curl -fsS "${auth[@]}" "${API}/user" | jget login)"
if [ -z "${ME}" ]; then
    echo "ERROR: token 无效或网络不通" >&2
    exit 1
fi
echo "   登录身份: ${ME}"

SCOPES="$(curl -sI "${auth[@]}" "${API}/user" | tr -d '\r' | sed -n 's/^[Xx]-[Oo][Aa]uth-[Ss]copes: *//p')"
echo "   权限范围: ${SCOPES:-（fine-grained token，按仓库授权）}"

echo "== 2. 确保仓库 ${OWNER}/${REPO} 存在 =="
code="$(curl -s -o /tmp/cs_repo.json -w '%{http_code}' "${auth[@]}" "${API}/repos/${OWNER}/${REPO}")"
if [ "${code}" = "200" ]; then
    echo "   仓库已存在，跳过创建"
elif [ "${code}" = "404" ]; then
    code2="$(curl -s -o /tmp/cs_repo.json -w '%{http_code}' -X POST "${auth[@]}" \
        "${API}/user/repos" \
        -d "{\"name\":\"${REPO}\",\"private\":true,\"description\":\"CamScanner 7.26.5 save-to-files patch (injected dylib)\",\"has_issues\":false,\"has_wiki\":false}")"
    case "${code2}" in
        201) echo "   已创建私有仓库" ;;
        422) echo "   仓库已存在（422），继续" ;;
        *)   echo "ERROR: 创建失败 HTTP ${code2}"; cat /tmp/cs_repo.json; exit 1 ;;
    esac
else
    echo "ERROR: 查询仓库失败 HTTP ${code}"; cat /tmp/cs_repo.json; exit 1
fi

echo "== 3. 推送 main =="
# 不落盘：通过 -c 临时覆盖 credential.helper
git -c credential.helper='' \
    -c "credential.helper=!f() { test \"\$1\" = get && echo username=x-access-token && echo password=${PAT}; }; f" \
    push --force -u "https://github.com/${OWNER}/${REPO}.git" HEAD:refs/heads/main

echo "== 4. 确认远端状态 =="
ls_sha="$(curl -fsS "${auth[@]}" "${API}/repos/${OWNER}/${REPO}/commits/main" | jget sha)"
echo "   远端 main = ${ls_sha:0:12}"
local_sha="$(git rev-parse HEAD)"
echo "   本地 HEAD  = ${local_sha:0:12}"
if [ "${ls_sha:0:12}" != "${local_sha:0:12}" ]; then
    echo "WARN: 远端与本地不一致，请检查" >&2
fi

echo
echo "== 完成 =="
echo "仓库   : https://github.com/${OWNER}/${REPO}"
echo "Actions: https://github.com/${OWNER}/${REPO}/actions"
echo
echo "远端地址仍为无 token 形式："
git remote -v | sed 's/^/  /'