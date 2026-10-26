# in/ —— 原始 ipa 放置目录

CI 从这里取原始包。三种给法，任选其一：

## 方式 A：直接提交（走 Git LFS）

```bash
git lfs install
cp /path/to/扫描全能王_7.26.5.ipa in/CamScanner_7.26.5_original.ipa
git add .gitattributes in/CamScanner_7.26.5_original.ipa
git commit -m "chore: add original ipa via lfs"
git push
```

已被 `.gitattributes` 标记为 `filter=lfs`，不会触发 100MB 单文件限制。
LFS 免费额度 1GB 存储 / 1GB 月流量，167MB 的包大约够 6 次完整 checkout。

## 方式 B：从私有 Release 下（推荐，仓库保持干净）

不要往 `in/` 放任何东西，直接在 GitHub 上手动触发 workflow，
把 `ipa_url` 填成私有 Release 的 asset 直链。CI 会先 curl 下来再解包。

```bash
gh release create v7.26.5-original /path/to.ipa --repo <you>/<repo>
# 然后在 Actions → Run workflow 里：
#   ipa_url = https://github.com/<you>/<repo>/releases/download/v7.26.5-original/xxx.ipa
```

私有仓库的 release 直链需要带 token。CI 里已注入 `GITHUB_TOKEN`，
若链接是私有 asset，把 `ipa_url` 写成 API 形式更稳：

```
https://api.github.com/repos/<you>/<repo>/releases/assets/<asset_id>
```

workflow 会用 `Authorization: Bearer $GITHUB_TOKEN` + `Accept: application/octet-stream` 拉取。

## 方式 C：本地跑（macOS 且已装 Xcode）

```bash
make inject IPA=/path/to/扫描全能王_7.26.5.ipa
```

---

**注意**：`in/` 下只应有一个 `.ipa`。CI 找不到指定文件名时会取第一个，
多于一个容易拿错包（拿到已注入过的包会导致重复注入 → 双份 dylib → 必崩）。