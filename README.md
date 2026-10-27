# CamScanner 7.26.5「保存到文件」补丁

给扫描全能王 / CamScanner Lite **7.26.5**（`com.intsig.CamScannerLite`）的分享面板补回
「保存到文件」，让「图片转 Word」生成的文件能直接存进 iOS「文件」App。

补丁形态是**注入式 dylib**。编译在 GitHub Actions 的 macOS runner 上完成（产物仅 ~140KB），
**注入与重打包在本机用纯 Python 完成**，不需要 Xcode / clang / codesign，也不需要下载 266MB 的成品 ipa。

> **当前产物**：`dist/CamScanner_7.26.5_SaveToFiles_local.ipa`（192.1 MB，2026-10-27 v4）
> 对应 CI run `40443332968`（commit `8434b9ff`，success）
> dylib 含 **arm64 + arm64e 双切片**（361,016 B），与主二进制 arm64e 对齐。

---

## ★ 装完后第一件事：看日志

v4 开始有**文件日志**，手机上直接可取，不用连电脑、不用 Xcode：

1. 打开「文件」App → 我的 iPhone → **扫描全能王**（LC 里装的这个 app）
2. 找到 **`CSFS.log`**，长按 → 共享/拷贝出来

日志开头一定是这三行（确认装的是 v4）：
```
==========================================================
CamScannerSaveToFiles v4 loaded (build <日期> <时间>)
日志位置：App 沙盒 Documents/CSFS.log
==========================================================
```

然后关键看这两条：
```
★★★ officeFileShareViewData hook=1 ★★★（这是 Word 面板的唯一入口）
...
built item ...: title=保存到文件 (wrote=1)
appended save-to-files entry, total=N
```

- `hook=1` → 挂点装上了；`hook=0` → 挂点没找到（把日志发我）
- `wrote=1` → 标题写进去了；`wrote=0` 或出现 `KVC set ... threw` → 是属性名问题
- `appended ... total=N` → 条目真的进数组了
- 若点「导出文档」后**完全没有** `officeFileShareViewData` 相关日志
  → 说明走的是另一个面板，需要重新定位（把日志发我）

---

## 1. 缺陷成因（逆向实证）

---

## 0. 版本演进与根因（四次真机反馈驱动）

### v4（当前）：第四次失败后才找到真正原因 —— hook 挂错了地方

用户第三次反馈仍是「邮件旁边、PDF 分享下方都没有」。把「导出文档」这条路
完整反汇编一遍后拿到决定性结论：

```
-exportWordAction 0x1012ee770 → -exportWord 0x1012eea10 → -shareWord 0x1012eec80
  → -showShareView 0x1018861fc → -showOfficeShareView 0x101888498
      ├─ -officeFileShareViewData 0x101888534      ← 数据在这里生成
      └─ +[CSSheetUtil showSingleSheetWithHeadConfig:dataList:...] 0x101888590
                                          ↑ 数组直接当实参传进去
```

**这个数组不经过任何 dataSource setter。** 反证：

| selector | 全 App 调用点数 | 调用者 |
|---|---|---|
| `setVerticallyListDataSource:` | **2** | 都在 `ISBlockDiversifiedActionSheetView` 的某个 init 内 |
| `setHorizontallyDataSource:` | **3** | `CSShareHorizontalAdapter` / `CSShareIconItemAdapter` / 同一 init |

**没有一处来自 `CSSheetUtil`。** 所以 v1~v3 一直在 hook 的那两个 setter，
对这个面板 **100% 不生效**——它们压根不会被调用。

> **最该记住的一句：判断 hook 有没有用，不能只看它「装上了」，要看它「在真实路径上」。**
> `method_setImplementation` 成功就返回 YES，永远显示成功；
> 但那条路上可能根本没人走过。前三次失败全部输在这一点。

v4 的三处对应修改：

1. 唯一有效挂点锁定 `-officeFileShareViewData`，并打印 `★★★ hook=1/0 ★★★`
2. 属性名以**原作者自己的调用**为准（`officeFileShareViewData` 内实证）：
   `setIdentifyId:`（`w2=0x64`，Swift Int）、`setTitle:`、`setIconImage:`
3. KVC 失败回退 IMP 直调 —— Swift 类默认不走 `-setValue:forKey:` 自动查找

### v3：真机反馈查出四条根因

| # | 根因 | 为什么查不到 | 后果 |
|---|---|---|---|
| A | 条目属性名写错（KVC 异常被自己 `@catch` 吞掉） | 名字「看着像」 | 面板静默不变 |
| B | 纵向数据源是**二维数组**，一维 `addObject:` | `cellForRowAtIndexPath:` 分组时走 `data[section][row]` | **崩宿主** |
| C | 「转换失败」根因是 `Reachability` 误报 `NotReachable` | 转换函数第一步就查网络（`0x101755fb4 cbz`） | 弹「转换失败」 |
| D | setter 名漏一个 `List`：`setVerticallyDataSource:` 在二进制里**不存在** | 只扫 `adrp+ldr` 得「0 处引用」假结论，实际走 `__objc_stubs` 跳板 | hook 从未装上 |

**D 的方法论教训**：现代 clang 把方法调用编成 `bl <stub>`，selref 的 `adrp+ldr` 在
`__objc_stubs` 段里而不在调用点。必须先解析 `__objc_stubs` 建立 `stub地址 → selector名`
映射，再在 `__text` 找 `bl stub`。我据此差点第二次改错方向。

详见 `扫描全能王_图片转Word_保存到文件_缺陷分析报告.md` 第「三·补」「三·补二」章。

---

## 1. 缺陷成因（逆向实证）

原版分享面板 `- [CSShareManager officeFileShareViewData]`（`0x10188860c`）硬编码了 5 个条目，
没有「保存到文件」：

| identifyId | 文案 key | 格式 |
|---|---|---|
| `0x64` | `cs_519b_pdf_share` | PDF |
| `officeFileShareType` | `cs_632_cloud_08` | 当前文档格式（PPT） |
| `officeFileShareType` | `cs_519b_word_share` | 当前文档格式（Word） |
| `officeFileShareType` | `cs_622_docstructure_06` | 当前文档格式（Excel） |
| `officeFileShareType` | `cs_633_cloud_01` | 原始格式 |

点击条目后由 `- [CSShareManager shareActionWithOperationTpe:]`（`0x1018c492c`）
按 operationType 查表分发（`0x1088ce534` 起的 halfword 跳转表，覆盖 `0x64`–`0x7D`）。

Word 最终出口是 `- [CSShareManager showShareActivityWithFilePath:completionBlock:]`
（`0x1018aa33c`）→ block（`0x1018aa6e4`）→ **`CCBus asyncCallData:@"share/system"`**
（`0x1018aa8c8`），即交给 app 自己的分享服务去弹系统面板。

关键的反证，说明「能力齐备，只是没接到 Word 上」：

- `- [CSDocSignatureBottomSonPresent sharePdfUrl:isSaveFileSystem:rootFolder:documentId:]`
  （`0x100b07a8c`）在 `0x100b07cb8` **已经使用了导出式**
  `- [UIDocumentPickerViewController initForExportingURLs:asCopy:]`（stub `0x105fc9e40`）
- `- [CSIGpyNativeHostApiImplement presentDocumentPickerWithFilePath:logPrefix:completion:]`
  （`0x10222354c`）同样有现成实现
- `com.apple.DocumentManager` 在主二进制出现 **0 次** → 不是黑名单排除
- `setExcludedActivityTypes:` 全二进制仅 1 处（`- [CSShareController showMoreAction]` `0x10190efbc`），与 Word 无关

**结论**：缺陷在产品层的面板条目缺失 + 分发缺分支，而不是系统权限或 API 能力问题。
因此最小侵入的修法是把面板补一条、把分发补一支，把最后一步的「弹系统分享」换成「弹文件选择器」。

### 一个必须绕开的坑

`- [CSShareManager officeFilePathsWithComplete:]`（`0x1018a9590`）看起来是理想的
「给我路径」入口，但反汇编显示它只做「把 `document.officeFilePath` 指向的文件复制到
`CSOfficeFileShareFolder` 临时目录」：

- `officeFilePath` 为空时**直接跳过该文档**（`0x1018a9760` / `0x1018a99f0`）
- 只有 `(成功数 + 失败数 == dataArray.count)` 时才回调 block（`0x1018a9a98`）

也就是说 Word 尚未转换时它**既不报错也不回调**，用它做入口会变成「点了没反应」。
所以补丁改为「借道原链路 + 出口接管」。

---

## 2. 补丁做了什么

| Hook | 目的 |
|---|---|
| `-[CSShareManager officeFileShareViewData]` | 在原 5 条之后再追加一条「保存到文件」（`identifyId = 0xE5`），并记下面板展示时的 `officeFileShareType` |
| `-[CSShareManager shareActionWithOperationTpe:needLog:]` | **主拦截点**。命中 `0xE5` 时：置 pending 标记 → 用真实 office 格式重新走原实现，让 app 走自己的转换/配额/VIP 链路 |
| `-[CSShareManager shareActionWithOperationTpe:]` | 同上（一参数版本，面板回调实际落在它上面） |
| `-[CSShareManager showShareActivityWithFilePath:completionBlock:]` | 公共出口。pending 命中 → 改道 `initForExportingURLs:asCopy:YES`；否则原样转发 |
| `-[CSActivityUtil shareWithActivityItems:subject:result:]` | 兜底增强：把 NSString 路径规范成 fileURL，保证系统分享面板也能出现「存储到文件」。纯增益，失败即透传 |

### 为什么两个 shareAction 重载都要 hook

这里有一个很容易踩空的地方，必须讲清楚：

| selector | IMP | 内容 |
|---|---|---|
| `-shareActionWithOperationTpe:` | `0x1018c492c` | 只有两条指令的 **thunk**：`mov w3,#1` + `b 0x106165680` |
| `-shareActionWithOperationTpe:needLog:` | `0x1018c4934` | **真正的实现体**（含 `0x64`–`0x7D` 分派表） |

证据链：

```
0x1018c492c  mov w3,#1 ; b #0x106165680
0x106165680  adrp x1,... ; ldr x1,[x1,#0x478]  →  shareActionWithOperationTpe:needLog:
0x106165660  adrp x1,... ; ldr x1,[x1,#0x470]  →  shareActionWithOperationTpe:
```

两个 selref 槽（`0x107a1a470` / `0x107a1a478`）相邻，证实是同一对重载。

签名不是猜的，是从 `class_ro_t → baseMethods` 的 relative `method_t`
逐个读出 `__RODATA,__objc_methtype` 得到的：

| selector | types | 解读 |
|---|---|---|
| `shareActionWithOperationTpe:` | `B24@0:8q16` | `BOOL (id, SEL, long)` |
| `shareActionWithOperationTpe:needLog:` | `B28@0:8q16B24` | `BOOL (id, SEL, long, BOOL)` |

其中 `B`=BOOL、`@`=id（隐式 self）、`:`=SEL（隐式 _cmd）、`q`=long（NSInteger）。
实现体第 9 行 `mov x20, x3`（x3 = 第 3 个参数 = needLog 的 BOOL）与编码互相印证。

**只 hook 一参数版本**能拦到「面板点击」（面板回调走 thunk），
但会漏掉所有**直接调 `:needLog:`** 的入口。所以两个都 hook，主拦截点在 `:needLog:`。

### 由此引出的一个必崩写法（已固化进 lint）

`CSFSBeginSaveToFiles` 里要「重派发回原链路」，如果写成：

```objc
IMP imp = [manager methodForSelector:@selector(shareActionWithOperationTpe:)];
((BOOL(*)(id,SEL,NSInteger))imp)(manager, sel, officeType);
```

取回的是**已被我们替换掉的 hook IMP**，于是：

```
hook → CSFSBeginSaveToFiles → hook → CSFSBeginSaveToFiles → …  栈溢出 → 闪退
```

正确写法是调安装时保存的 `gOrig*`。这一条已作为 `lint_dylib.py` 的 **R7** 规则固化，
并做过反证（故意写递归版本 → 脚本报 FAIL 并拒绝通过）。

`asCopy:YES` 是关键：系统在导出模式下会自己处理**新建**与**同名覆盖**的冲突提示，
补丁不需要也不应该自己写文件。

### 复用到了什么

因为「先借道原链路」，下列 app 自有逻辑全部保留，补丁不重造：

- Word 转换（`shareJsonWordConvertToWordComplete:` → `jsonWordConvertToFileWithModel:completion:`）
- 配额 / VIP 判定（`checkBeforeSharingWordWithParams:isWordPayDefer:resultBlock:`）
- 文件名清洗与生成目录（`officeFileNameWithTitle:extension:` / `CSOfficeFileShareFolder`）
- 埋点与审计日志

---

## 3. 构建

### 目录

```
camscanner-patch/
├── .github/workflows/build.yml   CI：预检 → 编译 → 注入 → 重签 → 打包 → 上传
├── src/CamScannerSaveToFiles.m   补丁源码（唯一需要改的源文件）
├── tools/
│   ├── presyntax.py              ObjC 语法预检（纯文本，不需要编译器，Windows 也能跑）
│   ├── inject_dylib.py           纯 Python 的 LC_LOAD_DYLIB 注入（不依赖 optool）
│   ├── lint_dylib.py             「崩宿主」专项静态检查（CI 强制闸门）
│   └── entitlements.plist        签名用 entitlements
├── Makefile                      本地快捷构建
└── in/                           放原始 ipa（见 in/README.md，支持 LFS / 直链）
```

### 跑 CI

两种模式（`workflow_dispatch` 的 `mode` 输入）：

| mode | 做什么 | 需要原始 ipa | 耗时 |
|---|---|---|---|
| `dylib`（默认） | 只编译 + 崩宿主 lint，验证源码**能否编过** | 否 | ~1 分钟 |
| `full` | 解包 → 注入 → 重签 → 重打包 → 出 ipa | 是 | ~8 分钟 |

提供原始 ipa，二选一：

- 放到 `in/`（例：`in/CamScanner_7.26.5_original.ipa`，约 192 MB，走 Git LFS），或
- 不放进仓库，触发时在 `ipa_url` 填私有 Release 直链。细节见 `in/README.md`。

**踩过的坑（`ipa_url` 要读私有 Release asset）**：asset 挂在 **draft** release 下时，
`contents:read` 的 `GITHUB_TOKEN` 读不到它 —— draft 资产只对具备 `contents:write` 的
集成开放，GitHub 返回 **403 而不是 404**，只看状态码会误判成权限整体配错。
所以承载输入包的 release 必须转正（`draft:false`；仓库本身是 private，外部仍不可见）。
下载时 workflow 会带 `Accept: application/octet-stream`，正好是 asset API 的取回方式。

触发步骤：

1. GitHub → Actions → **Build CamScanner SaveToFiles IPA** → Run workflow。
2. `mode` 选 `full`，`ipa_url` 填 asset API 地址
   （形如 `https://api.github.com/repos/<owner>/<repo>/releases/assets/<id>`）。
3. 产物：`CamScanner-SaveToFiles-ipa`，含 `out/CamScanner_7.26.5_SaveToFiles.ipa`。
   `CamScannerSaveToFiles-dylib` 产物两种模式都会上传。

CI 会强制校验：

- `presyntax.py` 必须全绿（括号/块配平、selector 可知性、hook 签名对齐）—— **在编译之前**
- Bundle ID 必须是 `com.intsig.CamScannerLite`
- 主二进制必须存在 `CSShareManager` / `CSActivityUtil` / `CSShareModel` 三个类
  （换了 app 或砍了类的版本会被直接拒绝，不会产出错包）
- **输入包必须是未注入的**：主二进制已有 `CamScannerSaveToFiles` 加载项、
  或 `Frameworks/` 下已有同名 dylib，直接 fail（对已注入包二次注入 = 双重交换 = 必崩）
- 版本不是 7.26.5 时打 warning（补丁按 7.26.5 的符号写的）
- `lint_dylib.py` 必须全绿
- 注入时 `install_name` 必须是干净的绝对路径 / `@rpath` 形式
  （被 MSYS 之类改写成本地 Windows 路径会被拦死，见 §4 的坑）
- 注入后回读校验：二进制里真实存储的加载项必须等于期望值
- `install_name_tool` 改完后，主二进制的加载项必须与 dylib 的 LC_ID_DYLIB 一致
  （不一致 = 装上去必然闪退，这一条卡在打包前）

### 本地（任意平台）

```bash
make check                        # 语法预检 + 崩宿主检查，不需要编译器
```

Windows 上把解释器显式指过去：

```bash
make check PYTHON="C:/Users/xxx/.workbuddy/binaries/python/versions/3.13.12/python.exe"
```

### 本地（macOS，需 Xcode）

```bash
make dylib                       # 编译（会先自动跑语法预检）
make lint                        # 只跑崩宿主检查（含产物层检查）
make inject IPA=in/original.ipa   # 全流程出 ipa
```

---

## 4. 注入原理

`tools/inject_dylib.py` 不改任何已有 load command，只在 `32 + sizeofcmds` 之后、
第一个有文件实体的小节之前写一条新的 `LC_LOAD_DYLIB`，然后更新 `ncmds` / `sizeofcmds`。

实测该二进制可用头部空洞：

```
header end    : 0x4998
第一个实体小节: 0x8000 (__text)
可用空洞      : 13928 字节
需要          :   64 字节（"/usr/lib/CamScannerSaveToFiles.dylib"）
```

写完后 CI 再用 `install_name_tool -change` 把它改指到
`@executable_path/Frameworks/CamScannerSaveToFiles.dylib`，dylib 实际放在 app 内，
不需要写系统 `/usr/lib`。脚本幂等：重复执行会检测到已注入并直接返回。

不依赖 `optool` / `insert_dylib`，避免 macOS runner 上装第三方工具与
chained fixups 版本兼容问题。

### 一个静默到可怕的坑：install_name 被 MSYS 改写

在 **Windows 的 Git Bash** 里执行：

```bash
python inject_dylib.py CamScanner_Lite /usr/lib/CamScannerSaveToFiles.dylib
```

MSYS2 会把以 `/` 开头的参数当成路径自动转换，实际写进二进制的变成：

```
C:/Users/fengb/AppData/Local/Programs/WorkBuddy/resources/vendor/PortableGit/usr/lib/CamScannerSaveToFiles.dylib
```

这个错误**每一道常规检查都能通过**：

| 检查 | 结果 |
|---|---|
| Mach-O 结构完整 | 通过 |
| `ncmds` 从 177 → 178 | 通过 |
| `sizeofcmds` 正确增长 | 通过 |
| load command 不重叠 | 通过 |
| `codesign` 签名 | 通过 |

但 dyld 在设备上永远找不到这个库 —— 要么启动即闪退，要么补丁静默失效。

所以 `inject_dylib.py` 现在做三件事：

1. **写盘前拒绝**：`^[A-Za-z]:[\\/]`、`/c/` 开头、含反斜杠/空格/控制字符的 install_name 一律 `SystemExit`
2. 只接受绝对路径或以 `@rpath/` `@executable_path/` `@loader_path/` 开头
3. **写盘后回读**：重新解析二进制，确认 `dylib_names()` 里真实存在期望字符串，
   且 `ncmds` 恰好 +1

正确用法（任一）：

```bash
MSYS_NO_PATHCONV=1 python inject_dylib.py bin '/usr/lib/Foo.dylib'
python inject_dylib.py bin '@executable_path/Frameworks/Foo.dylib'    # 单引号 + 非 / 开头
```

实测结果：

```
need            : 64 bytes
write at        : 0x4998
== 注入完成 ==
  ncmds      -> 178
  sizeofcmds -> 0x49b8
  install_name -> /usr/lib/CamScannerSaveToFiles.dylib
  回读校验   -> OK
```

同一个二进制重复执行会返回「已注入，无需操作」，幂等。

---

## 5. 「崩宿主」防线

本项目历史上出过「编译完全通过、装上直接进安全模式」的事故，
四条必崩路径**全部能过编译**，所以防线必须建在运行期语义上：

| 必崩写法 | 本补丁的处置 |
|---|---|
| 在进程里 `dlopen` 一个可能已在运行的库 | **完全不 dlopen**，由 LC_LOAD_DYLIB 一次性加载，全局唯一 |
| orig 为 NULL 仍被转发调用 | 每处转发前强制判空；`lint_dylib.py` 用语法分析验证「有效保护」，**空 `if` 块会被判定为未保护** |
| hook 私有方法签名错位 | 所有签名由反汇编实证（含 selector 拼写逐个从 `__objc_methname` 核出），`presyntax.py` P6 校验形参个数 |
| hook 热路径读文件 / 写日志 | hook 内零文件 IO；路径合法性检查只在用户点击后的异步流程里做 |
| 用 `methodForSelector:` 取回自己的 hook 再重派发 → 无限递归 | `lint_dylib.py` **R7** 规则专项拦截；代码里一律走 `gOrig*` |

另外：

- 每个 hook 函数体整体 `@try/@catch`，异常绝不出线程（`lint` 用大括号配平逐个验证，不漏检含 block 参数的函数）
- 构造器整体 `try/catch`，类未注册时静默降级 + 延迟重试，不影响宿主启动
- 私有属性一律 `respondsToSelector` + protocol 声明，不用裸点语法
- pending 标记 20 秒自动失效，避免残留导致后续正常分享被误改道
- 只插入一条新 `identifyId = 0xE5`，不覆盖任何原有分支（原分派表只用到 `0x64`–`0x7D` / `0xD3` / `0xDE` / `0xDF` / `0xF0` / `0xF2` / `0x43`）

`lint_dylib.py` 的有效性做过反证：故意写一个含 `dlopen` + 空 `if` 守卫 + 文件 IO +
无 `@try` 的样本，脚本如实报出 6 项失败并拒绝通过。

### 两道闸门的分工

历史上的返工分两类，性质完全不同，不能互相替代：

| | 拦什么 | 工具 | 跑在 |
|---|---|---|---|
| 第一道 | **编不过**：少右括号、`@interface` 被误删、`@try` 缺失、hook 参数个数错位 | `presyntax.py` | 编译**之前** |
| 第二道 | **跑起来崩**：dlopen 双加载、orig 未判空、热路径文件 IO、裸点语法 | `lint_dylib.py` | 编译**之后** |

`presyntax.py` 不需要编译器（纯文本分析），所以在 Windows 上也能跑，
能把「3~5 分钟的 CI 往返」提前到本地 0.2 秒。它检查六项：

- P1 括号配平（`()` `[]` `{}`，跳过字符串与注释，报告**具体行号与该行内容**）
- P2 字符串/字符字面量闭合
- P3 `@interface` / `@implementation` / `@protocol` 与 `@end` 配平
- P4 `@try` / `@catch` / `@finally` 配平
- P5 **selector 可知性**：每条消息发送的 selector 必须在 `@protocol` 声明或系统白名单内
  —— 专治「重写文件时把私有类声明当注释删掉」，这一条是 **FAIL 而非 WARN**，
  因为带病代码若能 push 就等于没检查
- P6 **hook 签名对齐**：`CSFSHookInstance` 里 selector 的冒号数必须等于
  实现函数的形参个数减 2（`self` + `_cmd`）。参数错位在运行期就是读野指针

有效性同样做过反证：

| 违规样本 | presyntax 结果 |
|---|---|
| `[NSString class"];`（少右括号） | ✅ FAIL：`P1 第 4 行：'}' 与第 3 行的 '[' 不匹配` |
| 删掉 `@protocol` 后发 `setIdentifyId:` | ✅ FAIL：`P5 未声明的 selector 'setIdentifyId:'` |
| hook 表无安装点 | ✅ FAIL：`P6 未找到任何 CSFSHookInstance 安装点` |

三条都被拦下，退出码 1。

---

## 6. 验证清单（装机后按序走）

前置：设备已能装自签 ipa（SideStore / AltStore /  TrollStore 均可）。

### 6.1 装上了、没崩

1. 安装并**冷启动** App。
2. 控制台过滤 `CamScannerSaveToFiles`，应看到：
   ```
   [CamScannerSaveToFiles] loaded, starting install
   [CamScannerSaveToFiles] hooked -[CSShareManager officeFileShareViewData] ...
   [CamScannerSaveToFiles] hooked -[CSShareManager shareActionWithOperationTpe:] ...
   [CamScannerSaveToFiles] hooked -[CSShareManager shareActionWithOperationTpe:needLog:] ...
   [CamScannerSaveToFiles] hooked -[CSShareManager showShareActivityWithFilePath:completionBlock:] ...
   [CamScannerSaveToFiles] install finished, installed=1
   ```
3. 没有 `install finished` 或 `installed=0` → 类名/方法名对不上，别继续往下测。
4. 若看到 `WARN: 未能 hook shareActionWithOperationTpe:needLog:`，
   说明该重载不存在（版本不符）；主拦截点退回一参数版本，功能仍可用但覆盖面变窄。

### 6.2 主场景：图片转 Word → 保存到文件（新建）

1. 拍照或导入图片 → 转 Word → 等转换完成。
2. 点分享 → 面板底部应多出「保存到文件」。
3. 点它 → 先出现「正在生成文件…」，随后弹出系统的文件选择器（不是分享面板）。
4. 选「我的 iPhone / 某个文件夹」→ 存储。
5. **预期**：toast 提示「已保存到「文件」：xxx.docx」；到「文件」App 里对应目录能看到，
   点开内容与 App 内预览一致。

### 6.3 覆盖场景

对 6.2 已存在的同名文件再存一次 → 系统应弹「替换 / 两者都保留」，选「替换」后
文件被覆盖且内容为新版本；选「两者都保留」应生成 `xxx 2.docx`。

### 6.4 取消

在文件选择器里点取消 → 无任何提示，App 停在原页面，不崩、不卡死。

### 6.5 回归：原有分享不受影响

1. 同一文件走**原来的**「Word」条目 → 应正常弹系统分享面板（微信/邮件等），
   与未打补丁时一致。
2. 重复 6.2 与 6.5 交替 5 次以上，确认 pending 标记不会串场
   （正常分享被误改成文件选择器 = 标记残留，看日志有没有 `pending flag expired`）。

### 6.6 其它格式

PDF / Excel / PPT 各走一遍「保存到文件」，确认走的是对应格式（看日志
`officeFileShareType = 0x7b/0x79/0x7a`），扩展名正确。

### 6.7 万一崩了怎么恢复

- 崩溃日志：`/var/mobile/Library/Logs/CrashReporter/` 下最新的 `*.ips`，
  找 `CamScanner_Lite`；重点看 `Exception Type` 与 `Thread 0` 的栈顶，
  若栈顶落在 `CamScannerSaveToFiles` 的镜像范围内即为补丁问题。
- 回滚：直接卸载重装**未打补丁**的原版 ipa 即可，补丁不改用户数据、不写沙盒外任何文件。
- 若怀疑注入本身导致启动即崩（`dyld` 报错），先用 CI 的 `diagnostics` 产物里的
  `otool -L` 结果核对加载项路径是否与 dylib 的 LC_ID_DYLIB 一致。

---

## 7. 已知限制

- 补丁按 **7.26.5** 的符号编写。升级到其它版本时，类名/selector 大概率还在，
  但 operationType 分派表与面板结构可能变化，需要重新核对 `0xE5` 是否被占用。
- CI 里是 ad-hoc 签名（`-`），产物**不能**直接装到未越狱设备；
  需换真实证书，或交给 SideStore/AltStore 二次签名。
- 「保存到文件」目前只对 PDF / Word / Excel / PPT 开放；Markdown 等其它类型
  会提示「当前内容暂不支持导出」，避免走空路径。
- `initForExportingURLs:asCopy:` 需要 iOS 14+；iOS 13 上自动退化为系统分享面板
  （传 fileURL，仍有「存储到文件」）。