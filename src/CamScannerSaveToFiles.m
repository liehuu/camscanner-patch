//
//  CamScannerSaveToFiles.m
//  为扫描全能王 / CamScanner Lite 7.26.5 补回「保存到文件」导出能力
//  Target: com.intsig.CamScannerLite (arm64, cryptid=0)
//
//  ─────────────────────────────────────────────────────────────────────
//  设计要点（务必遵守，破坏任何一条都可能让宿主进程崩溃）
//  ─────────────────────────────────────────────────────────────────────
//   1. 不做 dlopen。本 dylib 由主二进制的 LC_LOAD_DYLIB 一次性加载，全局唯一，
//      不会出现"同一张方法表被两个引擎改写"的双加载场景。
//   2. 所有 orig IMP 转发前判空；所有私有方法调用前 respondsToSelector。
//   3. 被 hook 的方法签名全部由目标二进制反汇编实证得出，不做猜测：
//        -[CSShareManager officeFileShareViewData]                    -> NSMutableArray*
//        -[CSShareManager shareActionWithOperationTpe:]               -> BOOL  (2 条指令的 thunk)
//        -[CSShareManager shareActionWithOperationTpe:needLog:]       -> BOOL  (真实现体)
//        -[CSShareManager showShareActivityWithFilePath:completionBlock:] -> void
//        -[CSActivityUtil shareWithActivityItems:subject:result:]     -> void
//
//      注：曾计划用 -[CSShareManager officeFilePathsWithComplete:] 作为入口，已被否证。
//      反汇编 0x1018a9590 显示它只把 document.officeFilePath 复制到临时目录
//      CSOfficeFileShareFolder；当 officeFilePath 为空时该文档被静默跳过
//      （0x1018a9760 / 0x1018a99f0），且只有 (成功数+失败数 == dataArray.count)
//      才回调（0x1018a9a98）。Word 尚未转换时它既不报错也不回调 ——
//      用作入口会表现为「点了没反应」，因此改为 hook 真正的出口
//      -showShareActivityWithFilePath:completionBlock:（0x1018aa33c），
//      在其内部完成「拦截 → 换 UIDocumentPickerViewController 导出」。
//   4. 每个 hook 函数体整体 @try/@catch，异常绝不外溢到调用方线程。
//   5. 构造器整体 try/catch；目标类未注册时静默降级并延迟重试，
//      任何情况下都不影响宿主启动。
//   6. hook 内无同步文件 IO、无 IPC、无大对象分配。
//   7. 私有属性一律走 protocol 声明 + respondsToSelector，不用裸点语法。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#define CSFS_LOG(fmt, ...) NSLog(@"[CamScannerSaveToFiles] " fmt, ##__VA_ARGS__)

// ── 面板条目的 identifyId。原 app 使用 0x64~0x7D / 0xD3 / 0xDE / 0xDF / 0xF0 / 0xF2 / 0x43，
//    0xE5 未被占用（见 -[CSShareManager shareActionWithOperationTpe:needLog:] 的分派表）。
static const NSInteger kCSFSSaveToFilesId = 0xE5;
static NSString *const kCSFSSaveToFilesTitle = @"保存到文件";

static BOOL gCSFSInstalled = NO;

// ═══════════════════════════════════════════════════════════════════════
#pragma mark - 私有接口声明（签名均来自反汇编实证）
// ═══════════════════════════════════════════════════════════════════════

@protocol CSFSSheetItem <NSObject>
- (NSInteger)identifyId;
- (void)setIdentifyId:(NSInteger)identifyId;
- (void)setTitle:(NSString *)title;
- (void)setIconImage:(UIImage *)iconImage;
@end

@protocol CSFSShareManagerOps <NSObject>
// 当前文档对应的 office 格式 operationType：
//   0x78=Word  0x79=Excel  0x7A=PPT  0x7B=PDF  0x7C/0x7D=其它  0xD3=Markdown
- (NSInteger)officeFileShareType;
// 统一的「分享某文件」出口：所有 office 导出最终都会到这里
- (void)showShareActivityWithFilePath:(NSString *)filePath
                      completionBlock:(void (^)(void))completionBlock;
@end

// MBProgressHUD 的最小可用面
// 注意：MBProgressHUD 三套隐藏 API 必须全部声明，否则对 id 发送未声明的
// selector 在 ARC 下就是编译错误（no known instance method for selector）。
@protocol CSFSHUD <NSObject>
+ (instancetype)showHUDAddedTo:(UIView *)view animated:(BOOL)animated;
- (void)hide:(BOOL)animated afterDelay:(NSTimeInterval)delay;
- (void)hideAnimated:(BOOL)animated afterDelay:(NSTimeInterval)delay;
- (void)hideAnimated:(BOOL)animated;
- (void)hide:(BOOL)animated;
- (void)setMode:(NSInteger)mode;
- (void)setLabelText:(NSString *)text;
@end

// ═══════════════════════════════════════════════════════════════════════
#pragma mark - 通用工具
// ═══════════════════════════════════════════════════════════════════════

static UIWindow *CSFSTopWindow(void) {
    UIWindow *fallback = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (![scene isKindOfClass:[UIWindowScene class]]) continue;
            for (UIWindow *w in ((UIWindowScene *)scene).windows) {
                if (w.isKeyWindow) return w;
                if (!fallback) fallback = w;
            }
        }
    }
    if (fallback) return fallback;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return UIApplication.sharedApplication.keyWindow;
#pragma clang diagnostic pop
}

static UIViewController *CSFSTopViewController(void) {
    UIViewController *vc = CSFSTopWindow().rootViewController;
    if (!vc) return nil;

    // 沿 presentedViewController 链走到最上层，最多 16 层，防环
    for (int i = 0; i < 16; i++) {
        UIViewController *next = vc.presentedViewController;
        if (!next) break;
        vc = next;
    }
    // 再落到底部容器
    for (int i = 0; i < 16; i++) {
        if ([vc isKindOfClass:[UINavigationController class]]) {
            UIViewController *v = ((UINavigationController *)vc).visibleViewController;
            if (!v || v == vc) break;
            vc = v;
        } else if ([vc isKindOfClass:[UITabBarController class]]) {
            UIViewController *v = ((UITabBarController *)vc).selectedViewController;
            if (!v || v == vc) break;
            vc = v;
        } else {
            break;
        }
    }
    return vc;
}

// MBProgressHUD 文本提示；失败完全静默，绝不影响主流程
static void CSFSToast(NSString *message) {
    if (message.length == 0) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            Class hudClass = NSClassFromString(@"MBProgressHUD");
            UIWindow *win = CSFSTopWindow();
            if (hudClass && win) {
                id<CSFSHUD> hud = [(id<CSFSHUD>)hudClass showHUDAddedTo:win animated:YES];
                if (hud) {
                    if ([hud respondsToSelector:@selector(setMode:)]) {
                        [hud setMode:3];   // MBProgressHUDModeText
                    }
                    if ([hud respondsToSelector:@selector(setLabelText:)]) {
                        [hud setLabelText:message];
                    }
                    // 新老两套 API 都试
                    if ([hud respondsToSelector:@selector(hideAnimated:afterDelay:)]) {
                        [(id)hud hideAnimated:YES afterDelay:1.6];
                    } else if ([hud respondsToSelector:@selector(hide:afterDelay:)]) {
                        [hud hide:YES afterDelay:1.6];
                    } else if ([hud respondsToSelector:@selector(hide:)]) {
                        [hud hide:YES];
                    }
                    return;
                }
            }
        } @catch (NSException *e) {
            CSFS_LOG(@"toast failed: %@", e.reason);
        }
        CSFS_LOG(@"%@", message);
    });
}

// 显示一个等待指示。返回刚创建的对象，同时记到模块级变量里，
// 这样 CSFSHideBusy(nil) 能关掉"当前正在显示的那个"。
//
// 为什么要有模块级持有：调用方有两处写的是 CSFSHideBusy(nil)
// （原链路拒绝了 / 改道完成后），如果不做全局持有，
// 这两处就是空操作，HUD 会一直挂在屏幕上转圈 —— 用户会以为卡死。
static __weak id gCSFSBusyHUD = nil;

static id CSFSShowBusy(NSString *text) {
    @try {
        Class hudClass = NSClassFromString(@"MBProgressHUD");
        UIWindow *win = CSFSTopWindow();
        if (!hudClass || !win) return nil;
        id<CSFSHUD> hud = [(id<CSFSHUD>)hudClass showHUDAddedTo:win animated:YES];
        if (hud && text.length && [hud respondsToSelector:@selector(setLabelText:)]) {
            [hud setLabelText:text];
        }
        gCSFSBusyHUD = hud;
        return hud;
    } @catch (NSException *e) {
        return nil;
    }
}

static void CSFSHideBusy(id hud) {
    // 传 nil 表示"关掉当前显示的那个"，而不是什么都不做
    id target = hud ? hud : gCSFSBusyHUD;
    if (!target) return;
    if (!hud) gCSFSBusyHUD = nil;
    @try {
        id<CSFSHUD> h = (id<CSFSHUD>)target;
        if ([h respondsToSelector:@selector(hideAnimated:)]) {
            [h hideAnimated:YES];
        } else if ([h respondsToSelector:@selector(hide:)]) {
            [h hide:YES];
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"hide busy threw: %@", e.reason);
    }
}

// 把任意元素（NSString 路径 / NSURL / 带 path 的对象）规整成存在的本地 fileURL
static NSURL *CSFSCoerceToFileURL(id obj) {
    NSURL *url = nil;
    @try {
        if ([obj isKindOfClass:[NSURL class]]) {
            url = (NSURL *)obj;
            if (!url.isFileURL && url.path.length > 0) url = [NSURL fileURLWithPath:url.path];
        } else if ([obj isKindOfClass:[NSString class]]) {
            NSString *s = (NSString *)obj;
            if (s.length == 0) return nil;
            if ([s hasPrefix:@"file://"]) {
                url = [NSURL URLWithString:s];
            } else if ([s hasPrefix:@"/"]) {
                url = [NSURL fileURLWithPath:s];
            } else {
                // 既不是绝对路径也不是 file URL：可能是相对路径或纯文件名，放弃
                return nil;
            }
        } else if ([obj respondsToSelector:NSSelectorFromString(@"path")]) {
            // 用 IMP 直接取，避免 performSelector 在 ARC 下的告警与内存语义问题
            IMP imp = [obj methodForSelector:NSSelectorFromString(@"path")];
            if (imp) {
                id (*fn)(id, SEL) = (id (*)(id, SEL))imp;
                id p = fn(obj, NSSelectorFromString(@"path"));
                if ([p isKindOfClass:[NSString class]] && [(NSString *)p length] > 0) {
                    url = [NSURL fileURLWithPath:(NSString *)p];
                }
            }
        }
    } @catch (NSException *e) {
        return nil;
    }
    if (!url) return nil;
    if (![[NSFileManager defaultManager] fileExistsAtPath:url.path]) return nil;
    return url;
}

// ═══════════════════════════════════════════════════════════════════════
#pragma mark - 文档选择器代理
// ═══════════════════════════════════════════════════════════════════════

@interface CSFSPickerDelegate : NSObject <UIDocumentPickerDelegate>
@end

// 强持有代理，picker 结束后释放，避免野指针
static CSFSPickerDelegate *gCSFSPickerDelegate = nil;
static __weak UIDocumentPickerViewController *gCSFSActivePicker = nil;

@implementation CSFSPickerDelegate

- (void)documentPicker:(UIDocumentPickerViewController *)controller
    didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    CSFS_LOG(@"didPickDocumentsAtURLs count=%lu", (unsigned long)urls.count);
    if (urls.count == 1) {
        CSFSToast([NSString stringWithFormat:@"已保存到「文件」：%@",
                   urls.firstObject.lastPathComponent ?: @""]);
    } else if (urls.count > 1) {
        CSFSToast([NSString stringWithFormat:@"已保存 %lu 个文件到「文件」",
                   (unsigned long)urls.count]);
    }
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
    // 用户取消：静默，不打扰
    CSFS_LOG(@"documentPickerWasCancelled");
}

@end

// ═══════════════════════════════════════════════════════════════════════
#pragma mark - 「保存到文件」导出实现
// ═══════════════════════════════════════════════════════════════════════

static void CSFSPresentExportPicker(NSArray<NSURL *> *fileURLs) {
    if (fileURLs.count == 0) {
        CSFSToast(@"没有可导出的文件");
        return;
    }
    UIViewController *host = CSFSTopViewController();
    if (!host) {
        CSFSToast(@"当前无可用的展示页面");
        return;
    }
    if (host.presentedViewController) {
        // 原分享面板可能还在退场动画中，等一拍再试，最多重试 3 次
        // 用静态计数器避免无限递归
        static int retry = 0;
        if (retry < 3) {
            retry++;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                CSFSPresentExportPicker(fileURLs);
            });
            return;
        }
        retry = 0;
        CSFSToast(@"请先关闭当前弹窗再试");
        return;
    }

    if (@available(iOS 14.0, *)) {
        // 导出式 picker：asCopy=YES，系统负责"新建 / 覆盖同名文件"的完整交互
        UIDocumentPickerViewController *picker =
            [[UIDocumentPickerViewController alloc] initForExportingURLs:fileURLs asCopy:YES];
        if (!gCSFSPickerDelegate) gCSFSPickerDelegate = [CSFSPickerDelegate new];
        picker.delegate = gCSFSPickerDelegate;
        picker.allowsMultipleSelection = (fileURLs.count > 1);
        gCSFSActivePicker = picker;
        [host presentViewController:picker animated:YES completion:nil];
        CSFS_LOG(@"presented export picker with %lu url(s)", (unsigned long)fileURLs.count);
    } else {
        // iOS 13 及以下没有导出式 picker，退化为系统分享表（传 fileURL 仍会出现"存储到文件"）
        UIActivityViewController *avc =
            [[UIActivityViewController alloc] initWithActivityItems:fileURLs
                                             applicationActivities:nil];
        if (avc.popoverPresentationController) {
            avc.popoverPresentationController.sourceView = host.view;
            avc.popoverPresentationController.sourceRect =
                CGRectMake(CGRectGetMidX(host.view.bounds),
                           CGRectGetMidY(host.view.bounds), 1, 1);
        }
        gCSFSActivePicker = nil;
        [host presentViewController:avc animated:YES completion:nil];
        CSFS_LOG(@"presented legacy activity controller with %lu url(s)", (unsigned long)fileURLs.count);
    }
}

// ═══════════════════════════════════════════════════════════════════════
#pragma mark - 导出核心：先让 app 自己把文件生成出来，再改道到文件选择器
// ═══════════════════════════════════════════════════════════════════════
//
// 为什么不直接调 -officeFilePathsWithComplete:？
//   反汇编 0x1018a9590 显示它只做「把 document.officeFilePath 指向的文件复制到
//   临时目录」，officeFilePath 为空时**直接跳过该文档**，并且只有在
//   (收集成功数 + 失败数 == dataArray.count) 时才回调。也就是说当 Word 还没
//   转换出来时，它既不报错也不回调 —— 用它做入口会变成"点了没反应"。
//
// 因此采用「借道原链路 + 出口接管」：
//   1) 记下 pending 标记；
//   2) 调原 -shareActionWithOperationTpe:（Word 类型），app 会走它自己的
//      转换 → jsonWordConvertToWordComplete: → actionSheetClickItemAndShare...；
//   3) 所有 office 导出的最终公共出口是
//      -showShareActivityWithFilePath:completionBlock:（0x1018aa33c），
//      在该方法里发现 pending 标记就把 fileURL 交给 UIDocumentPicker 而不是
//      交给 CCBus 去弹系统分享面板。
//   这样复用了 app 的配额校验 / VIP 判定 / 转换排队 / 临时目录逻辑，
//   补丁只替换"最后一步去哪里"。

static NSInteger gCSFSOfficeShareType = 0x7B;   // 最近一次面板展示时的格式

// ── orig IMP 指针 ──────────────────────────────────────────────────────
// 必须定义在使用点之前。C 语言没有 Hoisting：CSFSBeginSaveToFiles 在 ~L394
// 就要用它们重派发给原实现，而原先这两个定义写在 ~L619，clang 直接报
//   error: use of undeclared identifier 'gOrigShareActionWithOperationTpe'
//   error: call to undeclared function ... [-Wimplicit-function-declaration]
//   error: redefinition ... as different kind of symbol
// 所以统一挪到模块级状态区，和 gCSFSOfficeShareType 放一起。
static BOOL (*gOrigShareActionWithOperationTpe)(id, SEL, NSInteger) = NULL;
static BOOL (*gOrigShareActionWithOperationTpeNeedLog)(id, SEL, NSInteger, BOOL) = NULL;

@interface CSFSExportState : NSObject
@property (class, nonatomic, readonly) CSFSExportState *shared;
@property (atomic, assign) BOOL pendingSaveToFiles;
@property (atomic, assign) NSInteger pendingDeadlineTick;
@end

@implementation CSFSExportState
+ (CSFSExportState *)shared {
    static CSFSExportState *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [CSFSExportState new]; });
    return s;
}
- (instancetype)init {
    if ((self = [super init])) { _pendingSaveToFiles = NO; }
    return self;
}
@end

static void CSFSArmPending(void) {
    CSFSExportState.shared.pendingSaveToFiles = YES;
    // 20 秒后自动失效，避免标记残留导致下一次正常分享被误接管
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(20.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (CSFSExportState.shared.pendingSaveToFiles) {
            CSFS_LOG(@"pending flag expired without hitting the exit");
            CSFSExportState.shared.pendingSaveToFiles = NO;
        }
    });
}

static BOOL CSFSConsumePending(void) {
    @synchronized (CSFSExportState.shared) {
        if (!CSFSExportState.shared.pendingSaveToFiles) return NO;
        CSFSExportState.shared.pendingSaveToFiles = NO;
        return YES;
    }
}

// 入口：由面板「保存到文件」条目触发
static void CSFSBeginSaveToFiles(id manager, NSInteger officeType) {
    if (!manager) return;

    // Markdown / 其它非常规 office 类型没有对应的 office 文件，直接提示
    if (officeType != 0x78 && officeType != 0x79 &&
        officeType != 0x7A && officeType != 0x7B) {
        CSFSToast(@"当前内容暂不支持导出");
        return;
    }

    CSFSArmPending();
    CSFSShowBusy(@"正在生成文件…");

    // 交给原分发逻辑，触发 app 自己的转换链路
    //
    // ⚠ 这里绝对不能写 `[manager methodForSelector:sel]`。
    //   此刻该方法表里存的 IMP 已经被我们替换成 CSFS_shareActionWithOperationTpe，
    //   methodForSelector: 取回来的就是 hook 自己 —— 于是形成
    //     hook → CSFSBeginSaveToFiles → hook → CSFSBeginSaveToFiles → …
    //   的无限递归，几秒内栈溢出、宿主闪退。
    //   必须走安装时存下的 orig IMP。
    BOOL ok = NO;
    @try {
        if (gOrigShareActionWithOperationTpeNeedLog) {
            // 用 needLog=YES 走真实实现体（一参数版本只是 thunk，最终也会落到这里）
            ok = gOrigShareActionWithOperationTpeNeedLog(manager,
                                                         @selector(shareActionWithOperationTpe:needLog:),
                                                         officeType, YES);
        } else if (gOrigShareActionWithOperationTpe) {
            ok = gOrigShareActionWithOperationTpe(manager,
                                                  @selector(shareActionWithOperationTpe:),
                                                  officeType);
        } else {
            CSFS_LOG(@"no orig IMP available, cannot re-dispatch");
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"re-dispatch to original pipeline threw: %@", e.reason);
        ok = NO;
    }

    if (!ok) {
        // 原链路拒绝了（例如配额/VIP 拦截），撤回标记，避免拖累后续分享
        CSFSExportState.shared.pendingSaveToFiles = NO;
        CSFSHideBusy(nil);
        CSFS_LOG(@"original pipeline declined, pending cancelled");
    }
}

// 面板条目去重：避免同一数组被多次追加
static BOOL CSFSArrayAlreadyHasSaveItem(NSArray *items) {
    for (id item in items) {
        if (![item respondsToSelector:@selector(identifyId)]) continue;
        @try {
            if ([(id<CSFSSheetItem>)item identifyId] == kCSFSSaveToFilesId) return YES;
        } @catch (NSException *e) {
            continue;
        }
    }
    return NO;
}

// 构造一条 CSSheetVerticalItemModel
static id CSFSMakeSaveItem(void) {
    static NSString *const kItemClassName =
        @"_TtC19CSUIComponent_Swift24CSSheetVerticalItemModel";
    Class itemClass = NSClassFromString(kItemClassName);
    if (!itemClass) return nil;

    id item = nil;
    @try {
        item = [[itemClass alloc] init];
    } @catch (NSException *e) {
        return nil;
    }
    if (!item) return nil;

    if ([item respondsToSelector:@selector(setIdentifyId:)]) {
        [(id<CSFSSheetItem>)item setIdentifyId:kCSFSSaveToFilesId];
    } else {
        return nil;  // 关键 setter 缺失，宁可不加也不冒险
    }

    if ([item respondsToSelector:@selector(setTitle:)]) {
        [(id<CSFSSheetItem>)item setTitle:kCSFSSaveToFilesTitle];
    }

    if ([item respondsToSelector:@selector(setIconImage:)]) {
        UIImage *icon = nil;
        if (@available(iOS 13.0, *)) {
            icon = [UIImage systemImageNamed:@"folder"];
        }
        if (!icon) icon = [UIImage imageNamed:@"ic_share_24px"];   // app 内既有资源
        if (!icon) icon = [UIImage imageNamed:@"office_share_pdf"];
        if (icon) [(id<CSFSSheetItem>)item setIconImage:icon];
    }
    return item;
}

// ═══════════════════════════════════════════════════════════════════════
#pragma mark - Hook: -[CSShareManager showShareActivityWithFilePath:completionBlock:]
//  所有 office 导出的最终公共出口。这里判断 pending 标记：
//    - 命中 → 改道 UIDocumentPicker（导出式）
//    - 未命中 → 原样转发给原实现（保持系统分享面板不变）
// ═══════════════════════════════════════════════════════════════════════

static void (*gOrigShowShareActivity)(id, SEL, NSString *, void (^)(void)) = NULL;

static void CSFS_showShareActivityWithFilePath(id self, SEL _cmd,
                                               NSString *filePath,
                                               void (^completionBlock)(void)) {
    @try {
        if (CSFSConsumePending()) {
            CSFS_LOG(@"intercepted exit with path: %@", filePath);
            dispatch_async(dispatch_get_main_queue(), ^{
                @try {
                    CSFSHideBusy(nil);
                    NSURL *u = CSFSCoerceToFileURL(filePath);
                    if (u) {
                        CSFSPresentExportPicker(@[ u ]);
                    } else {
                        CSFSToast(@"文件尚未生成，请稍后重试");
                        CSFS_LOG(@"pending path not usable: %@", filePath);
                    }
                } @catch (NSException *e) {
                    CSFS_LOG(@"redirect threw: %@", e.reason);
                }
                @try {
                    if (completionBlock) completionBlock();
                } @catch (NSException *e) {
                    CSFS_LOG(@"completion block threw: %@", e.reason);
                }
            });
            return;
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"pending check threw: %@", e.reason);
    }

    if (gOrigShowShareActivity) {
        gOrigShowShareActivity(self, _cmd, filePath, completionBlock);
        return;
    }
    if (completionBlock) completionBlock();
}

// ═══════════════════════════════════════════════════════════════════════
#pragma mark - Hook: -[CSShareManager officeFileShareViewData]
// ═══════════════════════════════════════════════════════════════════════

static NSMutableArray *(*gOrigOfficeFileShareViewData)(id, SEL) = NULL;

static NSMutableArray *CSFS_officeFileShareViewData(id self, SEL _cmd) {
    @try {
        // 记下面板展示时的 office 格式，供「保存到文件」选择对应的转换路径
        @try {
            SEL sel = NSSelectorFromString(@"officeFileShareType");
            if ([self respondsToSelector:sel]) {
                IMP imp = [self methodForSelector:sel];
                if (imp) {
                    NSInteger (*fn)(id, SEL) = (NSInteger (*)(id, SEL))imp;
                    gCSFSOfficeShareType = fn(self, sel);
                    CSFS_LOG(@"officeFileShareType = 0x%lx", (long)gCSFSOfficeShareType);
                }
            }
        } @catch (NSException *e) {
            CSFS_LOG(@"read officeFileShareType threw: %@", e.reason);
        }

        id item = CSFSMakeSaveItem();
        if (item) {
            NSMutableArray *result = nil;
            if (gOrigOfficeFileShareViewData) {
                id orig = gOrigOfficeFileShareViewData(self, _cmd);
                // 原实现返回 NSMutableArray；若异常情形下返回不可变数组则复制一份
                if ([orig isKindOfClass:[NSMutableArray class]]) {
                    result = orig;
                } else if ([orig isKindOfClass:[NSArray class]]) {
                    result = [orig mutableCopy];
                }
            }
            if (!result) result = [NSMutableArray array];

            if (!CSFSArrayAlreadyHasSaveItem(result)) {
                [result addObject:item];
                CSFS_LOG(@"appended save-to-files entry, total=%lu", (unsigned long)result.count);
            }
            return result;
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"officeFileShareViewData hook threw: %@", e.reason);
    }
    if (gOrigOfficeFileShareViewData) return gOrigOfficeFileShareViewData(self, _cmd);
    return [NSMutableArray array];
}

// ═══════════════════════════════════════════════════════════════════════
#pragma mark - Hook: -[CSShareManager shareActionWithOperationTpe:(needLog:)]
// ═══════════════════════════════════════════════════════════════════════
//
// 这里有一个必须讲清楚的坑，否则 hook 会打在没人调用的方法上：
//
//   selector                                 IMP 地址        内容
//   -shareActionWithOperationTpe:            0x1018c492c    仅两条指令的 thunk：
//                                                             mov w3,#1
//                                                             b 0x106165680
//   -shareActionWithOperationTpe:needLog:    0x1018c4934    真正的实现体
//                                                             （含 0x64~0x7D 跳转表）
//
// 证据链（全部来自 class_ro_t → baseMethods 的 relative method_t）：
//   0x1018c492c  mov w3,#1 ; b #0x106165680
//   0x106165680  adrp x1,#0x107a1a000 / ldr x1,[x1,#0x478]  → shareActionWithOperationTpe:needLog:
//   0x106165660  adrp x1,#0x107a1a000 / ldr x1,[x1,#0x470]  → shareActionWithOperationTpe:
//   （两个 selref 槽 0x107a1a470 / 0x107a1a478 相邻，证实是同一对重载）
//
// 返回类型与参数也逐个核过（__RODATA,__objc_methtype）：
//   shareActionWithOperationTpe:            types = 'B24@0:8q16'        → BOOL (id,SEL,long)
//   shareActionWithOperationTpe:needLog:    types = 'B28@0:8q16B24'     → BOOL (id,SEL,long,BOOL)
//   其中 'B'=BOOL, '@'=id(隐式 self), ':'=SEL(隐式 _cmd), 'q'=long(NSInteger)
//   实现体第 9 行 `mov x20, x3` 也印证了 x3 = 第 3 个参数 = needLog 的 BOOL。
//
// 结论：只 hook 一参数版本能拦到「面板点击」这一条路（面板回调走 thunk），
// 但会**漏掉所有直接调 :needLog: 的路径**（例如从其它入口发起的分享）。
// 所以两个都 hook，且把 :needLog: 当主拦截点：拦到后自行分发，
// 不再让原实现重复执行一遍埋点/跳转。

// （gOrigShareActionWithOperationTpe / ...NeedLog 两个指针已上移到模块级状态区，
//   原因见那里的注释：C 无 Hoisting，定义必须早于使用点。）

// 抽出公共拦截逻辑，避免两份重复代码在细节上漂移
static BOOL CSFSTryInterceptShareAction(id self, NSInteger operationType) {
    if (operationType != kCSFSSaveToFilesId) return NO;
    @try {
        CSFS_LOG(@"intercepted save-to-files tap, officeType=0x%lx",
                 (long)gCSFSOfficeShareType);
        // 用面板展示时记录的真实 office 格式去驱动转换
        CSFSBeginSaveToFiles(self, gCSFSOfficeShareType);
    } @catch (NSException *e) {
        CSFS_LOG(@"save-to-files dispatch threw: %@", e.reason);
    }
    return YES;
}

static BOOL CSFS_shareActionWithOperationTpe(id self, SEL _cmd, NSInteger operationType) {
    @try {
        if (CSFSTryInterceptShareAction(self, operationType)) return YES;
        if (gOrigShareActionWithOperationTpe) {
            return gOrigShareActionWithOperationTpe(self, _cmd, operationType);
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"shareAction(1-arg) threw: %@", e.reason);
    }
    return NO;
}

static BOOL CSFS_shareActionWithOperationTpeNeedLog(id self, SEL _cmd,
                                                    NSInteger operationType,
                                                    BOOL needLog) {
    @try {
        if (CSFSTryInterceptShareAction(self, operationType)) return YES;
        if (gOrigShareActionWithOperationTpeNeedLog) {
            return gOrigShareActionWithOperationTpeNeedLog(self, _cmd, operationType, needLog);
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"shareAction(2-arg) threw: %@", e.reason);
    }
    return NO;
}

// ═══════════════════════════════════════════════════════════════════════
#pragma mark - Hook: -[CSActivityUtil shareWithActivityItems:subject:result:]
//  兜底增强：系统分享面板若被喂入的是 NSString 路径，规范化为 fileURL，
//  保证系统能注入 UIActivityTypeSaveToFiles。纯增益，失败即原样透传。
// ═══════════════════════════════════════════════════════════════════════

static void (*gOrigShareWithActivityItems)(id, SEL, id, id, id) = NULL;

static id CSFSNormalizedItems(id items) {
    if (![items isKindOfClass:[NSArray class]]) return items;
    NSArray *arr = (NSArray *)items;
    NSMutableArray *out = [NSMutableArray arrayWithCapacity:arr.count];
    BOOL changed = NO;
    NSUInteger converted = 0;
    for (id obj in arr) {
        NSURL *u = nil;
        // 仅处理 NSString 且确实是已存在文件的情形，其余原样保留
        if ([obj isKindOfClass:[NSString class]]) {
            u = CSFSCoerceToFileURL(obj);
        }
        if (u) {
            [out addObject:u];
            changed = YES;
            converted++;
        } else {
            [out addObject:obj];
        }
    }
    if (!changed) return items;
    CSFS_LOG(@"normalized %lu item(s) to fileURL in activity items",
             (unsigned long)converted);
    return out;
}

static void CSFS_shareWithActivityItems(id self, SEL _cmd, id items, id subject, id result) {
    id normalized = items;
    @try {
        normalized = CSFSNormalizedItems(items);
    } @catch (NSException *e) {
        CSFS_LOG(@"normalize threw: %@", e.reason);
        normalized = items;
    }
    if (gOrigShareWithActivityItems) {
        gOrigShareWithActivityItems(self, _cmd, normalized, subject, result);
    }
}

// ═══════════════════════════════════════════════════════════════════════
#pragma mark - 安装
// ═══════════════════════════════════════════════════════════════════════

static BOOL CSFSHookInstance(Class cls, SEL sel, IMP newImp, IMP *outOrig) {
    if (!cls || !sel) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        CSFS_LOG(@"method not found: -[%@ %@]", NSStringFromClass(cls), NSStringFromSelector(sel));
        return NO;
    }
    // 保存原始 IMP 后才替换；替换后若 orig 为空则下次调用会跳过而非调 NULL
    IMP orig = method_setImplementation(m, newImp);
    if (outOrig) *outOrig = orig;
    if (!orig) {
        CSFS_LOG(@"WARNING: original IMP is NULL for -[%@ %@]",
                 NSStringFromClass(cls), NSStringFromSelector(sel));
        return NO;
    }
    CSFS_LOG(@"hooked -[%@ %@] orig=%p new=%p",
             NSStringFromClass(cls), NSStringFromSelector(sel), orig, newImp);
    return YES;
}

static void CSFSInstall(void) {
    if (gCSFSInstalled) return;

    @try {
        Class shareManager = NSClassFromString(@"CSShareManager");
        Class activityUtil = NSClassFromString(@"CSActivityUtil");

        if (!shareManager && !activityUtil) {
            CSFS_LOG(@"target classes not registered yet, will retry");
            return;
        }

        if (shareManager) {
            CSFSHookInstance(shareManager,
                             @selector(officeFileShareViewData),
                             (IMP)CSFS_officeFileShareViewData,
                             (IMP *)&gOrigOfficeFileShareViewData);

            CSFSHookInstance(shareManager,
                             NSSelectorFromString(@"shareActionWithOperationTpe:"),
                             (IMP)CSFS_shareActionWithOperationTpe,
                             (IMP *)&gOrigShareActionWithOperationTpe);

            // 主拦截点：真正的实现体挂在这个重载上（见上方证据链）。
            // 装不上不影响功能（一参数版本那个 thunk 仍会走到我们的 hook），
            // 只是会漏掉直接调 :needLog: 的入口，所以失败仅告警不中断。
            if (!CSFSHookInstance(shareManager,
                                  NSSelectorFromString(@"shareActionWithOperationTpe:needLog:"),
                                  (IMP)CSFS_shareActionWithOperationTpeNeedLog,
                                  (IMP *)&gOrigShareActionWithOperationTpeNeedLog)) {
                CSFS_LOG(@"WARN: 未能 hook shareActionWithOperationTpe:needLog:，"
                         @"仅一参数入口生效");
            }

            // 关键：最终出口改道
            CSFSHookInstance(shareManager,
                             NSSelectorFromString(@"showShareActivityWithFilePath:completionBlock:"),
                             (IMP)CSFS_showShareActivityWithFilePath,
                             (IMP *)&gOrigShowShareActivity);
        }

        if (activityUtil) {
            CSFSHookInstance(activityUtil,
                             NSSelectorFromString(@"shareWithActivityItems:subject:result:"),
                             (IMP)CSFS_shareWithActivityItems,
                             (IMP *)&gOrigShareWithActivityItems);
        }

        gCSFSInstalled = (gOrigOfficeFileShareViewData != NULL);
        CSFS_LOG(@"install finished, installed=%d", (int)gCSFSInstalled);
    } @catch (NSException *e) {
        CSFS_LOG(@"install threw: %@", e.reason);
    }
}

static void CSFSRetryInstall(void) {
    if (gCSFSInstalled) return;
    CSFSInstall();
    if (!gCSFSInstalled) {
        // 再给一次机会：下一轮 runloop
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            CSFSInstall();
        });
    }
}

__attribute__((constructor))
static void CSFSEntry(void) {
    @try {
        CSFS_LOG(@"loaded, starting install");
        CSFSInstall();
        if (!gCSFSInstalled) {
            // 类尚未注册（理论上不会，但防御）：等 App 启动完成再试
            [[NSNotificationCenter defaultCenter]
                addObserverForName:UIApplicationDidFinishLaunchingNotification
                            object:nil
                             queue:[NSOperationQueue mainQueue]
                        usingBlock:^(NSNotification *note) {
                CSFSRetryInstall();
            }];
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"constructor threw: %@", e.reason);
    }
}