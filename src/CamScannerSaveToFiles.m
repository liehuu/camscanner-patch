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
#import <objc/message.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

// ── 日志 ───────────────────────────────────────────────────────────────
//
// ⚠ 为什么不再只用 NSLog：
//   前三版都卡在「装上了但看不到条目」，而 NSLog 只能在 Xcode / 控制台看，
//   手机上根本拿不到。结果只能靠猜，越猜越偏。
//   所以这里同时写一份**文件日志**到 App 的 Documents 下，
//   用户在「文件」App → 我的 iPhone → 扫描全能王（或 LC 里的这个 app）
//   就能直接看到并导出这个 txt，一眼确定卡在哪一步。
//
// 崩溃安全：日志写入整体 try/catch，且只在专用串行队列上做，绝不阻塞主线程。
// 宏写成单条语句（不用 do{...}while(0) 包），
// 一是避免和自研 lint 的括号配平逻辑打架，二是这里本来就只有一条语句。
static void CSFSLogToFile(NSString *msg);

#define CSFS_LOG(fmt, ...) \
    CSFSLogToFile([NSString stringWithFormat:@"[CSFS] " fmt, ##__VA_ARGS__])

// ── 同步崩溃取证日志（v16 新增）────────────────────────────────────────
//
// CSFS(11).log 的教训：日志停在「v12 json head」之后就没了，看起来像崩在
// JSON 解析那一段。但那只说明**异步队列里还没写盘的条目跟着进程一起没了**，
// 崩溃点其实在这之后更远的地方。
//
// CSFS_LOG 走 dispatch_async + NSFileHandle，进程一崩，队列里积压的条目
// 全部丢失 —— 用它来找崩溃点等于蒙眼打靶。所以崩溃取证必须用**同步 write(2)**：
//   · 不开缓冲、不排队、不依赖 Foundation 对象生命周期
//   · 直接 write(2) 到已打开的 fd，系统调用返回即已进入内核页缓存
//   · 即使在任意线程崩溃，此前每一次 CHECKPOINT 都必然落盘
//
// 用法：只在可能崩溃的**关键步骤之间**埋点（不要在热路径里刷屏）。
// 每条都带 [CRASH-TRACE] 前缀，日志里一眼可辨。
static void CSFSCrashTrace(const char *tag);

// ── 面板条目的 identifyId。原 app 使用 0x64~0x7D / 0xD3 / 0xDE / 0xDF / 0xF0 / 0xF2 / 0x43，
//    0xE5 未被占用（见 -[CSShareManager shareActionWithOperationTpe:needLog:] 的分派表）。
static const NSInteger kCSFSSaveToFilesId = 0xE5;
static NSString *const kCSFSSaveToFilesTitle = @"保存到文件";

static BOOL gCSFSInstalled = NO;

// ── 文件日志实现 ───────────────────────────────────────────────────────
//
// 落盘位置（按优先级，第一个可写就用）：
//   1) <Documents>/CSFS.log
//   2) <Library/Caches>/CSFS.log
//   3) $TMPDIR/CSFS.log
// 都是沙盒内路径，不需要额外权限，用户可通过「文件」App 取到 Documents 下的那份。
//
// 三条硬约束（对应「崩宿主」自查表第 4 条）：
//   1. 只在专用串行队列写，绝不在主线程做 IO
//   2. 单条日志 > 4KB 就截断，防止异常日志撑爆磁盘
//   3. 整体 try/catch，日志失败也绝不影响业务

// 路径解析**不单独成函数**，直接内联在 CSFSLogToFile 的 async block 里。
//
// 原因（踩过一次）：项目 lint 判定「IO 是否在主线程」是按函数体看的 ——
// 若 createFileAtPath: 落在独立函数 CSFSLogPath 里，即使它的调用点确实在
// dispatch_async 的 block 内，检查器也看不到这层跨函数关系，会直接判
// 「会卡主线程、watchdog 杀进程」。内联之后语义完全一样（本来也就只被
// 日志写盘这一处调用），但检查器能正确证明它跑在后台。

// 同步崩溃取证实现。
//
// 刻意**不用** NSString / NSFileHandle / NSFileManager：
// 崩溃往往发生在对象状态已经损坏的时候，此时再走 Foundation 等于在雷区里跑步。
// 这里只用 C 运行时 + POSIX：
//   · 路径由 CSFSLogToFile 首次解析后存成 C 字符串（gCSFSTracePath）
//   · 首次调用时 open(2) 一个 fd，之后一直是 append 模式
//   · 每次 write(2) 一条，同步返回
//
// 线程安全：write(2) 对同一 fd 的 O_APPEND 在写入量 < PIPE_BUF(512) 时是原子的，
// 本次每行上限 256 字节，不会与其他线程的日志交错成半行。
static int gCSFSTraceFd = -1;
static char gCSFSTracePath[1024];

static void CSFSCrashTracePath(const char *path) {
    if (!path || !path[0]) return;
    size_t n = strlen(path);
    if (n >= sizeof(gCSFSTracePath)) n = sizeof(gCSFSTracePath) - 1;
    memcpy(gCSFSTracePath, path, n);
    gCSFSTracePath[n] = '\0';
    // 复用同一个文件：与 CSFS_LOG 写同一份 CSFS.log，用户在「文件」App 里
    // 只需要取一个文件，不用满沙盒找第二个日志。
    //
    // 刻意在这里就把 fd 打开好，而不是留给 CSFSCrashTrace 惰性初始化：
    // 本函数由 CSFSLogToFile 的 dispatch_once 调用，天然只执行一次，
    // 不存在并发重复 open 的竞态。这样 CSFSCrashTrace 退化成
    // 「判断 fd + write」两步，崩溃现场执行路径越短越安全。
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) gCSFSTraceFd = fd;
}

static void CSFSCrashTrace(const char *tag) {
    if (!tag) return;
    // 只读不初始化：fd 由 CSFSCrashTracePath 在 dispatch_once 里备好。
    // 若尚未就绪（极早期调用），静默跳过 —— 取证失败绝不能影响业务。
    int wfd = gCSFSTraceFd;
    if (wfd < 0) return;
    // 缓冲必须 < PIPE_BUF(512)：多线程同时 write(2) 同一 fd 时，
    // 小于 PIPE_BUF 的写入是原子的，不会互相撕裂成半行。
    // 本项目的 lint R8b 会把 ≥512 判为失败（第一次就抓到 512 这个临界值）。
    char buf[256];
    int n = snprintf(buf, sizeof(buf), "[CRASH-TRACE] %s\n", tag);
    if (n <= 0) return;
    // snprintf 返回「本应写入的长度」，超长时 n 可能 > sizeof(buf)，
    // 必须夹回实际可用长度，否则 write 会读越界（这是常见的一行崩溃）。
    if ((size_t)n >= sizeof(buf)) n = (int)sizeof(buf) - 1;
    // 忽略返回值：日志失败绝不影响业务，更不能因为日志再崩一次
    (void)write(wfd, buf, (size_t)n);
}

static void CSFSLogToFile(NSString *msg) {
    if (msg.length == 0) return;
    // 截断，避免超长日志
    if (msg.length > 4000) msg = [[msg substringToIndex:4000] stringByAppendingString:@"…(truncated)"];
    // ⚠ 这里必须**直接**写 dispatch_get_global_queue，不能封进 CSFSLogQueue()。
    //   项目 lint 的 R3b 是靠「IO 函数体内出现该符号 + IO 位于 dispatch_async
    //   的 block 内」来判定「没在主线程做 IO」的。封装一层它就不认了，
    //   会把这条日志判成「会卡主线程、watchdog 杀进程」。
    //   dispatch_get_global_queue 本身只是取队列句柄，开销可忽略。
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @try {
            // ── 路径解析（内联，详见上方说明）──────────────────────────
            // 落盘位置按优先级：Documents → Caches → TMPDIR，
            // 第一个可写的用。Documents 那份用户能在「文件」App 里直接取到。
            static NSString *cachedPath = nil;
            static dispatch_once_t oncePath;
            dispatch_once(&oncePath, ^{
                @try {
                    NSFileManager *fm = [NSFileManager defaultManager];
                    NSArray *dirs = @[
                        [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject],
                        [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject],
                        NSTemporaryDirectory(),
                    ];
                    for (NSString *d in dirs) {
                        if (d.length == 0) continue;
                        NSString *p = [d stringByAppendingPathComponent:@"CSFS.log"];
                        // 直接尝试创建；已存在时 createFileAtPath: 返回 NO 也无妨，
                        // 下面统一用 fileHandleForWritingAtPath: 判断是否真能写。
                        [fm createFileAtPath:p contents:[NSData data] attributes:nil];
                        if ([fm fileExistsAtPath:p]) {
                            cachedPath = p;
                            // 让同步崩溃取证也落到同一份 CSFS.log（用户只需取一个文件）。
                            // ⚠ 必须放在 dispatch_once 内部：本 block 执行在并发的
                            // global 队列上，放到 block 外面会让多个线程同时进来
                            // 各自 open 一次，造成 fd 泄漏。
                            CSFSCrashTracePath(p.fileSystemRepresentation);
                            break;
                        }
                    }
                } @catch (NSException *e) {
                    NSLog(@"[CSFS] log path resolve threw: %@", e.reason);
                }
            });
            NSString *p = cachedPath;
            if (p.length == 0) return;
            static NSDateFormatter *df = nil;
            static dispatch_once_t onceF;
            dispatch_once(&onceF, ^{
                df = [[NSDateFormatter alloc] init];
                df.dateFormat = @"HH:mm:ss.SSS";
            });
            NSString *line = [NSString stringWithFormat:@"%@ %@\n", [df stringFromDate:[NSDate date]], msg];
            NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
            if (!data) return;

            // global 队列是并发的，追加必须串行化，否则多行会交错成乱码。
            // 用静态锁而不是串行队列：锁的作用域只覆盖「写文件」这一小段，
            // 比给每条日志都排一次队更轻，也不会引入队列嵌套风险。
            static NSLock *logLock = nil;
            static dispatch_once_t onceLock;
            dispatch_once(&onceLock, ^{ logLock = [[NSLock alloc] init]; });
            [logLock lock];
            @try {
                NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p];
                // 用两层 @try/@catch 代替 @try/@finally：
                // 项目 lint 要求 @try 与 @catch 严格一一对应，
                // 「无论写成功与否都要 closeFile」用嵌套 catch 也能表达完整。
                @try {
                    @try {
                        [fh seekToEndOfFile];
                        [fh writeData:data];
                    } @catch (NSException *e) {
                        NSLog(@"[CSFS] log write inner threw: %@", e.reason);
                    }
                    [fh closeFile];
                } @catch (NSException *e) {
                    NSLog(@"[CSFS] log close threw: %@", e.reason);
                }
            } @catch (NSException *e) {
                NSLog(@"[CSFS] log write outer threw: %@", e.reason);
            } @finally {
                [logLock unlock];
            }
        } @catch (NSException *e) {
            NSLog(@"[CSFS] log write threw: %@", e.reason);
        }
    });
}

// 「强制网络可达」窗口标志。
// 为什么需要它：CSConvertWorkTool 的 Word 转换第一步就做 Reachability 检查，
// NotReachable 时直接弹「转换失败」，连试都不试（证据链见下方 reachability hook 注释）。
// 只在我们主动驱动转换的那几秒置位，退出即复位，绝不长期改变宿主网络判断。
static BOOL gCSFSForceReachable = NO;

// ───────────────────────────────────────────────────────────────────────
//  前向声明（必须留在文件最顶部）
// ───────────────────────────────────────────────────────────────────────
//  C 没有 Hoisting：定义晚于使用就是编译错误（use of undeclared identifier）。
//  本文件里「面板条目构造」这一组函数被上下游多处调用，且调用点分散在
//  文件前三分之一，被调函数却在中后段（因为它们依赖协议与工具函数）。
//  以前是靠物理搬动整个函数体解决的，但每搬一次就可能漏掉一个依赖，
//  上一次就是这样让 CI 首编失败。现在统一在这里声明，函数体位置随意。
static NSString *CSFSLocalized(NSString *key, NSString *fallback);
static NSString *CSFSItemTitle(id it);
static long long CSFSItemOpType(id it);
static BOOL CSFSArrayContainsTitle(NSArray *arr, NSString *title);
static Class CSFSItemClass(NSString *fullName);
static id CSFSBuildItem(Class cls, NSString *title, NSInteger identifyId, NSString *iconName);

// 两个已实证的 Swift 条目模型类名。
// 元数据里的长度前缀分别是 24 / 26 —— 这正是 Swift 混淆类名的固定格式
// _TtC<模块名长>模块名<类名长>类名：
//   _TtC19CSUIComponent_Swift24CSSheetVerticalItemModel    纵向（以 PDF 分享 那一列）
//   _TtC19CSUIComponent_Swift26CSSheetHorizontalItemModel  横向（邮件 / 更多 那一排）
// 它们不在 ObjC 类列表里（Swift 类不进 __objc_classlist），只能 NSClassFromString 取。
static NSString *const kCSFSVerticalItemClass =
    @"_TtC19CSUIComponent_Swift24CSSheetVerticalItemModel";
static NSString *const kCSFSHorizontalItemClass =
    @"_TtC19CSUIComponent_Swift26CSSheetHorizontalItemModel";

// ═══════════════════════════════════════════════════════════════════════
#pragma mark - 私有接口声明（签名均来自反汇编实证）
// ═══════════════════════════════════════════════════════════════════════

// 面板条目对象的协议 —— 全部来自 ISBlockDiversifiedActionSheetView 的反汇编实证，
// 不是猜的，这一点极其重要：
//
//   -tableView:cellForRowAtIndexPath: (0x1020208ac) 依次向 model 取：
//       section / objectAtIndexedSubscript: / row / selectedIcon /
//       originalTintColor / rightIcon / selectedTintColor
//   -tableView:didSelectRowAtIndexPath: (0x102021218) 依次向 model 取：
//       actionSheetOperationType / actionSheetCellSeletedType
//   -clickTableViewCellWithIndexPath: (0x102021950) 取：
//       titleString / titleAttributedString / actionSheetOperationType
//       —— 并且把 titleString 作为回调参数抛给业务层
//   -collectionView:didSelectItemAtIndexPath: (0x102020578) 取：
//       titleString / selectedSegmentIndex
//
// 所以：条目必须有 titleString 与 actionSheetOperationType 两个属性。
// 上一版写的 title / identifyId 是**完全错的属性名** ——
// KVC setValue:forKey: 在属性不存在时会抛 NSUndefinedKeyException，
// 被 @catch 吃掉后 item 为 nil，于是「加了但看不见、点了也没反应」。
// 这正是用户第三次反馈「没看到保存到文件」的根因。
@protocol CSFSSheetItem <NSObject>
- (NSString *)titleString;
- (void)setTitleString:(NSString *)titleString;
- (NSInteger)actionSheetOperationType;
- (void)setActionSheetOperationType:(NSInteger)type;
- (UIImage *)selectedIcon;
- (void)setSelectedIcon:(UIImage *)icon;
- (UIImage *)rightIcon;
- (void)setRightIcon:(UIImage *)icon;
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

// SSZipArchive 的最小可用面（v16）
//
// ⚠ 为什么必须写成协议声明，而不是继续用 methodForSelector: + IMP 直调：
//   v15 闪退的真正根因就在这里。原写法是
//       id zip = ((id(*)(id,SEL,NSString*))methodImp)([[zipCls alloc] init], initSel, outPath);
//   `[[zipCls alloc] init]` 是 +1 的临时结果，只作为实参出现，没有被任何
//   变量（更没有被 __strong 变量）持有。ARC 在语句结束时就把它 release 掉，
//   而 initWithPath: 明明返回的还是同一个对象 —— 于是 zip 立刻变成悬空指针，
//   下一行 [zip respondsToSelector:] 就是 EXC_BAD_ACCESS。
//   这是确定性崩溃，不是偶发，所以「重试一次」这类兜底永远不会成功。
//
//   改成协议 + 正常消息发送后，objc 的 init family 语义能被编译器识别，
//   ARC 会正确延长生命周期；同时省掉所有手写 IMP 强转的签名错位风险。
@protocol CSFSZipArchive <NSObject>
- (id)initWithPath:(NSString *)path;
- (BOOL)open;
- (void)close;
- (void)writeData:(NSData *)data
         filename:(NSString *)filename
     withPassword:(NSString *)password;
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
            // 顺手复位强制可达，避免窗口残留影响后续正常分享
            gCSFSForceReachable = NO;
            // v10：转换链若中途死掉（如原生前置失败弹 alert），
            // 出口永远不会来，必须把「正在生成文件」的 busy 收掉
            CSFSHideBusy(nil);
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

// 面板条目去重：避免同一数组被多次追加。
// 判据用「标题」，因为 actionSheetOperationType / identifyId 这类内部枚举
// 会随版本漂移，而标题是我们自己写进去的常量。
static BOOL CSFSArrayAlreadyHasSaveItem(NSArray *items) {
    return CSFSArrayContainsTitle(items, kCSFSSaveToFilesTitle)
        || CSFSArrayContainsTitle(items, CSFSLocalized(@"cs_649_object_10", kCSFSSaveToFilesTitle));
}

// 构造一条 CSSheetVerticalItemModel。
// 直接复用 CSFSBuildItem，保证属性名只有一处定义（避免又写出 title/identifyId 这种错名）。
static id CSFSMakeSaveItem(void) {
    Class itemClass = CSFSItemClass(kCSFSVerticalItemClass);
    if (!itemClass) return nil;
    NSString *title = CSFSLocalized(@"cs_649_object_10", kCSFSSaveToFilesTitle);
    return CSFSBuildItem(itemClass, title, kCSFSSaveToFilesId, nil);
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
            // 转换已完成，立刻关掉「强制可达」窗口，不留下任何残留
            gCSFSForceReachable = NO;
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

        // ⚠⚠ 这里是整个补丁最关键的一处，务必看清：
        //
        //   officeFileShareViewData 的返回数组**不走任何 dataSource setter**。
        //   调用方是：
        //     CSShareManager -showOfficeShareView (0x101888498)
        //        → officeFileShareViewData            (0x101888534)
        //        → CSSheetUtil showSingleSheetWithHeadConfig:dataList:resultCallBack:cancelCallBack:
        //                                             (0x101888590)
        //   即数组是**直接**作为参数交给弹出面板的。
        //
        //   实证反证：setVerticallyListDataSource: 全 App 只有 2 处调用
        //   （都在 ISBlockDiversifiedActionSheetView 的某个 init 里），
        //   setHorizontallyDataSource: 只有 3 处，没有一处来自 CSSheetUtil。
        //   → 所以那两个 setter hook 对「导出文档」这个面板 **100% 不生效**，
        //     别指望它们。唯一有效挂点就是本方法（officeFileShareViewData）。
        //
        //   ⇒ 因此本条 hook 必须做到：只要原数组非空，就一定能多出一格。
        id orig = nil;
        if (gOrigOfficeFileShareViewData) orig = gOrigOfficeFileShareViewData(self, _cmd);

        NSMutableArray *result = nil;
        if ([orig isKindOfClass:[NSMutableArray class]]) {
            result = orig;
        } else if ([orig isKindOfClass:[NSArray class]]) {
            result = [orig mutableCopy];
        }
        if (!result) result = [NSMutableArray array];

        if (!CSFSArrayAlreadyHasSaveItem(result)) {
            id item = CSFSMakeSaveItem();
            if (item) {
                [result addObject:item];
                CSFS_LOG(@"appended save-to-files entry, total=%lu", (unsigned long)result.count);
            } else {
                CSFS_LOG(@"ERROR: cannot build item — 面板不会出现新条目。"
                         @"看上面 'IMP set' / 'KVC set' 日志定位是哪个 setter 失败");
            }
        }
        return result;
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
#pragma mark - Hook: 修掉「转换失败」的网络误判
// ═══════════════════════════════════════════════════════════════════════
//
//  用户反馈：「点击更多会提示转换失败」。
//
//  反汇编 CSConvertWorkTool
//  -convertWordWithOcrReturnString:imagesName:fromViewController:wordTitle:isFree:type:completeBlock:
//  （0x101755f10）得到失败根因，证据链如下：
//
//    0x101755f8c  adrp x8, #0x107a65000
//    0x101755f90  ldr  x0, [x8, #0xc8]      ; x0 = [Reachability class]（classref 实测）
//    0x101755f94  bl   0x1060731a0          ; +[Reachability reachabilityForInternetConnection]
//    0x101755f9c  ...
//    0x101755fa4  bl   0x105f4e040          ; -[Reachability currentReachabilityStatus]
//    0x101755fb4  cbz  x20, #0x101756100    ; 状态 == 0 (NotReachable) → 直接跳失败分支
//
//    失败分支 0x101756100 做的事就是：取 mainBundle → localizedStringForKey:
//    → 组装 UIAlert，文案本地化 key 为 c_sign_msg_account_registered_tip，
//    兜底英文 'Unable to proceed, please reconnect to network and try again.'
//
//  也就是说：**只要 Reachability 认为网络不可达，Word 转换连试都不试就失败**。
//  在越狱/LiveContainer 等非标准运行环境下 SCNetworkReachability 误判极常见
//  （沙箱限制、VPN/代理、首次冷启动），于是用户明明能上网却被拦下。
//
//  修法：把 currentReachabilityStatus 的返回值在「调用方是转换工具链」时
//  纠正为 Reachable。不做全局改（会影响 app 其它网络逻辑），
//  只在我们自己驱动转换时置位一个标志，转换结束后立刻复位。

// Reachability 的枚举值（iOS 常见实现）：
//   NotReachable = 0, ReachableViaWWAN = 1, ReachableViaWiFi = 2
static const NSInteger kCSFSReachableViaWiFi = 2;

// gCSFSForceReachable 已前移到文件头部全局区（CSFSArmPending 也要复位它）

static NSInteger (*gOrigReachabilityStatus)(id, SEL) = NULL;

static NSInteger CSFS_currentReachabilityStatus(id self, SEL _cmd) {
    NSInteger real = 0;
    if (gOrigReachabilityStatus) {
        @try { real = gOrigReachabilityStatus(self, _cmd); }
        @catch (NSException *e) { real = 0; }
    }
    if (gCSFSForceReachable && real == 0) {
        // 只在「我们主动驱动转换」这个窗口内纠正，窗口外完全保持原行为
        CSFS_LOG(@"reachability corrected: %ld -> WiFi (forced)", (long)real);
        return kCSFSReachableViaWiFi;
    }
    return real;
}

// ═══════════════════════════════════════════════════════════════════════
#pragma mark - Hook: OCR 结果页导出面板（用户实际走的那条路）
// ═══════════════════════════════════════════════════════════════════════
//
//  为什么必须加这一组 hook（2026-10-26 真机反馈推翻了原定位）：
//
//  原补丁只 hook 了 CSShareManager -officeFileShareViewData，但用户「图片转
//  Word → 分享」走的**根本不是那个面板**。真机截图显示的面板是：
//
//      文件卡片（W 图标 + 文件名 + 「Word 文稿」）
//      ────────────────────────────────
//      [邮件]            [更多]
//      ────────────────────────────────
//       更多分享方式
//      [以 PDF 分享]
//
//  这个面板由 ISOcrResultExportSheetLikeView 绘制，由
//  CSOcrResultsBottomExportPresenter 提供数据与回调：
//
//    -clickExportAction                                   0x10226a544
//      └─ -actionSheetShareTextAndFileWithFileWay:         0x10226a65c
//           ├─ fileWay==3 → -initOcrResultsEmailExportWith… 0x105fca700
//           └─ 其它      → -initOcrResultsExportWith…       0x105fca720
//                └─ 回调 → -actionSheetClickItemAndShareWith
//                            FileWay:withItemTitle:withAllPage:  0x10226aab8
//                     ├─ "…_message"     (短信)
//                     ├─ "…_share_menu_more" (更多) → 按 exportFileType 再分
//                     │     ├─ "cs_516_share_as_word" → -shareWordFileWith…
//                     │     └─ "cs_516_share_as_txt"  → -shareTxtFileWith…
//                     └─ 其它
//
//  面板父类 ISBlockDiversifiedActionSheetView 暴露了两个数据源 setter，
//  这正是「往面板里加一格」的官方接口：
//      -setHorizontallyDataSource:      横向那一排（截图里的 邮件 / 更多）   0x1020221c4
//      -setVerticallyListDataSource:    纵向列表（截图里的 以 PDF 分享）     0x1020221e8
//  ⚠ 纵向那个真实名字带 "List"！写成 -setVerticallyDataSource: 是 method not found，
//    hook 装不上，落点直接消失 —— 已按 __objc_methname 与 init 调用点双重取证修正。
//
//  这两个 setter 的调用点都在父类 init
//  -initDiversifiedActionSheetWithTitle:headView:needCancelItem:selectedCellIndexPaths:
//   horizontallyListTitle:horizontallyListDataSource:verticallyListDataSource:
//   cancelBlock:clikCellBlock:clikCellHiddenViewBlock:
//  体内（0x10201e078 横向 / 0x10201dfec+0x10201e030 纵向）。
//  也就是说：子类 init 把数组交给父类 init，父类 init 再写进属性。
//  我们 hook 的正是这个写入点，所以在面板 show 之前就已完成追加。
//
//  用户要求：「在邮件旁边加一个保存到文件 app，或者在以 PDF 分享下方加一个」。
//  两处都加，各按各自的数组模型构造。
//
//  ⚠ 条目模型是 Swift 类（两个都已在 __cstring 里实证到，元数据里的长度前缀
//     分别是 24 / 26 —— 这正是 Swift 混淆类名的固定格式 _TtC<模块长>模块名<类名长>类名）
//     _TtC19CSUIComponent_Swift24CSSheetVerticalItemModel    纵向（以 PDF 分享 那一列）
//     _TtC19CSUIComponent_Swift26CSSheetHorizontalItemModel  横向（邮件 / 更多 那一排）
//  它们不在 ObjC 类列表里（Swift 类不进 __objc_classlist），只能 NSClassFromString 取。
//  取不到就整体降级，绝不影响面板正常展示。
//
//  ⚠⚠ setter 名字差一个词就会祭掉整个落点（本文件曾经踩过）：
//      真实名字  -setVerticallyListDataSource:   （0x1020221e8）
//      错误写法  -setVerticallyDataSource:
//      取证方式：查 __objc_methname 只有带 List 的那个；再查
//      ISBlockDiversifiedActionSheetView -initDiversifiedActionSheetWithTitle:…
//      体内 0x10201dfec / 0x10201e030 两处 `bl 0x1061556e0`
//      （0x1061556e0 = __objc_stubs 里 setVerticallyListDataSource: 的跳板）。
//      附带教训：统计 selector 引用数不能只扫 adrp+ldr，现代 clang 走
//      __objc_stubs 跳板，方法体里是 `bl <stub>`，直接扫 adrp+ldr 会得到
//      「0 处引用」的假结论 —— 我据此差点又改错方向。
//
//  两个类名常量已上移到文件头部（前段函数也要用，C 无 Hoisting）。

// 探测一个条目对象上实际有哪些可用 setter。
// 它到底是 CSSheetVerticalItemModel 还是别的兄弟类，靠这里实测决定，
// 不靠猜 —— 猜错 setter 就是 unrecognized selector，直接打崩宿主。
static void CSFSDumpItemSetters(id item, NSString *tag) {
    if (!item) return;
    @try {
        NSMutableString *s = [NSMutableString string];
        unsigned int n = 0;
        Method *ms = class_copyMethodList(object_getClass(item), &n);
        if (ms) free(ms);
        // 实例方法列表里有意义的 setter
        ms = class_copyMethodList([item class], &n);
        for (unsigned int i = 0; i < n; i++) {
            const char *nm = sel_getName(method_getName(ms[i]));
            if (nm && strncmp(nm, "set", 3) == 0) {
                [s appendFormat:@"%s ", nm];
            }
        }
        if (ms) free(ms);
        CSFS_LOG(@"[%@] class=%@ setters={ %@}", tag,
                 NSStringFromClass([item class]), s);
    } @catch (NSException *e) {
        CSFS_LOG(@"[%@] dump setters threw: %@", tag, e.reason);
    }
}

// 把一个 NSArray 里每个元素的真实字段打出来。
// 这是判断「面板条目到底长什么样」的唯一可靠手段：
// 之前靠静态分析猜了两轮都猜偏，真机日志一次就能定。
// 字段名按实证取 titleString / actionSheetOperationType，并兼容旧名。
static void CSFSDumpDataSource(NSArray *arr, NSString *tag) {
    if (![arr isKindOfClass:[NSArray class]]) {
        CSFS_LOG(@"[%@] dataSource is not NSArray: %@", tag,
                 NSStringFromClass([arr class]));
        return;
    }
    CSFS_LOG(@"[%@] dataSource count=%lu firstCls=%@", tag,
             (unsigned long)arr.count,
             arr.count ? NSStringFromClass([arr.firstObject class]) : @"(empty)");
    NSUInteger i = 0;
    for (id it in arr) {
        // 二维数组（纵向分组）展开一层再打
        if ([it isKindOfClass:[NSArray class]]) {
            CSFS_LOG(@"[%@] section[%lu] count=%lu", tag,
                     (unsigned long)i, (unsigned long)[(NSArray *)it count]);
            NSUInteger j = 0;
            for (id sub in (NSArray *)it) {
                CSFS_LOG(@"[%@]   [%lu][%lu] cls=%@ opType=0x%llx title=%@",
                         tag, (unsigned long)i, (unsigned long)j,
                         NSStringFromClass([sub class]),
                         (long long)CSFSItemOpType(sub),
                         CSFSItemTitle(sub) ?: @"(nil)");
                j++;
            }
        } else {
            CSFS_LOG(@"[%@] [%lu] cls=%@ opType=0x%llx title=%@",
                     tag, (unsigned long)i, NSStringFromClass([it class]),
                     (long long)CSFSItemOpType(it),
                     CSFSItemTitle(it) ?: @"(nil)");
            if (i == 0) CSFSDumpItemSetters(it, tag);
        }
        i++;
    }
}

// （CSFSItemTitle / CSFSArrayContainsTitle 已前移到「通用工具」区，
//   因为 officeFileShareViewData 那条老路径也要用，避免定义滞后导致引用不到。）

static NSString *CSFSLocalized(NSString *key, NSString *fallback) {
    @try {
        NSString *s = [[NSBundle mainBundle] localizedStringForKey:key value:nil table:nil];
        if (s.length && ![s isEqualToString:key]) return s;
    } @catch (NSException *e) {}
    return fallback ?: key;
}

// 取条目标题。实证名 titleString 优先（cell 渲染与点击回调都读它），兼容 title。
static NSString *CSFSItemTitle(id it) {
    if (!it) return nil;
    for (NSString *k in @[ @"titleString", @"title" ]) {
        @try {
            if ([it respondsToSelector:NSSelectorFromString(k)]) {
                id v = [it valueForKey:k];
                if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] > 0) {
                    return (NSString *)v;
                }
            }
        } @catch (NSException *e) { continue; }
    }
    return nil;
}

// 取条目操作类型。实证名 actionSheetOperationType 优先，兼容 identifyId。
static long long CSFSItemOpType(id it) {
    if (!it) return -1;
    for (NSString *k in @[ @"actionSheetOperationType", @"identifyId" ]) {
        @try {
            if ([it respondsToSelector:NSSelectorFromString(k)]) {
                id v = [it valueForKey:k];
                if ([v respondsToSelector:@selector(longLongValue)]) {
                    return [v longLongValue];
                }
            }
        } @catch (NSException *e) { continue; }
    }
    return -1;
}

// 用「标题」定位条目：这是最稳的判据。
// actionSheetOperationType 是内部枚举、随版本漂移；标题来自本地化表，
// 而且 cell 渲染与点击回调用的都是 titleString（已由反汇编确认）。
static BOOL CSFSArrayContainsTitle(NSArray *arr, NSString *title) {
    if (![arr isKindOfClass:[NSArray class]] || title.length == 0) return NO;
    for (id it in arr) {
        NSString *t = CSFSItemTitle(it);
        if (t && [t isEqualToString:title]) return YES;
    }
    return NO;
}

// 取条目模型类：Swift 类名带 module 前缀，形如
//   _TtC19CSUIComponent_Swift24CSSheetVerticalItemModel
// 直接写死全名，取不到就返回 nil（调用方整体降级）。
static Class CSFSItemClass(NSString *fullName) {
    if (fullName.length == 0) return nil;
    Class c = NSClassFromString(fullName);
    if (c) return c;
    // 退一步：按后缀在已注册类里搜一遍，容忍 Swift module 版本号变化
    NSString *suffix = nil;
    NSRange r = [fullName rangeOfString:@"CSSheet"];
    if (r.location != NSNotFound) suffix = [fullName substringFromIndex:r.location];
    if (suffix.length == 0) return nil;

    // ⚠ 结果必须缓存。objc_getClassList 要遍历上万个类并逐个取名字，
    //   而本函数会在每次面板弹出时被调用（可能还在主线程），
    //   不缓存就是每次都卡一次 —— 属于自查表第 4 条「热路径里的大开销」。
    //   类注册表在进程生命周期内只增不减，缓存永不失效。
    static NSMutableDictionary<NSString *, id> *cache = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ cache = [NSMutableDictionary dictionary]; });
    @synchronized (cache) {
        id hit = cache[suffix];
        if (hit) return (hit == [NSNull null]) ? nil : (Class)hit;
    }

    int count = objc_getClassList(NULL, 0);
    Class found = nil;
    if (count > 0) {
        Class *buf = (Class *)malloc(sizeof(Class) * (size_t)count);
        if (buf) {
            count = objc_getClassList(buf, count);
            for (int i = 0; i < count; i++) {
                const char *nm = class_getName(buf[i]);
                if (!nm) continue;
                // 用 C 字符串直接比后缀，避免为每个类都建一个 NSString（上万个临时对象）
                size_t nl = strlen(nm), sl = (size_t)suffix.length;
                if (nl <= sl) continue;
                if (strcmp(nm + (nl - sl), suffix.UTF8String) == 0) {
                    found = buf[i];
                    break;
                }
            }
            free(buf);
        }
    }
    @synchronized (cache) {
        cache[suffix] = found ? (id)found : (id)[NSNull null];
    }
    return found;
}

// 向条目对象写入标题 / operationType / 图标。
//
// 属性名按「实证优先 + 容错兜底」两级策略：
//   一级（实证确认）：titleString / actionSheetOperationType / selectedIcon / rightIcon
//   二级（容错）：如果 Swift 模型把这些暴露成 title / identifyId / iconImage，
//                 也一并兼容 —— 不同版本可能改过名。
// 一个标题都写不进去时才返回 nil（宁可不加，也不加一个空白格）。
//
// ⚠ KVC 写不存在的 key 会抛 NSUndefinedKeyException，所以每个写入都必须
//   先用 respondsToSelector: 判 setter 是否存在，再逐项 @try。
static BOOL CSFSSetStringIfPossible(id item, NSArray<NSString *> *keys, NSString *value) {
    for (NSString *k in keys) {
        NSString *setter = [NSString stringWithFormat:@"set%@%@:",
                            [[k substringToIndex:1] uppercaseString],
                            [k substringFromIndex:1]];
        SEL sel = NSSelectorFromString(setter);
        if (![item respondsToSelector:sel]) continue;

        // ① 先走 KVC。KVC 会顺手维护 _key / key / isKey 等命名变体，
        //    对 ObjC 类最稳。
        @try { [item setValue:value forKey:k]; return YES; }
        @catch (NSException *e) {
            CSFS_LOG(@"KVC set %@ threw: %@ — fallback to IMP call", k, e.reason);
        }

        // ② KVC 失败就直接按 IMP 调 setter。
        //    为什么需要这一步：Swift 类**默认不实现** NSObject 的
        //    -setValue:forKey: 自动查找（除非显式 @objc dynamic / 继承链里
        //    有 KVC 支持），KVC 会抛 NSUndefinedKeyException 或
        //    NSUnknownKeyException，于是标题写不进去，面板上就是一格空白。
        //    这正是「装上却看不到条目」的成因，且异常被上层 @catch 吞掉后
        //    完全无声 —— 必须给一条不依赖 KVC 的硬写入通道。
        IMP imp = [item methodForSelector:sel];
        if (!imp) continue;
        @try {
            void (*fn)(id, SEL, id) = (void (*)(id, SEL, id))imp;
            fn(item, sel, value);
            CSFS_LOG(@"IMP set %@ OK", k);
            return YES;
        }
        @catch (NSException *e) {
            CSFS_LOG(@"IMP set %@ threw: %@", k, e.reason);
        }
    }
    return NO;
}

static BOOL CSFSSetIntegerIfPossible(id item, NSArray<NSString *> *keys, NSInteger value) {
    for (NSString *k in keys) {
        NSString *setter = [NSString stringWithFormat:@"set%@%@:",
                            [[k substringToIndex:1] uppercaseString],
                            [k substringFromIndex:1]];
        SEL sel = NSSelectorFromString(setter);
        if (![item respondsToSelector:sel]) continue;

        // 同 CSFSSetStringIfPossible：KVC 优先，失败回退到 IMP 直调。
        // ------------------------ !!! 重要 !!! ------------------------
        // 这里**刻意**用 NSInteger 而不是 NSNumber* 调 IMP。
        // 实测（0x101888774）`mov w2, #0x64` —— 原作者是**按整数传参**，
        // 说明 identifyId 是 Swift 的 Int（不是 NSNumber*）。若按 id 传，
        // 会得到一个非法指针，运行时可能直接 EXC_BAD_ACCESS。
        // 所以 IMP 直调这条支路，参数必须按 NSInteger 传。
        @try { [item setValue:@(value) forKey:k]; return YES; }
        @catch (NSException *e) {
            CSFS_LOG(@"KVC set %@ threw: %@ — fallback to IMP(NSInteger)", k, e.reason);
        }

        IMP imp = [item methodForSelector:sel];
        if (!imp) continue;
        @try {
            void (*fn)(id, SEL, NSInteger) = (void (*)(id, SEL, NSInteger))imp;
            fn(item, sel, value);
            CSFS_LOG(@"IMP set %@ OK (=%ld)", k, (long)value);
            return YES;
        }
        @catch (NSException *e) {
            CSFS_LOG(@"IMP set %@ threw: %@", k, e.reason);
        }
    }
    return NO;
}

// 通用「对象参数」写入：KVC 优先，失败回退 IMP 直调。用于图标这类 id 参数。
// 与 String 版的区别只是「不做 NSString 假设」，三者共用同一套回退逻辑。
static BOOL CSFSSetObjectIfPossible(id item, NSArray<NSString *> *keys, id value) {
    for (NSString *k in keys) {
        NSString *setter = [NSString stringWithFormat:@"set%@%@:",
                            [[k substringToIndex:1] uppercaseString],
                            [k substringFromIndex:1]];
        SEL sel = NSSelectorFromString(setter);
        if (![item respondsToSelector:sel]) continue;
        @try { [item setValue:value forKey:k]; return YES; }
        @catch (NSException *e) {
            CSFS_LOG(@"KVC set %@ threw: %@ — fallback to IMP(id)", k, e.reason);
        }
        IMP imp = [item methodForSelector:sel];
        if (!imp) continue;
        @try {
            void (*fn)(id, SEL, id) = (void (*)(id, SEL, id))imp;
            fn(item, sel, value);
            CSFS_LOG(@"IMP set %@ OK", k);
            return YES;
        }
        @catch (NSException *e) {
            CSFS_LOG(@"IMP set %@ threw: %@", k, e.reason);
        }
    }
    return NO;
}

static id CSFSBuildItem(Class cls, NSString *title, NSInteger identifyId, NSString *iconName) {
    if (!cls || title.length == 0) return nil;
    id item = nil;
    @try { item = [[cls alloc] init]; }
    @catch (NSException *e) { CSFS_LOG(@"item alloc threw: %@", e.reason); return nil; }
    if (!item) return nil;

    // ① 标题
    //   ⚠ 最硬的一条实证：`CSShareManager -officeFileShareViewData` (0x1018887c0)
    //     自己就是用 `setTitle:` 往这个 Swift 类里写标题的：
    //       0x101888768  ldr x0, [x27, #0xfb0]  ; cls CSSheetVerticalItemModel
    //       0x10188876c  bl  _objc_alloc_init
    //       0x101888778  bl  sel 'setIdentifyId:'   (w2 = 0x64)
    //       0x1018887c0  bl  sel 'setTitle:'
    //       0x1018887fc  bl  sel 'setIconImage:'
    //     原作者亲自调的 setter 一定可用，所以 setTitle: 必须排第一。
    //   （之前把 titleString 排第一，而 Swift 类默认不走 KVC 的
    //     -setValue:forKey: 自动查找，结果标题写不进去 → 面板上是一格空白。）
    BOOL wroteTitle = CSFSSetStringIfPossible(item,
                        @[ @"title", @"titleString" ], title);

    // ② operationType：identifyId 同样是原作者在用的（w2 = 0x64 = 100）
    BOOL wroteType = CSFSSetIntegerIfPossible(item,
                        @[ @"identifyId", @"actionSheetOperationType" ], identifyId);

    // ③ 标题富文本（clickTableViewCellWithIndexPath: 会读它）
    @try {
        if ([item respondsToSelector:@selector(setTitleAttributedString:)]) {
            [item setValue:[[NSAttributedString alloc] initWithString:title]
                    forKey:@"titleAttributedString"];
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"set titleAttributedString threw: %@", e.reason);
    }

    // ④ 图标：按实证顺序 iconImage（原作者 0x1018887fc 用的就是 setIconImage:）
    //    → selectedIcon / rightIcon（父类 cell 配置读的）
    @try {
        UIImage *icon = nil;
        if (iconName.length) icon = [UIImage imageNamed:iconName];
        if (!icon) {
            if (@available(iOS 13.0, *)) icon = [UIImage systemImageNamed:@"folder"];
        }
        if (icon) {
            CSFSSetObjectIfPossible(item,
                @[ @"iconImage", @"selectedIcon", @"rightIcon" ], icon);
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"set icon threw: %@", e.reason);
    }

    CSFS_LOG(@"built item %@: title=%@(wrote=%d) type=%@(wrote=%d)",
             NSStringFromClass([item class]), title, (int)wroteTitle,
             @(identifyId), (int)wroteType);

    // 标题写不进去 → 面板上就是一格空白，不如不加
    return wroteTitle ? item : nil;
}

// ── 收集「已经生成好的文件」 ──────────────────────────────────────────
//
// 用户走到分享面板时，Word 文件其实**已经生成完毕**了 —— 因为面板顶部
// 那张文件卡片就在展示它（截图里写着「转 Word_扫描全…」「Word 文稿」）。
// 所以最优路径是：把那个文件直接交给 UIDocumentPicker，不要再触发一次
// 转换（再转一次既慢，又正是「更多」报「转换失败」的成因之一）。
//
// 怎么找它：
//   1) 先在 presenter 的上下文里找（ocrDataPresenter / imagesArray 等）；
//   2) 找不到就扫沙盒里最近生成的文档类文件，取最新的若干个。
//      这条兜底在实践中非常有效：用户点分享时，那个 Word 刚写完不到几秒。

static NSArray<NSString *> *CSFSInterestingExtensions(void) {
    return @[ @"docx", @"doc", @"pdf", @"txt", @"xlsx", @"pptx" ];
}

// CSFS_BACKGROUND_SCAN_OK
//   本文件确实包含目录扫描（enumeratorAtPath: / attributesOfItemAtPath:），
//   这会触发「崩宿主」自查表第 4 条（hook 热路径里有文件 IO）。
//   处理方式不是删掉扫描，而是**限定它只能跑在后台队列**：
//   调用点 CSFS_doSaveToFiles 里用
//       dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{ ... })
//   包住整个 CSFSCollectReadyFileURLs，扫完才回主线程弹 picker。
//   工具 lint_dylib.py 的 R3 会校验「标注了本标记」且「确实在 global queue 块内」，
//   两者缺一就仍然拦下 —— 防止后人把它改回主线程。 
static NSArray<NSURL *> *CSFSScanRecentFiles(NSTimeInterval withinSeconds) {
    NSMutableArray<NSURL *> *out = [NSMutableArray array];
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSMutableArray<NSString *> *roots = [NSMutableArray array];
        // 只扫 app 自己的容器，不越界到别的 app
        NSArray *candidates = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES);
        if (candidates.count) [roots addObject:candidates.firstObject];
        [roots addObject:NSTemporaryDirectory()];
        NSString *caches = NSSearchPathForDirectoriesInDomains(
            NSCachesDirectory, NSUserDomainMask, YES).firstObject;
        if (caches) [roots addObject:caches];

        NSDate *threshold = [NSDate dateWithTimeIntervalSinceNow:-withinSeconds];
        NSSet *exts = [NSSet setWithArray:CSFSInterestingExtensions()];

        // ⚠ 排序依据（mtime）必须在遍历时一次性取好。
        //   曾把 attributesOfItemAtPath: 直接写进 sortUsingComparator:，
        //   那是 O(n log n) 次磁盘 IO —— 几百个文件就能把主线程卡住几百毫秒，
        //   严重时触发 watchdog。现在改成「遍历时记录，排序只比内存值」。
        NSMutableArray<NSArray *> *entries = [NSMutableArray array];   // @[url, mtime]

        for (NSString *root in roots) {
            if (root.length == 0) continue;
            NSDirectoryEnumerator *en = [fm enumeratorAtPath:root];
            NSString *rel = nil;
            NSUInteger scanned = 0;
            while ((rel = [en nextObject])) {
                if (++scanned > 20000) break;   // 防御：目录异常大时止血
                NSString *ext = rel.pathExtension.lowercaseString;
                if (![exts containsObject:ext]) continue;
                NSString *full = [root stringByAppendingPathComponent:rel];
                NSDictionary *attr = [fm attributesOfItemAtPath:full error:NULL];
                if (!attr) continue;
                // 统一用 objectForKey: 取属性，不用点语法。
                // 原因同上：NSDictionary 上对 NSFileAttributeKey 的点语法
                // 返回值类型推断不稳定，容易把标量当成对象。
                id typeObj = [attr objectForKey:NSFileType];
                if ([typeObj isEqualToString:NSFileTypeDirectory]) continue;
                NSDate *mod = [attr objectForKey:NSFileModificationDate];
                if (![mod isKindOfClass:[NSDate class]]) continue;
                if (!mod || [mod compare:threshold] == NSOrderedAscending) continue;
                // ⚠ 不要写 `NSNumber *size = attr.fileSize;`
                //   NSDictionary 的 fileSize 返回值在 SDK 里声明为
                //   NSFileAttributeKey（NSString*）→ id，经点语法后类型推断会
                //   落到 unsigned long long，于是被当成标量初始化 NSNumber*，
                //   ARC 下直接报 "implicit conversion of 'unsigned long long'
                //   to 'NSNumber *' is disallowed"。CI 首编就是这么挂的。
                //   显式用 objectForKey: 再判类型，既无歧义也顺带做了防御。
                id sizeObj = [attr objectForKey:NSFileSize];
                if (![sizeObj respondsToSelector:@selector(unsignedLongLongValue)]) continue;
                if ([sizeObj unsignedLongLongValue] < 64) continue;
                [entries addObject:@[ [NSURL fileURLWithPath:full], mod ]];
            }
        }
        [entries sortUsingComparator:^NSComparisonResult(NSArray *a, NSArray *b) {
            return [(NSDate *)b[1] compare:(NSDate *)a[1]];   // 新的在前，纯内存比较
        }];
        for (NSArray *e in entries) [out addObject:(NSURL *)e[0]];
    } @catch (NSException *e) {
        CSFS_LOG(@"scan recent files threw: %@", e.reason);
    }
    return out;
}

// 从 presenter 自身能拿到的数据里挑文件；拿不到就回落最近文件扫描。
static NSArray<NSURL *> *CSFSCollectReadyFileURLs(id presenter) {
    NSMutableArray<NSURL *> *out = [NSMutableArray array];
    @try {
        // ① presenter 自己的 exportFileType 能告诉我们目标格式
        NSString *preferredExt = nil;
        SEL selType = NSSelectorFromString(@"exportFileType");
        if (presenter && [presenter respondsToSelector:selType]) {
            IMP imp = [presenter methodForSelector:selType];
            if (imp) {
                NSInteger (*fn)(id, SEL) = (NSInteger (*)(id, SEL))imp;
                NSInteger t = fn(presenter, selType);
                CSFS_LOG(@"presenter exportFileType=%ld", (long)t);
            }
        }

        // ② 扫最近 10 分钟内生成的文档文件
        NSArray<NSURL *> *recent = CSFSScanRecentFiles(600.0);
        CSFS_LOG(@"recent files within 10min: %lu", (unsigned long)recent.count);
        for (NSURL *u in recent) {
            CSFS_LOG(@"   recent: %@", u.path);
        }

        if (preferredExt.length) {
            for (NSURL *u in recent) {
                if ([u.pathExtension.lowercaseString isEqualToString:preferredExt]) {
                    [out addObject:u];
                }
            }
        }
        if (out.count == 0) {
            // 优先 docx（用户当前场景），再退到任何最近文档
            for (NSURL *u in recent) {
                if ([u.pathExtension.lowercaseString isEqualToString:@"docx"]) {
                    [out addObject:u];
                }
            }
        }
        if (out.count == 0) {
            NSUInteger take = MIN(recent.count, (NSUInteger)3);
            for (NSUInteger i = 0; i < take; i++) [out addObject:recent[i]];
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"collect file urls threw: %@", e.reason);
    }
    return out;
}

// ── 面板数据源 hook ───────────────────────────────────────────────────
//
// 两个 setter 都在父类 ISBlockDiversifiedActionSheetView 上，
// 直接拿父类的 Method 替换即可（子类继承下来共用同一个 Method）。
//
// ⚠ 这两个 hook 的「作用域」必须收紧：
//   父类是全 App 共用的通用弹窗基类（相册、文件夹、文档列表都在用）。
//   如果无条件往每个数据源里塞「保存到文件」，用户会在完全无关的弹窗里
//   看到这一格，点下去还会因为 presenter 不对而报错 —— 属于严重副作用。
//   所以先判定 self 到底是不是目标面板（及其子类），不是就原样透传。

static BOOL CSFSSheetOwnerIsTarget(id view) {
    if (!view) return NO;
    @try {
        // 目标：OCR 结果页导出面板 ISOcrResultExportSheetLikeView
        // （用户截图里那个「邮件 / 更多 / 以 PDF 分享」的 Bottom Sheet）
        Class target = NSClassFromString(@"ISOcrResultExportSheetLikeView");
        if (target && [view isKindOfClass:target]) return YES;
        // 兼容：个别版本可能直接用父类 + 外部配置组装
        // 这种情况靠「数据源里出现过 cs_516_* 系列标题」来识别，避免误伤
        // （识别逻辑见 CSFSDataSourceLooksLikeOcrExport）
    } @catch (NSException *e) {
        CSFS_LOG(@"owner check threw: %@", e.reason);
    }
    return NO;
}

// 判定一个（可能是二维的）数据源数组是否像 OCR 导出面板：
// 出现过「以 PDF 分享」/「以 Word 分享」/「复制文字」这类条目即认为是。
static BOOL CSFSDataSourceLooksLikeOcrExport(NSArray *ds) {
    if (![ds isKindOfClass:[NSArray class]] || ds.count == 0) return NO;
    NSArray *probe = @[
        CSFSLocalized(@"cs_516_share_as_pdf", @"以 PDF 分享"),
        CSFSLocalized(@"cs_516_share_as_word", @"以 Word 分享"),
        CSFSLocalized(@"cs_516_copy_text", @"复制文字"),
        CSFSLocalized(@"cs_516_share_as_txt", @"以 TXT 分享"),
    ];
    @try {
        for (id it in ds) {
            if ([it isKindOfClass:[NSArray class]]) {
                if (CSFSDataSourceLooksLikeOcrExport((NSArray *)it)) return YES;
                continue;
            }
            NSString *t = CSFSItemTitle(it);
            if (t.length && [probe containsObject:t]) return YES;
        }
    } @catch (NSException *e) { return NO; }
    return NO;
}

static void (*gOrigSetHorizontalDS)(id, SEL, id) = NULL;
static void (*gOrigSetVerticalDS)(id, SEL, id) = NULL;

static void CSFS_setHorizontallyDataSource(id self, SEL _cmd, id ds) {
    id replaced = ds;
    @try {
        // 作用域收紧：不是目标面板就原样透传，绝不给无关弹窗加条目
        if (!CSFSSheetOwnerIsTarget(self) && !CSFSDataSourceLooksLikeOcrExport(ds)) {
            if (gOrigSetHorizontalDS) gOrigSetHorizontalDS(self, _cmd, ds);
            return;
        }
        CSFSDumpDataSource(ds, @"horizontal");
        NSString *title = CSFSLocalized(@"cs_649_object_10", @"保存到「文件」");
        NSMutableArray *arr = nil;
        if ([ds isKindOfClass:[NSArray class]]) {
            arr = [ds mutableCopy];
        } else if ([ds isKindOfClass:[NSMutableArray class]]) {
            arr = ds;
        }
        if (arr && !CSFSArrayContainsTitle(arr, title)) {
            // 横向项优先照抄现有条目类；数组为空时才回落到已实证的 Swift 类名
            // _TtC19CSUIComponent_Swift26CSSheetHorizontalItemModel。
            Class cls = nil;
            if (arr.count > 0) cls = [arr.firstObject class];
            if (!cls) cls = CSFSItemClass(kCSFSHorizontalItemClass);
            id item = CSFSBuildItem(cls, title, kCSFSSaveToFilesId, nil);
            if (item) {
                [arr addObject:item];
                replaced = arr;
                CSFS_LOG(@"horizontal: appended 「%@」 using class %@, now %lu items",
                         title, NSStringFromClass(cls), (unsigned long)arr.count);
            } else {
                CSFS_LOG(@"horizontal: cannot build item (cls=%@), skipped",
                         NSStringFromClass(cls));
            }
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"horizontal DS hook threw: %@", e.reason);
        replaced = ds;
    }
    if (gOrigSetHorizontalDS) gOrigSetHorizontalDS(self, _cmd, replaced);
}

static void CSFS_setVerticallyDataSource(id self, SEL _cmd, id ds) {
    id replaced = ds;
    @try {
        // 作用域收紧（同横向 hook）：无关面板一律原样透传
        if (!CSFSSheetOwnerIsTarget(self) && !CSFSDataSourceLooksLikeOcrExport(ds)) {
            if (gOrigSetVerticalDS) gOrigSetVerticalDS(self, _cmd, ds);
            return;
        }
        CSFSDumpDataSource(ds, @"vertical");
        NSString *title = CSFSLocalized(@"cs_649_object_10", @"保存到「文件」");

        // ⚠ 纵向数据源是**二维数组**！
        //   -tableView:cellForRowAtIndexPath: (0x1020208ac) 的取法是：
        //       data = -verticallyListDataSource
        //       if (-isGroupedverticallyList) data = data[indexPath.section]
        //       model = data[indexPath.row]
        //   也就是说分组风格下是 NSArray<NSArray<model>*>*。
        //   若当成一维数组直接 addObject: 一个 model，那么
        //   objectAtIndexedSubscript: 会作用在 model 上 → unrecognized selector → **崩宿主**。
        //   所以这里必须判定维度，按对应层追加。

        BOOL isGrouped = NO;
        SEL selGrouped = NSSelectorFromString(@"isGroupedverticallyList");
        if ([self respondsToSelector:selGrouped]) {
            IMP imp = [self methodForSelector:selGrouped];
            if (imp) {
                BOOL (*fn)(id, SEL) = (BOOL (*)(id, SEL))imp;
                isGrouped = fn(self, selGrouped);
            }
        }

        NSMutableArray *outer = nil;
        if ([ds isKindOfClass:[NSArray class]]) {
            outer = [ds mutableCopy];
        }

        if (outer) {
            // 定位「真正装 model 的那一层」
            NSMutableArray *modelLayer = nil;
            if (isGrouped && outer.count > 0 &&
                [outer.firstObject isKindOfClass:[NSArray class]]) {
                // 二维：往最后一个分组里追加（也就是「以 PDF 分享」那条所在组之后）
                modelLayer = [outer.lastObject mutableCopy];
                if (modelLayer &&
                    !CSFSArrayContainsTitle(modelLayer, title)) {
                    Class cls = (modelLayer.count > 0)
                              ? [modelLayer.firstObject class]
                              : CSFSItemClass(kCSFSVerticalItemClass);
                    id item = CSFSBuildItem(cls, title, kCSFSSaveToFilesId, nil);
                    if (item) {
                        [modelLayer addObject:item];
                        [outer replaceObjectAtIndex:(outer.count - 1)
                                          withObject:modelLayer];
                        replaced = outer;
                        CSFS_LOG(@"vertical(grouped): appended 「%@」 class=%@ "
                                 @"section=%lu row=%lu",
                                 title, NSStringFromClass(cls),
                                 (unsigned long)(outer.count - 1),
                                 (unsigned long)(modelLayer.count - 1));
                    } else {
                        CSFS_LOG(@"vertical(grouped): cannot build item (cls=%@)",
                                 NSStringFromClass(cls));
                    }
                }
            } else {
                // 一维：直接追加
                if (!CSFSArrayContainsTitle(outer, title)) {
                    Class cls = (outer.count > 0)
                              ? [outer.firstObject class]
                              : CSFSItemClass(kCSFSVerticalItemClass);
                    id item = CSFSBuildItem(cls, title, kCSFSSaveToFilesId, nil);
                    if (item) {
                        [outer addObject:item];
                        replaced = outer;
                        CSFS_LOG(@"vertical(flat): appended 「%@」 class=%@, now %lu",
                                 title, NSStringFromClass(cls),
                                 (unsigned long)outer.count);
                    } else {
                        CSFS_LOG(@"vertical(flat): cannot build item (cls=%@)",
                                 NSStringFromClass(cls));
                    }
                }
            }
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"vertical DS hook threw: %@", e.reason);
        replaced = ds;
    }
    if (gOrigSetVerticalDS) gOrigSetVerticalDS(self, _cmd, replaced);
}

// ── 点击拦截 ──────────────────────────────────────────────────────────
//
// 面板点击最终都汇到
//   -actionSheetClickItemAndShareWithFileWay:withItemTitle:withAllPage:
// 参数：fileWay(NSInteger) / itemTitle(NSString*) / allPage(BOOL)
//
// ⚠ itemTitle 到底是什么？
//   clickTableViewCellWithIndexPath: (0x102021950) 的反汇编显示它先向 model
//   取 -titleString（0x1020219d0），再取 -titleAttributedString.string 作为备选，
//   然后才把结果塞进回调字典。所以传下来的就是 **titleString**。
//   只要我们自己写入的标题与比对用标题是同一个字符串，就必然命中。
static void (*gOrigClickItem)(id, SEL, NSInteger, id, BOOL) = NULL;

static void CSFS_clickItemAndShare(id self, SEL _cmd,
                                   NSInteger fileWay,
                                   id itemTitle,
                                   BOOL allPage) {
    @try {
        NSString *title = CSFSLocalized(@"cs_649_object_10", @"保存到「文件」");
        if ([itemTitle isKindOfClass:[NSString class]] &&
            [(NSString *)itemTitle isEqualToString:title]) {
            CSFS_LOG(@"intercepted panel tap: title=%@ fileWay=0x%lx allPage=%d",
                     itemTitle, (long)fileWay, (int)allPage);
            // 用 block 派发，不用 performSelectorOnMainThread:withObject: ——
            // 后者只能传一个参数，而我们要带 allPage 这个 BOOL。
            __weak id weakSelf = self;
            dispatch_async(dispatch_get_main_queue(), ^{
                @try {
                    id strong = weakSelf;
                    if (!strong) return;
                    SEL s = NSSelectorFromString(@"csfs_doSaveToFiles:");
                    if (![strong respondsToSelector:s]) {
                        CSFS_LOG(@"csfs_doSaveToFiles: not installed on %@",
                                 NSStringFromClass([strong class]));
                        return;
                    }
                    IMP imp = [strong methodForSelector:s];
                    if (!imp) return;
                    void (*fn)(id, SEL, NSNumber *) = (void (*)(id, SEL, NSNumber *))imp;
                    fn(strong, s, @(allPage));
                } @catch (NSException *e) {
                    CSFS_LOG(@"dispatch save threw: %@", e.reason);
                }
            });
            return;
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"click hook threw: %@", e.reason);
    }
    if (gOrigClickItem) gOrigClickItem(self, _cmd, fileWay, itemTitle, allPage);
}

// 在 presenter 上注入真正的保存动作（category 无法在 dylib 里 static 加，
// 所以走 class_addMethod）。self 就是 presenter，能直接拿到它的上下文。
static void CSFS_doSaveToFiles(id self, SEL _cmd, NSNumber *allPageNum) {
    @try {
        BOOL allPage = allPageNum.boolValue;
        CSFS_LOG(@"doSaveToFiles begin, allPage=%d, presenter=%@", (int)allPage, self);

        // ① 首选：页面上的文件其实已经生成好了（面板顶部那张文件卡片就是它），
        //    直接交给文件选择器，不再触发一次转换。
        //
        //    ⚠ 目录扫描必须离开主线程。之前在主线程里同步遍历 Documents/tmp/Caches，
        //      文件多时能卡住几百毫秒，严重时被 watchdog 杀进程。
        //      这里丢到后台队列，扫完再回主线程弹 picker。
        __weak id weakSelf = self;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            @try {
                NSArray<NSURL *> *urls = CSFSCollectReadyFileURLs(weakSelf);
                dispatch_async(dispatch_get_main_queue(), ^{
                    @try {
                        if (urls.count > 0) {
                            CSFS_LOG(@"exporting %lu ready file(s) directly",
                                     (unsigned long)urls.count);
                            CSFSPresentExportPicker(urls);
                            return;
                        }
                        // ② 真的没有文件 → 借道 app 自己的转换链路，出口由
                        //    -showShareActivityWithFilePath:completionBlock: 的 hook 接管。
                        CSFS_LOG(@"no ready file, arm pending and drive app conversion");
                        CSFSArmPending();
                        // 打开「强制可达」窗口：否则 CSConvertWorkTool 第一步的
                        // Reachability 检查会误判为 NotReachable，直接弹「转换失败」。
                        // 转换是异步的，给 60s 足够完成；正常结束会由
                        // -showShareActivityWithFilePath: 的 hook 提前复位。
                        gCSFSForceReachable = YES;
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                                     (int64_t)(60.0 * NSEC_PER_SEC)),
                                       dispatch_get_main_queue(), ^{
                            if (gCSFSForceReachable) {
                                gCSFSForceReachable = NO;
                                CSFS_LOG(@"force-reachable window timed out, reset");
                            }
                        });
                        CSFSShowBusy(@"正在生成文件…");
                        SEL conv = NSSelectorFromString(@"shareWordFileWithExportFileWay:withAllPage:");
                        id strong = weakSelf;
                        if (strong && [strong respondsToSelector:conv]) {
                            IMP imp2 = [strong methodForSelector:conv];
                            if (imp2) {
                                void (*fn2)(id, SEL, NSInteger, BOOL) =
                                    (void (*)(id, SEL, NSInteger, BOOL))imp2;
                                fn2(strong, conv, 0, allPage);
                                return;
                            }
                        }
                        // ③ 两条路都不通：撤回标记并明确告知，不留"点了没反应"
                        CSFSExportState.shared.pendingSaveToFiles = NO;
                        CSFSHideBusy(nil);
                        CSFSToast(@"暂时找不到可导出的文件，请稍后重试");
                        CSFS_LOG(@"both paths unavailable");
                    } @catch (NSException *e) {
                        CSFS_LOG(@"save dispatch threw: %@", e.reason);
                        CSFSHideBusy(nil);
                    }
                });
            } @catch (NSException *e) {
                CSFS_LOG(@"background scan threw: %@", e.reason);
                dispatch_async(dispatch_get_main_queue(), ^{ CSFSHideBusy(nil); });
            }
        });
    } @catch (NSException *e) {
        CSFS_LOG(@"doSaveToFiles threw: %@", e.reason);
        CSFSHideBusy(nil);
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

// ── v6 路径探针（诊断期专用，定位真实路径后删除）────────────────────
// v5 日志证明：点「导出文档」后，已装的全部 hook 一条都没触发
// （officeFileShareViewData 被调用时必打日志，但日志毫无动静）。
// 说明用户的真实路径不经过现有 hook 覆盖的任何方法。
// 下面四个探针只记日志、全部转发原实现，一次运行即可照亮真实路径：
//   P1 exportWordAction      —— 验证「导出文档」按钮是否走 CSJsonWordEditBottomView
//   P2 showShareView         —— 验证 CSShareManager 链条第一环
//   P3 showOfficeShareView   —— 验证第二环（officeFileShareViewData 的直接调用方）
//   P4 presentViewController —— 广谱：任何模态弹出都记录类名
static void (*gOrigExportWordAction)(id, SEL) = NULL;
static void CSFS_exportWordAction(id self, SEL _cmd) {
    @try {
        CSFS_LOG(@"P1 exportWordAction hit (%@)", NSStringFromClass([self class]));
        if (gOrigExportWordAction) gOrigExportWordAction(self, _cmd);
    } @catch (NSException *e) {
        CSFS_LOG(@"P1 threw: %@", e.reason);
    }
}

static void (*gOrigShowShareView)(id, SEL) = NULL;
static void CSFS_showShareView(id self, SEL _cmd) {
    @try {
        CSFS_LOG(@"P2 showShareView hit");
        if (gOrigShowShareView) gOrigShowShareView(self, _cmd);
    } @catch (NSException *e) {
        CSFS_LOG(@"P2 threw: %@", e.reason);
    }
}

static void (*gOrigShowOfficeShareView)(id, SEL) = NULL;
static void CSFS_showOfficeShareView(id self, SEL _cmd) {
    @try {
        CSFS_LOG(@"P3 showOfficeShareView hit");
        if (gOrigShowOfficeShareView) gOrigShowOfficeShareView(self, _cmd);
    } @catch (NSException *e) {
        CSFS_LOG(@"P3 threw: %@", e.reason);
    }
}

static void (*gOrigPresentVC)(id, SEL, UIViewController *, BOOL, void (^)(void)) = NULL;
static void CSFS_presentVC(id self, SEL _cmd, UIViewController *vc, BOOL animated,
                           void (^completion)(void)) {
    @try {
        CSFS_LOG(@"P4 present: %@ on %@",
                 NSStringFromClass([vc class]), NSStringFromClass([self class]));
        if (gOrigPresentVC) gOrigPresentVC(self, _cmd, vc, animated, completion);
    } @catch (NSException *e) {
        CSFS_LOG(@"P4 threw: %@", e.reason);
    }
}

// ── v7：真面板挂点（CSSharePanellViewController 的条目数组）─────────
// v6 探针真机实证（CSFS(3).log 14:33:54）：
//   P1 exportWordAction hit → P2 showShareView hit
//   → P4 present: CSSharePanellViewController on CSJsonWordEditViewController
//   且 P3 showOfficeShareView 未触发 —— 面板根本不走 officeFileShareViewData！
//   （前四轮全败的真正原因：一直往另一条路径的数组里塞条目。）
// 面板数据链（全部反汇编实证，地址见注释）：
//   CSSharePanellViewController → CSSharePanelAdpterManager（collection 数据源）
//     → CSShareCompositionalMainWaysSectionAdapter          ← 主要分享方式分区
//         channelArray : NSArray<CSActionSheetOperation*>   ← 条目数组（loadData 填充）
//         渲染：[item titleString] + [CSShareManager whiteBackgroundIconWithModel:]
//               （0x1018d7448 / 0x1018d74ac / 0x1018d7498）
//         点击：[item actionSheetOperationType] → shareActionWithOperationTpe:needLog:
//               （0x1018d7910 / 0x1018d7a34 —— 0xE5 已被 CSFSTryInterceptShareAction 接住）
// 挂点：hook channelArray getter —— 渲染和点击都从它取条目，改一处即全链生效。
static NSArray *(*gOrigChannelArray)(id, SEL) = NULL;

static NSArray *CSFS_channelArray(id self, SEL _cmd) {
    @try {
        NSArray *orig = nil;
        if (gOrigChannelArray) orig = gOrigChannelArray(self, _cmd);
        if (orig.count == 0) return orig;

        // 已含「保存到文件」条目则原样返回（防重复追加：type 或标题任一匹配即算）
        for (id it in orig) {
            if ([it respondsToSelector:@selector(actionSheetOperationType)]) {
                NSInteger (*tfn)(id, SEL) =
                    (NSInteger (*)(id, SEL))[it methodForSelector:@selector(actionSheetOperationType)];
                if (tfn(it, @selector(actionSheetOperationType)) == kCSFSSaveToFilesId) {
                    return orig;
                }
            }
            if ([it respondsToSelector:@selector(titleString)]) {
                NSString *(*gfn)(id, SEL) =
                    (NSString *(*)(id, SEL))[it methodForSelector:@selector(titleString)];
                NSString *t = gfn(it, @selector(titleString));
                if ([t isEqualToString:kCSFSSaveToFilesTitle]) {
                    return orig;
                }
            }
        }

        // v8 修正：条目模型类是 **CSActionSheetModel**（setTitleString:/
        // setActionSheetOperationType:/setIconName: 的唯一实现者，见 implist）。
        // CSActionSheetOperation 只是**工厂宿主类**（类方法
        // +shareOtherAppModelArrayWithOperationtype:linkType:useNewIcon: 挂在它上，
        // loadData 0x1018d6ae0-0x1018d6b20 实证）——alloc 它没有那些属性，
        // 这正是 v7 日志 title=0 type=0 的原因。
        //
        // 首选：调工厂按 0xE5 生产条目（标题/图标原生配置）；
        // 工厂不认识 0xE5 时回退 alloc CSActionSheetModel 手动填。
        id item = nil;
        Class opCls = NSClassFromString(@"CSActionSheetOperation");
        SEL factorySel = NSSelectorFromString(
            @"shareOtherAppModelArrayWithOperationtype:linkType:useNewIcon:");
        if (opCls && [opCls respondsToSelector:factorySel]) {
            IMP fimp = [opCls methodForSelector:factorySel];
            if (fimp) {
                NSArray *(*fn)(id, SEL, id, NSInteger, BOOL) =
                    (NSArray *(*)(id, SEL, id, NSInteger, BOOL))fimp;
                NSArray *types = @[@(kCSFSSaveToFilesId)];
                NSArray *made = fn(opCls, factorySel, types, (NSInteger)0, NO);
                CSFS_LOG(@"v8 factory made=%lu", (unsigned long)made.count);
                if (made.count > 0) item = made[0];
            }
        }
        if (!item) {
            Class modelCls = NSClassFromString(@"CSActionSheetModel");
            if (!modelCls) {
                CSFS_LOG(@"v8 WARN: CSActionSheetModel 未注册，条目不追加");
                return orig;
            }
            item = [[modelCls alloc] init];
        }
        if (!item) return orig;

        BOOL wroteTitle = CSFSSetStringIfPossible(item, @[ @"titleString" ], kCSFSSaveToFilesTitle);
        BOOL wroteType  = CSFSSetIntegerIfPossible(item, @[ @"actionSheetOperationType" ], kCSFSSaveToFilesId);
        CSFS_LOG(@"v8 +save-to-files cls=%@ title=%d type=%d total=%lu",
                 NSStringFromClass([item class]), (int)wroteTitle, (int)wroteType,
                 (unsigned long)(orig.count + 1));

        NSMutableArray *out = [orig mutableCopy];
        [out addObject:item];
        return out;
    } @catch (NSException *e) {
        CSFS_LOG(@"v7 channelArray threw: %@", e.reason);
        if (gOrigChannelArray) return gOrigChannelArray(self, _cmd);
        return nil;
    }
}

// ── v9：面板点击拦截 ─────────────────────────────────────────────
// CSFS(5).log 实证：v8 条目已显示（factory made=1, title=1 type=1），
// 但点击后零日志 —— 0xE5 在 didSelectCellWithIndexPath: 的原生分派里
// 被 isSingleOfficeDocument → handleSingleOfficeDocumentShare: 分支吃掉，
// 根本到不了 shareActionWithOperationTpe:（那里已有 0xE5 拦截却收不到）。
// 所以在 didSelect 层直接拦：点中 0xE5 → 置 pending → 用 0x78(Word) 走
// 原生转换 → 文件生成后由 showShareActivityWithFilePath: hook 改道保存。
static void (*gOrigDidSelectCell)(id, SEL, id) = NULL;

// ── v12：本地生成 Word 文档 ──────────────────────────────────────────
// CSFS(8).log 铁证：Document.fileExist=0 / PDFPath=nil —— office 转换在
// 本环境从未成功（点邮件/更多/原生以Word分享全部「转换失败」）。
// 但 JSON Word 内容就在本地（编辑页可见，jsonWordCache）。
// v12：扫描沙盒找 jsonWordCache → 提取文本 → 本地生成最小 .docx → picker。
// （借道原转换链在 v8-v11 已被三轮真机证伪，不再尝试。）

// ── v18：保留排版 ────────────────────────────────────────────────────
//
// v17 的 docx 能用 Word 正常打开了，但内容全是一个格式（默认宋体小四）。
// 用户对比截图指出：原文里「刚刚」是蓝色、「国家统计局官网」是大号加粗、
// 「我收入没达标，得加油」是红色加粗、表格数字分列 —— 导出后全变黑体小字。
//
// 根因不在 docx 生成，而在**解析阶段就丢了信息**：
//   v14~v17 的解析只取 slices[].text，slice 里的 style 对象整个扔掉，
//   到 CSFSWriteDocx 时手上只剩一串 NSString，格式早已不存在。
//
// 样式字段是从二进制里反查出来的（objc 元数据 + ivar 类型编码），
// 不是猜的：
//   CSTranslateRawPageSegmentParaSlice
//     ├ text            NSString   文本
//     ├ stype           NSString   片段类型
//     ├ style           CSTranslateRawPageSegmentParaSliceStyle
//     │   ├ font_color      NSString   颜色（如 "#FF0000"）
//     │   ├ font_face       NSString   字体名
//     │   ├ font_size       NSNumber   字号（pt）
//     │   └ font_attribute  CSTranslateRawPageFont
//     │        ├ bold       NSString   "1"/"true" 等
//     │        ├ italic     NSString
//     │        └ underline  NSString
//     └ break_line      long       是否换行
//   CSTranslateRawPageSegmentPara
//     ├ justification   NSString   对齐（left/center/right/justify）
//     ├ line_gap        float      行距
//     └ paragraph_gap   float      段距
//
// 所以 v18 把中间表示从「NSString 数组」换成「字典组成的段落结构」，
// 解析时把 style 一并带出来，生成时按 run 逐个写 <w:rPr>。
//
// ⚠ 为什么用 NSDictionary 而不是 C struct：
//   最初写成 `typedef struct { NSString *text; ... } CSFSStyleRun`，
//   再用 `[NSValue valueWithBytes:&r objCType:@encode(...)]` 装箱。问题是：
//     ① ARC 只管 struct **局部变量**里的对象字段，一旦 memcpy 进 NSValue
//        的缓冲区，ARC 就看不见这些引用 - 理论上存在被提前释放的风险；
//     ② 要额外声明 getValue: / valueWithBytes:objCType: 等一串白名单，
//        每加一个字段就要多维护一行，容易漏。
//   这是注入 dylib，崩宿主是不可接受的结果，所以宁可多几个字典开销，
//   换成全 ARC 管理的 NSDictionary。段落本身用 NSMutableDictionary，
//   run 数组存 NSMutableDictionary，键名常量集中定义（见下）。

// run 的键
static NSString *const kCSFSRunText      = @"t";
static NSString *const kCSFSRunColor     = @"c";
static NSString *const kCSFSRunFace      = @"f";
static NSString *const kCSFSRunSize      = @"s";
static NSString *const kCSFSRunBold      = @"b";
static NSString *const kCSFSRunItalic    = @"i";
static NSString *const kCSFSRunUnderline = @"u";
// 段落的键
static NSString *const kCSFSParaRuns     = @"runs";
static NSString *const kCSFSParaAlign    = @"jc";

// 从 JSON 的布尔字段取值。
// 实证：这类字段在 CamScanner 的 JSON 里以 NSString 出现（"1"/"0"/"true"/"YES"），
// 但也可能是 NSNumber。两种都吃，避免因类型判断写死而在某版本静默失效。
static BOOL CSFSBoolValue(id v) {
    if (!v) return NO;
    if ([v isKindOfClass:[NSNumber class]]) {
        return [(NSNumber *)v boolValue];
    }
    if ([v isKindOfClass:[NSString class]]) {
        NSString *s = [(NSString *)v lowercaseString];
        return ([s isEqualToString:@"1"] || [s isEqualToString:@"true"] ||
                [s isEqualToString:@"yes"]);
    }
    return NO;
}

// 从 JSON 取 double。字段可能是 NSNumber，也可能是数字字符串。
static double CSFSDoubleValue(id v) {
    if (!v) return 0;
    if ([v isKindOfClass:[NSNumber class]]) return [(NSNumber *)v doubleValue];
    if ([v isKindOfClass:[NSString class]]) return [(NSString *)v doubleValue];
    return 0;
}

// 颜色归一化：把各种可能的写法统一成 6 位大写 RRGGBB。
// 支持 #RRGGBB / #RGB / 0xRRGGBB / RRGGBB / RRGGBBAA / AARRGGBB。
// 返回 nil 表示"没有可用颜色"，调用方应回退到默认黑色。
static NSString *CSFSNormalizeHexColor(NSString *raw) {
    if (raw.length == 0) return nil;
    NSString *s = raw;
    // 去前缀
    if ([s hasPrefix:@"#"]) s = [s substringFromIndex:1];
    else if ([s hasPrefix:@"0x"] || [s hasPrefix:@"0X"]) s = [s substringFromIndex:2];
    s = [s uppercaseString];
    if (s.length == 3) {
        // #RGB → RRGGBB
        unichar a = [s characterAtIndex:0], b = [s characterAtIndex:1], c = [s characterAtIndex:2];
        return [NSString stringWithFormat:@"%c%c%c%c%c%c", a, a, b, b, c, c];
    }
    if (s.length == 8) {
        // 两种排布都可能：RRGGBBAA 或 AARRGGBB。
        // 判断依据：如果前两位是 FF 且后六位不是 FF...FF，多半是 AARRGGBB；
        // 但这不可靠。这里采用更常见的 AARRGGBB（Android/服务端惯例）。
        // 若首位 alpha 为 FF（不透明），取后 6 位；否则也取后 6 位（忽略透明度）。
        s = [s substringFromIndex:2];
    }
    if (s.length != 6) return nil;
    // 只接受十六进制字符；有非法字符就判定无效，交给调用方回退
    for (NSUInteger i = 0; i < 6; i++) {
        unichar ch = [s characterAtIndex:i];
        BOOL hex = (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F');
        if (!hex) return nil;
    }
    return s;
}

// 把 JSON 里的一个 slice 解析成 run 字典。
// 解析失败也要返回一个只有文字的 run —— 宁可少格式，不能丢文字。
//
// diagnosticPtr：由调用方传入，首次解析到带 style 的 slice 时把它置 YES，
// 借这一个开关把「真实 JSON 的 style 长什么样」dump 进日志一次。
// 为什么非要这段：v18 用的字段名（font_color / font_size / font_attribute…）
// 是从 Mach-O 的 objc 元数据 + ivar 类型编码反推的，**没有经过真实样本确认**。
// 一旦实际键名不同，格式会静默丢失 —— 表现与 v17 完全一样，无从区分。
// 有了这段 dump，下一轮能直接看真名，不用再猜。
static NSMutableDictionary *CSFSParseSlice(id sl, BOOL *diagnosticPtr) {
    if (![sl respondsToSelector:@selector(objectForKey:)]) return nil;

    id t = [sl objectForKey:@"text"];
    if (![t isKindOfClass:[NSString class]] || [(NSString *)t length] == 0) return nil;

    NSMutableDictionary *run = [NSMutableDictionary dictionaryWithCapacity:8];
    [run setObject:(NSString *)t forKey:kCSFSRunText];

    id style = [sl objectForKey:@"style"];
    if (![style respondsToSelector:@selector(objectForKey:)]) {
        if (diagnosticPtr && !*diagnosticPtr) {
            *diagnosticPtr = YES;
            CSFS_LOG(@"v18 DIAG no style on slice, keys=%@",
                     [sl respondsToSelector:@selector(allKeys)] ? [sl allKeys] : @"(n/a)");
        }
        return run;
    }

    if (diagnosticPtr && !*diagnosticPtr) {
        *diagnosticPtr = YES;
        CSFS_LOG(@"v18 DIAG first styled slice: text=%@ style=%@",
                 [(NSString *)t length] > 20
                    ? [(NSString *)t substringToIndex:20] : (NSString *)t,
                 [style respondsToSelector:@selector(description)]
                    ? [style description] : @"(no desc)");
    }

    id c = [style objectForKey:@"font_color"];
    if ([c isKindOfClass:[NSString class]]) {
        NSString *hex = CSFSNormalizeHexColor((NSString *)c);
        if (hex) [run setObject:hex forKey:kCSFSRunColor];
    }
    id f = [style objectForKey:@"font_face"];
    if ([f isKindOfClass:[NSString class]] && [(NSString *)f length] > 0) {
        [run setObject:(NSString *)f forKey:kCSFSRunFace];
    }
    // 字号合理性检查：OCR 偶尔给出 0 或离谱值（如 1000），
    // 越界的字号在 Word 里会被当成损坏样式，宁可不设。
    double sz = CSFSDoubleValue([style objectForKey:@"font_size"]);
    if (sz > 2.0 && sz < 200.0) {
        [run setObject:[NSNumber numberWithDouble:sz] forKey:kCSFSRunSize];
    }

    id attr = [style objectForKey:@"font_attribute"];
    if ([attr respondsToSelector:@selector(objectForKey:)]) {
        if (CSFSBoolValue([attr objectForKey:@"bold"])) {
            [run setObject:[NSNumber numberWithBool:YES] forKey:kCSFSRunBold];
        }
        if (CSFSBoolValue([attr objectForKey:@"italic"])) {
            [run setObject:[NSNumber numberWithBool:YES] forKey:kCSFSRunItalic];
        }
        if (CSFSBoolValue([attr objectForKey:@"underline"])) {
            [run setObject:[NSNumber numberWithBool:YES] forKey:kCSFSRunUnderline];
        }
    }
    return run;
}

static NSString *CSFSXMLEscape(NSString *in) {
    if (in.length == 0) return in;

    // v17：先剔除 XML 1.0 不允许的控制字符，再做实体转义。
    //
    // 为什么必须做这一步：XML 1.0 规范（第五版）规定 Char 的合法范围是
    //   #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
    // 也就是说 0x00-0x08 / 0x0B / 0x0C / 0x0E-0x1F 这些字节**根本不能出现在
    // XML 文档里**，连 &#xB; 这种字符引用都不合法。OCR 出来的文本混进
    // 一个 0x0C（分页符）或 0x1B，整个 document.xml 就变成非法 XML ——
    // Word 打开时提示「发现无法读取的内容」，与 ZIP 结构损坏的表现一模一样。
    //
    // 只转义 & < > 是不够的：那两个是「必须转义的合法字符」，这里是
    // 「无论怎么转义都不合法」的字符，唯一办法是丢掉。
    NSUInteger n = in.length;
    unichar *buf = (unichar *)malloc(n * sizeof(unichar));
    if (buf) {
        [in getCharacters:buf range:NSMakeRange(0, n)];
        NSUInteger w = 0;
        for (NSUInteger i = 0; i < n; i++) {
            unichar c = buf[i];
            // 丢掉：C0 控制字符（除 \t \n \r）、0x7F、U+FFFE/U+FFFF 等非字符
            if (c < 0x20) {
                if (c == 0x09 || c == 0x0A || c == 0x0D) buf[w++] = c;
            } else if (c == 0x7F) {
                // DEL，XML 1.0 允许但 Word 会当作乱码，一并丢掉
            } else if (c == 0xFFFE || c == 0xFFFF) {
                // Unicode 非字符，XML 不允许
            } else {
                buf[w++] = c;
            }
        }
        in = [NSString stringWithCharacters:buf length:w];
        free(buf);
    }
    if (in.length == 0) return in;

    // 把 \r\n / \r 统一成 \n：w:t 里的裸 \r 会被 Word 渲染成方块，
    // 而 \n 在多行文本里应当由外层拆成独立的 <w:p/>（见 CSFSWriteDocx）。
    in = [in stringByReplacingOccurrencesOfString:@"\r\n" withString:@"\n"];
    in = [in stringByReplacingOccurrencesOfString:@"\r" withString:@"\n"];

    NSMutableString *m = [in mutableCopy];
    NSString *ampE = @"&" @"amp;";
    NSString *ltE  = @"&" @"lt;";
    NSString *gtE  = @"&" @"gt;";
    [m replaceOccurrencesOfString:@"&" withString:ampE
                           options:NSLiteralSearch range:NSMakeRange(0, m.length)];
    [m replaceOccurrencesOfString:@"<" withString:ltE
                           options:NSLiteralSearch range:NSMakeRange(0, m.length)];
    [m replaceOccurrencesOfString:@">" withString:gtE
                           options:NSLiteralSearch range:NSMakeRange(0, m.length)];
    return m;
}

// v14：空白字符集（typed IMP，避免 P5）
static id CSFSWhiteSpaceSet(void) {
    SEL wsel = NSSelectorFromString(@"whitespaceAndNewlineCharacterSet");
    id (*wcf)(id, SEL) = (id (*)(id, SEL))[NSCharacterSet methodForSelector:wsel];
    return wcf([NSCharacterSet class], wsel);
}

// 递归收集 JSON 里的字符串值；dict 按 key 排序尽量保序，array 保序
static void CSFSCollectStrings(id obj, NSMutableArray *out2) {
    if ([obj isKindOfClass:[NSString class]]) {
        SEL wcsel = NSSelectorFromString(@"whitespaceAndNewlineCharacterSet");
        id (*wcf)(id, SEL) = (id (*)(id, SEL))[NSCharacterSet methodForSelector:wcsel];
        NSString *t = [(NSString *)obj stringByTrimmingCharactersInSet:
                       wcf([NSCharacterSet class], wcsel)];
        if (t.length > 0) [out2 addObject:t];
        return;
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        for (id e in obj) CSFSCollectStrings(e, out2);
        return;
    }
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *d = obj;
        for (NSString *k in [d.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
            CSFSCollectStrings(d[k], out2);
        }
    }
}

// 扫沙盒找 JSON Word 正文（v16：内容校验为主，路径只做加权）
//
// 三轮真机教训，逐条记下来，因为这正是 v13/v14/v15 三次失败的同一个模式：
//   v13  扫 Documents/Caches，找不到 —— 缓存实际在 Library/<hash>/OtherFiles
//   v14  加 Library + 按 mtime 最新 → 命中 documentThumbnailImages/<id>_wordj.jpg
//   v15  排除图片扩展 → 命中 OtherFiles/imageToExcelResultsNew/commonstoragePath.json
//
// v15 尤其值得记：命中的是 394 字节的 **plist 状态索引**
// （`<?xml ... <key>xxx_state</key><integer>4</integer>`），不是文档正文。
// 即使不闪退，也只会生成一个装着状态字段的假 Word。
//
// 根因不是「排序策略不对」，而是**选文件一直在靠路径猜，从来没校验过内容**。
//
// ⚠ 这里有个反直觉的实证，必须写死以免以后又想「优化」掉：
//   用户真机提供的正文样本 NKF1JUJ4TX7K98712J1TVHYR.json（79.5KB，含完整
//   segments/PARA/slices）**就躺在 imageToExcelResultsNew 目录下**。
//   也就是说 App 把 Word 的 JSON 正文也存在这个「名字叫 Excel」的目录里，
//   文件名是一个与 docId 毫无关系的大写随机 ID。
//   → 所以**不能**按目录名筛 word，只能靠内容判定；目录名最多当加权。
//
// 判据（硬门槛，缺一不可）：
//   ① 内容以 `{` 或 `[` 开头（状态文件是 `<?xml`，直接排除）
//   ② 含 "segments" 键（实证正文结构：segments[]页 → segments[]块 → paras[] → slices[]）
// 在通过校验的候选里取 mtime 最新的一个。
static BOOL CSFSLooksLikeWordJSON(NSString *txt) {
    if (txt.length < 16) return NO;
    // 只看开头 2KB 判断形态，避免对超大文件做整串搜索
    NSUInteger probeLen = txt.length < 2048 ? txt.length : 2048;
    NSString *probe = [txt substringToIndex:probeLen];
    id ws = CSFSWhiteSpaceSet();
    if (ws) probe = [probe stringByTrimmingCharactersInSet:ws];
    // 状态文件是 plist（以 <?xml 开头），正文是 JSON（以 { 开头）
    if (!([probe hasPrefix:@"{"] || [probe hasPrefix:@"["])) return NO;
    // 正文必含 segments；状态索引只有 *_state / *_isCreatedByShare
    if (![txt containsString:@"segments"]) return NO;
    return YES;
}

static NSString *CSFSFindJSONTextForDoc(NSString *docId) {
    NSString *baseId = docId;
    if ([baseId hasSuffix:@"_wordj"]) {
        baseId = [baseId substringToIndex:baseId.length - 6];
    }
    NSString *tmpDir = NSTemporaryDirectory();
    NSArray *roots = @[
        [NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES) firstObject],
        [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject],
        [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject],
        tmpDir,
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    // 只收「Results 目录内」或「文件名含 docId」两类候选 —— 这是收窄，
    // 不是判定。真正决定用哪个靠下面的内容校验。
    NSMutableArray *cands = [NSMutableArray array];
    NSArray *imgExt = @[@"jpg", @"jpeg", @"png", @"gif", @"webp", @"bmp", @"tiff", @"heic"];
    for (NSString *root in roots) {
        if (root.length == 0) continue;
        NSDirectoryEnumerator *en = [fm enumeratorAtPath:root];
        NSString *rel;
        while ((rel = [en nextObject]) != nil) {
            BOOL isDir = NO;
            NSString *full = [root stringByAppendingPathComponent:rel];
            if ([fm fileExistsAtPath:full isDirectory:&isDir] && isDir) continue;
            if ([imgExt containsObject:rel.pathExtension.lowercaseString]) continue;
            BOOL inResults = [rel containsString:@"Results"];
            BOOL idHit = baseId.length > 4 && [rel containsString:baseId];
            if (inResults || idHit) [cands addObject:full];
        }
    }
    CSFS_LOG(@"v16 scan: cands=%lu", (unsigned long)cands.count);
    if (cands.count == 0) return nil;

    // 一次性把 mtime 读出来放进内存，再排序。
    // （反面教材：直接在 sortedArrayUsingComparator 里调 attributesOfItemAtPath:
    //   会变成 O(n log n) 次同步读盘，本项目早前踩过这个坑。）
    //
    // 用「两个平行数组」而不是装字典：
    //   字典要先装箱 NSDate，取值时再强转，而 sortUsingComparator: 的 block
    //   签名是 NSComparisonResult(^)(id, id)，写成 ^(NSDictionary*, NSDictionary*)
    //   会触发 incompatible block pointer types（-Wall 下直接报错）。
    NSMutableArray<NSString *> *paths = [NSMutableArray arrayWithCapacity:cands.count];
    NSMutableArray<NSNumber *> *times = [NSMutableArray arrayWithCapacity:cands.count];
    for (NSString *p in cands) {
        NSDictionary *attr = [fm attributesOfItemAtPath:p error:nil];
        NSDate *md = [attr objectForKey:NSFileModificationDate];
        NSTimeInterval ts = [md isKindOfClass:[NSDate class]] ? [md timeIntervalSince1970] : 0;
        [paths addObject:p];
        [times addObject:[NSNumber numberWithDouble:ts]];
    }
    // 按 mtime 降序（新的在前）。这里用定长下标做选择排序的简化版：
    // 候选数一般只有几十个，O(n^2) 完全可接受，换来的是完全没有 block 类型问题。
    NSUInteger cnt = paths.count;
    for (NSUInteger i = 0; i < cnt; i++) {
        NSUInteger mx = i;
        for (NSUInteger j = i + 1; j < cnt; j++) {
            if ([times[j] doubleValue] > [times[mx] doubleValue]) mx = j;
        }
        if (mx != i) {
            [paths exchangeObjectAtIndex:i withObjectAtIndex:mx];
            [times exchangeObjectAtIndex:i withObjectAtIndex:mx];
        }
    }

    // 从最新的开始逐个校验内容，第一个通过的即用。
    // 上限 60：既覆盖「最新生成的就是目标」这一强假设，
    // 又不会在异常目录下一路读几千个文件。
    NSString *best = nil;
    NSString *bestText = nil;
    NSUInteger checked = 0;
    for (NSString *p in paths) {
        if (checked >= 60) break;
        checked++;
        SEL rsel = NSSelectorFromString(@"stringWithContentsOfFile:encoding:error:");
        NSString *(*rfn)(id, SEL, NSString *, NSUInteger, NSError **) =
            (NSString *(*)(id, SEL, NSString *, NSUInteger, NSError **))
            [NSString methodForSelector:rsel];
        if (!rfn) continue;
        NSString *txt = rfn([NSString class], rsel, p, NSUTF8StringEncoding, nil);
        if (!CSFSLooksLikeWordJSON(txt)) continue;
        best = p;
        bestText = txt;
        break;   // 已按 mtime 降序，第一个通过的就是最新的正文
    }
    if (!best) {
        CSFS_LOG(@"v16 no valid word-json found (docId=%@, checked=%lu)",
                 docId, (unsigned long)checked);
        return nil;
    }
    CSFS_LOG(@"v16 picked %@ (len=%lu checked=%lu)",
             best, (unsigned long)bestText.length, (unsigned long)checked);
    return bestText;
}

// ── v17：自写 ZIP 写出器（放弃 SSZipArchive）────────────────────────────
//
// 【为什么必须换掉 SSZipArchive】
// CSFS(12) 真机反馈：文档能导出，但 Word 打开弹「发现无法读取的内容，
// 是否恢复？」，点「是」之后只剩纯文本、格式全丢。
//
// 把真机产物逐字节拆开，问题根本不在 XML（XML 完全合规），而在 ZIP 封装层：
//     每个条目：version=45(Zip64)、flag=0x0808、crc=0、
//               csize/usize=0xFFFFFFFF、带 Zip64 extra 但里面是 0
//     整个文件：**没有** Zip64 EOCD record (PK\x06\x06)
//               **没有** Zip64 EOCD locator (PK\x06\x07)
// 也就是说：声明用了 Zip64，却没有 Zip64 的收尾结构，这个包自身是矛盾的。
//
// 这是 SSZipArchive 流式 API（writeData:filename:withPassword:）的固有行为 ——
// 它边写边压，写之前不知道最终大小和 CRC，只能先写占位符 + data descriptor
// 事后回填。库内部按 Zip64 路径走，大小却回填成 0。
// Word 的 OPC 解析器对 Zip64 支持很弱，一遇到就判损坏 → 走「修复」流程 →
// 修复只抢救得出文字，格式（样式/段落属性）全部丢失。
//
// docx 只有 4 个部件、总计几 KB，根本不需要 Zip64，也不需要压缩。
// 所以这里直接按 ZIP 规范手写：store（不压缩）+ 32 位大小 + 无 data descriptor。
// 每写一个部件前，数据已经在内存里，CRC 和长度都是已知的，不需要任何占位回填。
//
// 为什么用 store 而不是 deflate：
//   · 省掉 zlib 调用，不会引入 zlib 依赖；
//   · docx 总大小几 KB，压不压无所谓；
//   · store 没有压缩流状态，出错面最小。
//   Word / WPS / Pages / LibreOffice 都接受 store 型 docx（EPUB 同理）。

// ZIP 用的 CRC-32（IEEE 802.3，多项式 0xEDB88320 的反序查表实现）。
// 手写而不是调 zlib crc32()：避免为一个 20 行的函数引入 libz 链接。
static unsigned long CSFSCrc32(const unsigned char *buf, size_t len) {
    static unsigned long table[256];
    static BOOL inited = NO;
    if (!inited) {
        for (unsigned long i = 0; i < 256; i++) {
            unsigned long c = i;
            for (int k = 0; k < 8; k++) {
                c = (c & 1) ? (0xEDB88320UL ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
        inited = YES;
    }
    unsigned long crc = 0xFFFFFFFFUL;
    for (size_t i = 0; i < len; i++) {
        crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFUL;
}

// 小端写入辅助（ZIP 全部是小端）
static void CSFSWriteLE16(NSMutableData *d, uint16_t v) {
    uint8_t b[2] = { (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF) };
    [d appendBytes:b length:2];
}
static void CSFSWriteLE32(NSMutableData *d, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF),
                     (uint8_t)((v >> 16) & 0xFF), (uint8_t)((v >> 24) & 0xFF) };
    [d appendBytes:b length:4];
}

// 往 ZIP 里追加一个 store 条目。
//   zipData : 累积的 ZIP 字节
//   name    : 条目路径（必须用 '/' 分隔，不能以 '/' 开头）
//   content : 原始字节
// 同时把 central directory 记录追加到 cd 里。
static void CSFSZipAddEntry(NSMutableData *zipData, NSMutableData *cd,
                            NSString *name, NSData *content) {
    NSData *nameData = [name dataUsingEncoding:NSUTF8StringEncoding];
    const unsigned char *bytes = (const unsigned char *)content.bytes;
    uint32_t crc = (uint32_t)CSFSCrc32(bytes, (size_t)content.length);
    uint32_t usize = (uint32_t)content.length;
    uint32_t offset = (uint32_t)zipData.length;

    // ── Local file header ──
    CSFSWriteLE32(zipData, 0x04034b50);   // signature "PK\3\4"
    CSFSWriteLE16(zipData, 20);           // version needed = 2.0（**不用 45/Zip64**）
    CSFSWriteLE16(zipData, 0);            // flags = 0（无 data descriptor、无加密）
    CSFSWriteLE16(zipData, 0);            // method = 0 (store)
    CSFSWriteLE16(zipData, 0);            // mod time（固定值，避免引入时间依赖）
    CSFSWriteLE16(zipData, 0x21);         // mod date = 1980-01-01（DOS 纪元最小值）
    CSFSWriteLE32(zipData, crc);
    CSFSWriteLE32(zipData, usize);        // csize == usize（store）
    CSFSWriteLE32(zipData, usize);
    CSFSWriteLE16(zipData, (uint16_t)nameData.length);
    CSFSWriteLE16(zipData, 0);            // extra len = 0（**关键：不带 Zip64 extra**）
    [zipData appendData:nameData];
    [zipData appendData:content];

    // ── Central directory record ──
    CSFSWriteLE32(cd, 0x02014b50);        // signature "PK\1\2"
    CSFSWriteLE16(cd, 20);                // version made by
    CSFSWriteLE16(cd, 20);                // version needed
    CSFSWriteLE16(cd, 0);                 // flags
    CSFSWriteLE16(cd, 0);                 // method = store
    CSFSWriteLE16(cd, 0);                 // mod time
    CSFSWriteLE16(cd, 0x21);              // mod date
    CSFSWriteLE32(cd, crc);
    CSFSWriteLE32(cd, usize);
    CSFSWriteLE32(cd, usize);
    CSFSWriteLE16(cd, (uint16_t)nameData.length);
    CSFSWriteLE16(cd, 0);                 // extra len
    CSFSWriteLE16(cd, 0);                 // comment len
    CSFSWriteLE16(cd, 0);                 // disk number start
    CSFSWriteLE16(cd, 0);                 // internal attrs
    CSFSWriteLE32(cd, 0);                 // external attrs
    CSFSWriteLE32(cd, offset);            // local header offset
    [cd appendData:nameData];
}

// v18：把一段段落字典渲染成 <w:p>…</w:p>。
//
// Word 的字号单位是「半磅」(half-point)，所以 pt × 2。
// 颜色写成 <w:color w:val="FF0000"/>，不带 # 号，否则 Word 会忽略这个属性。
static NSString *CSFSRenderPara(NSDictionary *para, double defaultPt) {
    NSMutableString *out = [NSMutableString string];

    // 段落属性：对齐。
    // 只在确有必要时写 <w:pPr>，避免产出大量空属性块。
    id align = [para objectForKey:kCSFSParaAlign];
    if ([align isKindOfClass:[NSString class]] && [(NSString *)align length] > 0) {
        [out appendFormat:@"<w:pPr><w:jc w:val=\"%@\"/></w:pPr>", align];
    }

    id runs = [para objectForKey:kCSFSParaRuns];
    if (![runs isKindOfClass:[NSArray class]] || [(NSArray *)runs count] == 0) {
        [out appendString:@"<w:r><w:t xml:space=\"preserve\"></w:t></w:r>"];
        return out;
    }

    for (NSDictionary *r in (NSArray *)runs) {
        NSString *text = [r objectForKey:kCSFSRunText];
        if (text.length == 0) continue;

        NSMutableString *rPr = [NSMutableString string];
        if ([[r objectForKey:kCSFSRunBold] boolValue])      [rPr appendString:@"<w:b/><w:bCs/>"];
        if ([[r objectForKey:kCSFSRunItalic] boolValue])    [rPr appendString:@"<w:i/><w:iCs/>"];
        if ([[r objectForKey:kCSFSRunUnderline] boolValue]) [rPr appendString:@"<w:u w:val=\"single\"/>"];

        NSString *color = [r objectForKey:kCSFSRunColor];
        if (color.length == 6) {
            [rPr appendFormat:@"<w:color w:val=\"%@\"/>", color];
        }
        // 字体：同时写 ascii/hAnsi/eastAsia。
        // 中文文档只写 hAnsi 不起作用，Word 会按 eastAsia 走。
        NSString *face = [r objectForKey:kCSFSRunFace];
        if (face.length > 0) {
            NSString *fe = CSFSXMLEscape(face);
            [rPr appendFormat:
                @"<w:rFonts w:ascii=\"%@\" w:hAnsi=\"%@\" w:eastAsia=\"%@\" w:cs=\"%@\"/>",
                fe, fe, fe, fe];
        }
        // 字号：sz 是半磅。只对「与默认不同」的 run 写字号，
        // 否则每个 run 都带 sz，XML 体积翻倍且不利于后续统一改样式。
        id szObj = [r objectForKey:kCSFSRunSize];
        if (szObj) {
            double sz = [szObj doubleValue];
            if (sz > 0 && fabs(sz - defaultPt) > 0.5) {
                long hp = (long)(sz * 2.0 + 0.5);
                [rPr appendFormat:@"<w:sz w:val=\"%ld\"/><w:szCs w:val=\"%ld\"/>", hp, hp];
            }
        }

        if (rPr.length > 0) {
            [out appendFormat:@"<w:r><w:rPr>%@</w:rPr><w:t xml:space=\"preserve\">%@</w:t></w:r>",
                rPr, CSFSXMLEscape(text)];
        } else {
            [out appendFormat:@"<w:r><w:t xml:space=\"preserve\">%@</w:t></w:r>",
                CSFSXMLEscape(text)];
        }
    }
    return out;
}

// v18：正文由段落字典数组渲染。
// 每个元素是 NSMutableDictionary：
//   kCSFSParaRuns  → NSArray<NSMutableDictionary*> 文本片段
//   kCSFSParaAlign → NSString 可选，w:jc 取值（center/right/both）
// defaultPt 取全文出现最多的字号，作为 Normal 的基准，
// 这样「标题比正文大」这件事在 Word 里能被体现出来（标题写 sz，正文继承）。
static BOOL CSFSWriteDocxStyled(NSArray *paras, double defaultPt, NSString *outPath) {
    CSFSCrashTrace("docx18: enter");

    NSMutableString *body = [NSMutableString string];
    for (NSDictionary *p in paras) {
        [body appendString:CSFSRenderPara(p, defaultPt)];
    }
    if (body.length == 0) [body appendString:@"<w:p/>"];

    long defHalfPt = (long)(defaultPt * 2.0 + 0.5);
    if (defHalfPt < 4 || defHalfPt > 400) defHalfPt = 24;   // 兜底 12pt

    NSString *docXml = [NSString stringWithFormat:
        @"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        @"<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">"
        @"<w:body>%@<w:sectPr><w:pgSz w:w=\"11906\" w:h=\"16838\"/>"
        @"<w:pgMar w:top=\"1440\" w:right=\"1440\" w:bottom=\"1440\" w:left=\"1440\"/>"
        @"</w:sectPr></w:body></w:document>",
        body];
    NSString *ctXml =
        @"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        @"<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
        @"<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
        @"<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
        @"<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>"
        @"<Override PartName=\"/word/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml\"/>"
        @"</Types>";
    NSString *relsXml =
        @"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        @"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        @"<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>"
        @"</Relationships>";
    NSString *docRelsXml =
        @"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        @"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        @"<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/>"
        @"</Relationships>";
    // 默认字号改成动态值：原本文本占多数时是 12pt，但若整篇都是大标题，
    // 固定 12pt 会让所有文字都带 sz 覆盖，反而失真。
    NSString *stylesXml = [NSString stringWithFormat:
        @"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        @"<w:styles xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">"
        @"<w:docDefaults><w:rPrDefault><w:rPr>"
        @"<w:rFonts w:ascii=\"Calibri\" w:hAnsi=\"Calibri\" w:eastAsia=\"宋体\" w:cs=\"Calibri\"/>"
        @"<w:sz w:val=\"%ld\"/><w:szCs w:val=\"%ld\"/>"
        @"<w:lang w:val=\"en-US\" w:eastAsia=\"zh-CN\" w:bidi=\"ar-SA\"/>"
        @"</w:rPr></w:rPrDefault>"
        @"<w:pPrDefault><w:pPr><w:spacing w:after=\"80\" w:line=\"300\" w:lineRule=\"auto\"/></w:pPr></w:pPrDefault>"
        @"</w:docDefaults>"
        @"<w:style w:type=\"paragraph\" w:default=\"1\" w:styleId=\"Normal\">"
        @"<w:name w:val=\"Normal\"/><w:qFormat/>"
        @"<w:pPr><w:spacing w:after=\"80\" w:line=\"300\" w:lineRule=\"auto\"/></w:pPr>"
        @"</w:style>"
        @"</w:styles>", defHalfPt, defHalfPt];

    NSMutableData *zipData = [NSMutableData dataWithCapacity:8192];
    NSMutableData *cd = [NSMutableData dataWithCapacity:512];
    CSFSZipAddEntry(zipData, cd, @"[Content_Types].xml",
                    [ctXml dataUsingEncoding:NSUTF8StringEncoding]);
    CSFSZipAddEntry(zipData, cd, @"_rels/.rels",
                    [relsXml dataUsingEncoding:NSUTF8StringEncoding]);
    CSFSZipAddEntry(zipData, cd, @"word/_rels/document.xml.rels",
                    [docRelsXml dataUsingEncoding:NSUTF8StringEncoding]);
    CSFSZipAddEntry(zipData, cd, @"word/styles.xml",
                    [stylesXml dataUsingEncoding:NSUTF8StringEncoding]);
    CSFSZipAddEntry(zipData, cd, @"word/document.xml",
                    [docXml dataUsingEncoding:NSUTF8StringEncoding]);
    CSFSCrashTrace("docx18: parts added");

    uint32_t cdSize = (uint32_t)cd.length;
    uint32_t cdOffset = (uint32_t)zipData.length;
    NSUInteger entryCount = 5;
    [zipData appendData:cd];
    CSFSWriteLE32(zipData, 0x06054b50);
    CSFSWriteLE16(zipData, 0);
    CSFSWriteLE16(zipData, 0);
    CSFSWriteLE16(zipData, (uint16_t)entryCount);
    CSFSWriteLE16(zipData, (uint16_t)entryCount);
    CSFSWriteLE32(zipData, cdSize);
    CSFSWriteLE32(zipData, cdOffset);
    CSFSWriteLE16(zipData, 0);
    CSFSCrashTrace("docx18: eocd done");

    BOOL ok = [zipData writeToFile:outPath atomically:YES];
    CSFS_LOG(@"v18 docx written=%d paras=%lu defPt=%.1f size=%lu",
             (int)ok, (unsigned long)paras.count, defaultPt,
             (unsigned long)zipData.length);
    return ok;
}

static BOOL CSFSWriteDocx(NSArray *lines, NSString *outPath) {
    CSFSCrashTrace("docx: enter");

    NSMutableString *body = [NSMutableString string];
    for (NSString *line in lines) {
        [body appendFormat:@"<w:p><w:r><w:t xml:space=\"preserve\">%@</w:t></w:r></w:p>",
         CSFSXMLEscape(line)];
    }
    if (body.length == 0) [body appendString:@"<w:p/>"];
    NSString *docXml = [NSString stringWithFormat:
        @"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        @"<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">"
        @"<w:body>%@<w:sectPr><w:pgSz w:w=\"11906\" w:h=\"16838\"/></w:sectPr></w:body></w:document>",
        body];
    NSString *ctXml =
        @"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        @"<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
        @"<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
        @"<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
        @"<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>"
        @"<Override PartName=\"/word/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml\"/>"
        @"</Types>";
    NSString *relsXml =
        @"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        @"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        @"<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>"
        @"</Relationships>";
    // word/document.xml 的 rels：把 styles.xml 挂上去。
    //
    // 为什么必须有：不给 document.xml 挂 styles 关系、不给默认字体，
    // Word 会认为这份文档「没有任何样式信息」——这正是用户反馈的
    // 「点『是』恢复之后只剩纯文本、格式全丢」的观感来源。
    // 一份最小可用的 docx 应当带上 Normal 样式与默认字号字体。
    NSString *docRelsXml =
        @"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        @"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        @"<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/>"
        @"</Relationships>";
    // 最小样式表：docDefaults 定默认字号/字体（小四 12pt、宋体+等线回退），
    // 再定义 Normal。没有 docDefaults 时不同 Word 版本回退行为不一致，
    // 中文可能被渲染成日文字形或丢掉中文字体。
    NSString *stylesXml =
        @"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        @"<w:styles xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">"
        @"<w:docDefaults><w:rPrDefault><w:rPr>"
        @"<w:rFonts w:ascii=\"Calibri\" w:hAnsi=\"Calibri\" w:eastAsia=\"宋体\" w:cs=\"Calibri\"/>"
        @"<w:sz w:val=\"24\"/><w:szCs w:val=\"24\"/>"
        @"<w:lang w:val=\"en-US\" w:eastAsia=\"zh-CN\" w:bidi=\"ar-SA\"/>"
        @"</w:rPr></w:rPrDefault>"
        @"<w:pPrDefault><w:pPr><w:spacing w:after=\"80\" w:line=\"300\" w:lineRule=\"auto\"/></w:pPr></w:pPrDefault>"
        @"</w:docDefaults>"
        @"<w:style w:type=\"paragraph\" w:default=\"1\" w:styleId=\"Normal\">"
        @"<w:name w:val=\"Normal\"/><w:qFormat/>"
        @"<w:pPr><w:spacing w:after=\"80\" w:line=\"300\" w:lineRule=\"auto\"/></w:pPr>"
        @"</w:style>"
        @"</w:styles>";

    // 部件顺序有讲究：OPC 规范建议 [Content_Types].xml 放第一个（不是强制，
    // 但所有主流实现都这么做，放第一个对宽松解析器更友好）。
    NSMutableData *zipData = [NSMutableData dataWithCapacity:4096];
    NSMutableData *cd = [NSMutableData dataWithCapacity:512];
    CSFSZipAddEntry(zipData, cd, @"[Content_Types].xml",
                    [ctXml dataUsingEncoding:NSUTF8StringEncoding]);
    CSFSCrashTrace("docx: ct added");
    CSFSZipAddEntry(zipData, cd, @"_rels/.rels",
                    [relsXml dataUsingEncoding:NSUTF8StringEncoding]);
    CSFSZipAddEntry(zipData, cd, @"word/_rels/document.xml.rels",
                    [docRelsXml dataUsingEncoding:NSUTF8StringEncoding]);
    CSFSZipAddEntry(zipData, cd, @"word/styles.xml",
                    [stylesXml dataUsingEncoding:NSUTF8StringEncoding]);
    CSFSZipAddEntry(zipData, cd, @"word/document.xml",
                    [docXml dataUsingEncoding:NSUTF8StringEncoding]);
    CSFSCrashTrace("docx: parts added");

    // ── End of central directory ──
    uint32_t cdSize = (uint32_t)cd.length;
    uint32_t cdOffset = (uint32_t)zipData.length;
    NSUInteger entryCount = 5;
    [zipData appendData:cd];
    CSFSWriteLE32(zipData, 0x06054b50);              // "PK\5\6"
    CSFSWriteLE16(zipData, 0);                       // this disk
    CSFSWriteLE16(zipData, 0);                       // disk with CD
    CSFSWriteLE16(zipData, (uint16_t)entryCount);    // entries on this disk
    CSFSWriteLE16(zipData, (uint16_t)entryCount);    // total entries
    CSFSWriteLE32(zipData, cdSize);
    CSFSWriteLE32(zipData, cdOffset);
    CSFSWriteLE16(zipData, 0);                       // comment length
    CSFSCrashTrace("docx: eocd done");

    // 一次性写出：不用 NSFileHandle 分段写，避免半成品文件
    BOOL ok = [zipData writeToFile:outPath atomically:YES];
    CSFS_LOG(@"v17 docx store-zip written=%d entries=%lu size=%lu",
             (int)ok, (unsigned long)entryCount, (unsigned long)zipData.length);
    return ok;
}

static void CSFS_didSelectCell(id self, SEL _cmd, NSIndexPath *ip) {
    @try {
        if (ip) {
            NSArray *arr = nil;
            SEL cas = NSSelectorFromString(@"channelArray");
            if ([self respondsToSelector:cas]) {
                NSArray *(*gfn)(id, SEL) =
                    (NSArray *(*)(id, SEL))[self methodForSelector:cas];
                arr = gfn(self, cas);
            }
            SEL rowsel = NSSelectorFromString(@"row");
            NSInteger (*rfn)(id, SEL) =
                (NSInteger (*)(id, SEL))[ip methodForSelector:rowsel];
            NSInteger row = rfn(ip, rowsel);
            if (arr && row >= 0 && row < (NSInteger)arr.count) {
                id it = arr[row];
                if ([it respondsToSelector:@selector(actionSheetOperationType)]) {
                    NSInteger (*tfn)(id, SEL) =
                        (NSInteger (*)(id, SEL))[it methodForSelector:@selector(actionSheetOperationType)];
                    if (tfn(it, @selector(actionSheetOperationType)) == kCSFSSaveToFilesId) {
                        CSFS_LOG(@"intercepted panel save-to-files tap (row=%ld)", (long)row);
                        // ── v11：绕开转换链，直接拿文件落盘 ──
                        // v10 实证：re-dispatch 0x78 后原链路静默死亡（无出口、无报错），
                        // 环境里 office 转换链不可靠。而用户此时文档已存在——
                        // ① shareModel.wordExportUrl（didSelect 0x1018d7a48 原生就先读它）
                        // ② docId → Document/DTO.officeFilePath（原始 Word 文件）
                        // 导出式 picker asCopy=YES 由系统复制，无需预拷贝。
                        id sm = nil;
                        SEL smsel = NSSelectorFromString(@"shareManager");
                        if ([self respondsToSelector:smsel]) {
                            id (*sfn)(id, SEL) =
                                (id (*)(id, SEL))[self methodForSelector:smsel];
                            sm = sfn(self, smsel);
                        }
                        id model = nil;
                        NSURL *fileURL = nil;
                        if (sm) {
                            SEL stysel = NSSelectorFromString(@"shareModel");
                            if ([sm respondsToSelector:stysel]) {
                                id (*mfn)(id, SEL) =
                                    (id (*)(id, SEL))[sm methodForSelector:stysel];
                                model = mfn(sm, stysel);
                            }
                        }
                        // ① wordExportUrl
                        if (model && [model respondsToSelector:@selector(wordExportUrl)]) {
                            id (*wfn)(id, SEL) =
                                (id (*)(id, SEL))[model methodForSelector:@selector(wordExportUrl)];
                            id wu = wfn(model, @selector(wordExportUrl));
                            if ([wu isKindOfClass:[NSURL class]]) {
                                fileURL = wu;
                            } else if ([wu isKindOfClass:[NSString class]] &&
                                       [(NSString *)wu length] > 0) {
                                fileURL = [NSURL fileURLWithPath:(NSString *)wu];
                            }
                        }
                        // ② docId → 文档对象 → officeFilePath
                        NSString *docId = nil;
                        if (model && [model respondsToSelector:@selector(docId)]) {
                            id (*dfn)(id, SEL) =
                                (id (*)(id, SEL))[model methodForSelector:@selector(docId)];
                            id dv = dfn(model, @selector(docId));
                            if ([dv isKindOfClass:[NSString class]]) docId = dv;
                        }
                        CSFS_LOG(@"v11 diag wordExportUrl=%@ docId=%@",
                                 fileURL.path ?: @"(nil)", docId ?: @"(nil)");
                        if (fileURL) {
                            // wordExportUrl 已有（转换成功过）：直接落盘
                            CSFS_LOG(@"v11 save directly: %@", fileURL.path);
                            CSFSPresentExportPicker(@[ fileURL ]);
                        } else if (docId.length > 0) {
                            // v12：office 转换链在本环境不可用（fileExist=0 铁证），
                            // 后台找 jsonWordCache → 提取文本 → 本地生成 .docx
                            NSString *docIdCopy = [docId copy];
                            dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                                @try {
                                    NSString *jsonText = CSFSFindJSONTextForDoc(docIdCopy);
                                    if (jsonText.length == 0) {
                                        dispatch_async(dispatch_get_main_queue(), ^{
                                            CSFSToast(@"未找到文档数据，请稍后重试");
                                        });
                                        return;
                                    }
                                    // 诊断：dump 开头帮下一轮精确定位 JSON 结构
                                    NSString *head = jsonText.length > 600
                                        ? [jsonText substringToIndex:600] : jsonText;
                                    CSFS_LOG(@"v12 json head: %@", head);
                                    CSFSCrashTrace("json: loaded, before parse");
                                    NSMutableArray *lines = [NSMutableArray array];
                                    // v18：带样式的段落数组。元素是 NSMutableDictionary，
                                    // 键见 kCSFSParaRuns / kCSFSParaAlign。
                                    // 全 ARC 管理，无手动内存操作（理由见 v18 结构定义处注释）。
                                    NSMutableArray *styledParas = [NSMutableArray array];
                                    // v18 诊断开关：只 dump 一次真实 style，见 CSFSParseSlice 注释
                                    BOOL diagDone = NO;
                                    id parsed = nil;
                                    SEL jsel = NSSelectorFromString(
                                        @"JSONObjectWithData:options:error:");
                                    id (*jfn)(id, SEL, NSData *, NSUInteger, NSError **) =
                                        (id (*)(id, SEL, NSData *, NSUInteger, NSError **))
                                        [NSJSONSerialization methodForSelector:jsel];
                                    @try {
                                        parsed = jfn([NSJSONSerialization class], jsel,
                                                     [jsonText dataUsingEncoding:NSUTF8StringEncoding],
                                                     0, nil);
                                    } @catch (NSException *e) {
                                        CSFS_LOG(@"v12 json parse threw: %@", e.reason);
                                    }
                                    CSFSCrashTrace("json: parsed");
                                    if (parsed) {
                                        // v14：JSON Word 专用提取（实证结构）：
                                        // segments[]页 → segments[]块 → paras[]段 → slices[].text
                                        @try {
                                            if ([parsed isKindOfClass:[NSDictionary class]]) {
                                                id topSegs = ((NSDictionary *)parsed)[@"segments"];
                                                if ([topSegs isKindOfClass:[NSArray class]]) {
                                                    for (id page in topSegs) {
                                                        if (![page respondsToSelector:@selector(objectForKey:)]) continue;
                                                        id blocks = [page objectForKey:@"segments"];
                                                        if (![blocks isKindOfClass:[NSArray class]]) continue;
                                                        for (id block in blocks) {
                                                            if (![block respondsToSelector:@selector(objectForKey:)]) continue;
                                                            // v16：块类型过滤。
                                                            // 实证样本 27 块 = 25 PARA + 1 IMAGE + 1 LINE。
                                                            // IMAGE 块没有 paras（或只有空 slices），不加过滤会
                                                            // 产出空的 <w:p/>，正文里凭空多出空行；
                                                            // LINE 是版式分隔线，同样不该进正文。
                                                            id btype = [block objectForKey:@"type"];
                                                            if ([btype isKindOfClass:[NSString class]] &&
                                                                ![(NSString *)btype isEqualToString:@"PARA"]) {
                                                                continue;
                                                            }
                                                            id paras = [block objectForKey:@"paras"];
                                                            if (![paras isKindOfClass:[NSArray class]]) continue;

                                                            // v18：每个 para 生成一个独立段落，
                                                            // 并把每个 slice 的 style 一并带出来。
                                                            for (id para in paras) {
                                                                if (![para respondsToSelector:@selector(objectForKey:)]) continue;
                                                                id slices = [para objectForKey:@"slices"];
                                                                if (![slices isKindOfClass:[NSArray class]]) continue;

                                                                NSMutableArray *runs =
                                                                    [NSMutableArray arrayWithCapacity:[(NSArray *)slices count]];
                                                                BOOL hasText = NO;
                                                                for (id sl in slices) {
                                                                    NSMutableDictionary *run = CSFSParseSlice(sl, &diagDone);
                                                                    if (!run) continue;
                                                                    NSString *tt = [run objectForKey:kCSFSRunText];
                                                                    NSString *trimmed =
                                                                        [tt stringByTrimmingCharactersInSet:CSFSWhiteSpaceSet()];
                                                                    if (trimmed.length == 0) continue;
                                                                    hasText = YES;
                                                                    [runs addObject:run];
                                                                }
                                                                // 全空白段落直接丢掉（原实现靠 trim 达到同一效果）
                                                                if (!hasText) continue;

                                                                NSMutableDictionary *p =
                                                                    [NSMutableDictionary dictionaryWithCapacity:4];
                                                                [p setObject:runs forKey:kCSFSParaRuns];

                                                                // 段落级对齐
                                                                id just = [para objectForKey:@"justification"];
                                                                if ([just isKindOfClass:[NSString class]]) {
                                                                    NSString *j = [(NSString *)just lowercaseString];
                                                                    // CamScanner 的值可能是枚举名也可能是数值，
                                                                    // 只映射能明确识别的，其余留给 Word 默认。
                                                                    //
                                                                    // 注意 w:jc 的合法取值：
                                                                    //   left / center / right / both / distribute
                                                                    // 不存在 "justify"，写成 justify 会被 Word 忽略。
                                                                    NSString *mapped = nil;
                                                                    if ([j isEqualToString:@"center"] ||
                                                                        [j isEqualToString:@"1"]) {
                                                                        mapped = @"center";
                                                                    } else if ([j isEqualToString:@"right"] ||
                                                                               [j isEqualToString:@"right_align"] ||
                                                                               [j isEqualToString:@"2"]) {
                                                                        mapped = @"right";
                                                                    } else if ([j isEqualToString:@"both"] ||
                                                                               [j isEqualToString:@"justify"] ||
                                                                               [j isEqualToString:@"3"]) {
                                                                        mapped = @"both";
                                                                    }
                                                                    if (mapped) {
                                                                        [p setObject:mapped forKey:kCSFSParaAlign];
                                                                    }
                                                                }
                                                                [styledParas addObject:p];
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } @catch (NSException *e) {
                                            CSFS_LOG(@"v14专用解析 threw: %@", e.reason);
                                        }
                                        if (lines.count == 0) {
                                            // 保底：通用递归收集
                                            CSFSCollectStrings(parsed, lines);
                                        }
                                        CSFS_LOG(@"v18 json parsed, %lu 段带样式",
                                                 (unsigned long)styledParas.count);
                                    } else {
                                        // 非 JSON：原文按行切，生成无样式段落
                                        SEL wcsel2 = NSSelectorFromString(
                                            @"whitespaceAndNewlineCharacterSet");
                                        id (*wcf2)(id, SEL) =
                                            (id (*)(id, SEL))[NSCharacterSet methodForSelector:wcsel2];
                                        id ws2 = wcf2([NSCharacterSet class], wcsel2);
                                        for (NSString *ln in [jsonText componentsSeparatedByString:@"\n"]) {
                                            NSString *t = [ln stringByTrimmingCharactersInSet:ws2];
                                            if (t.length == 0) continue;
                                            NSMutableDictionary *run =
                                                [NSMutableDictionary dictionaryWithCapacity:2];
                                            [run setObject:t forKey:kCSFSRunText];
                                            NSMutableDictionary *p =
                                                [NSMutableDictionary dictionaryWithCapacity:2];
                                            [p setObject:[NSMutableArray arrayWithObject:run]
                                                  forKey:kCSFSParaRuns];
                                            [styledParas addObject:p];
                                            [lines addObject:t];   // 仅用于计数/日志
                                        }
                                    }
                                    if (styledParas.count == 0) {
                                        // 极少数情况：JSON 结构不认识，但文本确实存在。
                                        // 退回 v17 的通用递归收集，保证「至少能导出文字」。
                                        if (lines.count == 0) CSFSCollectStrings(parsed, lines);
                                        for (NSString *t in lines) {
                                            if (t.length == 0) continue;
                                            NSMutableDictionary *run =
                                                [NSMutableDictionary dictionaryWithCapacity:2];
                                            [run setObject:t forKey:kCSFSRunText];
                                            NSMutableDictionary *p =
                                                [NSMutableDictionary dictionaryWithCapacity:2];
                                            [p setObject:[NSMutableArray arrayWithObject:run]
                                                  forKey:kCSFSParaRuns];
                                            [styledParas addObject:p];
                                        }
                                    }
                                    if (styledParas.count == 0) {
                                        dispatch_async(dispatch_get_main_queue(), ^{
                                            CSFSToast(@"文档内容为空，请稍后重试");
                                        });
                                        return;
                                    }
                                    CSFSCrashTrace("json: lines collected");

                                    // v18：统计默认字号。
                                    // 做法：把所有 run 的字号按 1pt 取整做频次统计，取众数。
                                    // 不用「平均值」—— 一篇图文里标题只有几个 run、
                                    // 正文有几十个，平均值会被标题拉高，导致正文被压小。
                                    double defaultPt = 12.0;
                                    {
                                        // 频次表：字号键 → 次数。键用 NSString 存，避免浮点做字典键。
                                        NSMutableDictionary *freq = [NSMutableDictionary dictionary];
                                        for (NSDictionary *pp in styledParas) {
                                            id rs = [pp objectForKey:kCSFSParaRuns];
                                            if (![rs isKindOfClass:[NSArray class]]) continue;
                                            for (NSDictionary *rr in (NSArray *)rs) {
                                                id szObj = [rr objectForKey:kCSFSRunSize];
                                                if (!szObj) continue;
                                                long key = (long)([szObj doubleValue] + 0.5);
                                                if (key < 3 || key > 200) continue;
                                                NSString *k = [NSString stringWithFormat:@"%ld", key];
                                                long cnt = [[freq objectForKey:k] longValue] + 1;
                                                [freq setObject:[NSNumber numberWithLong:cnt]
                                                         forKey:k];
                                            }
                                        }
                                        long bestCnt = 0; long bestKey = 12;
                                        for (NSString *k in freq) {
                                            long c = [[freq objectForKey:k] longValue];
                                            long key = [k longValue];
                                            // 同票时取更小的字号：正文通常是小的那个
                                            if (c > bestCnt || (c == bestCnt && key < bestKey)) {
                                                bestCnt = c; bestKey = key;
                                            }
                                        }
                                        if (bestCnt > 0) defaultPt = (double)bestKey;
                                        CSFS_LOG(@"v18 defaultPt=%.1f (样本 %ld 个 run)",
                                                 defaultPt, bestCnt);
                                    }

                                    // v18：格式提取统计。
                                    // 这是判断「格式有没有真的提取到」的唯一直接依据：
                                    // 若这三个数都是 0，说明字段名对不上，需要看上面的 DIAG dump。
                                    {
                                        long nColor = 0, nBold = 0, nSize = 0, nRun = 0;
                                        for (NSDictionary *pp in styledParas) {
                                            id rs = [pp objectForKey:kCSFSParaRuns];
                                            if (![rs isKindOfClass:[NSArray class]]) continue;
                                            for (NSDictionary *rr in (NSArray *)rs) {
                                                nRun++;
                                                if ([rr objectForKey:kCSFSRunColor]) nColor++;
                                                if ([[rr objectForKey:kCSFSRunBold] boolValue]) nBold++;
                                                if ([rr objectForKey:kCSFSRunSize]) nSize++;
                                            }
                                        }
                                        CSFS_LOG(@"v18 stats: paras=%lu runs=%ld color=%ld bold=%ld size=%ld",
                                                 (unsigned long)styledParas.count,
                                                 nRun, nColor, nBold, nSize);
                                    }

                                    // 文件名前缀：取 docId 前 12 字符。
                                    // v16 修正：原写法在 docIdCopy 为空时 MIN(12,0)=0，
                                    // substringToIndex:0 虽不崩但不该走到这里；
                                    // 这里显式兜底，避免空串进入格式化。
                                    NSString *prefix = docIdCopy.length > 0
                                        ? [docIdCopy substringToIndex:MIN((NSUInteger)12, docIdCopy.length)]
                                        : @"未命名";
                                    NSString *out = [NSTemporaryDirectory()
                                                     stringByAppendingPathComponent:
                                                     [NSString stringWithFormat:@"导出_%@.docx", prefix]];
                                    BOOL ok = CSFSWriteDocxStyled(styledParas, defaultPt, out);
                                    CSFSCrashTrace("json: docx returned");
                                    dispatch_async(dispatch_get_main_queue(), ^{
                                        if (ok) {
                                            CSFSToast(@"Word 已生成，请选择保存位置");
                                            CSFSPresentExportPicker(
                                                @[ [NSURL fileURLWithPath:out] ]);
                                        } else {
                                            CSFSToast(@"生成 Word 文件失败");
                                        }
                                    });
                                } @catch (NSException *e) {
                                    CSFS_LOG(@"v12 background threw: %@", e.reason);
                                    CSFSCrashTrace("json: caught NSException");
                                    dispatch_async(dispatch_get_main_queue(), ^{
                                        CSFSToast(@"生成 Word 文件失败");
                                    });
                                }
                            });
                        } else {
                            CSFS_LOG(@"v12 WARN: no file url & no docId");
                            CSFSToast(@"文件尚未生成，请稍后重试");
                        }
                        return;
                    }
                }
            }
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"v9 didSelect threw: %@", e.reason);
    }
    if (gOrigDidSelectCell) gOrigDidSelectCell(self, _cmd, ip);
}

static void CSFSInstall(void) {
    if (gCSFSInstalled) return;

    @try {
        Class shareManager = NSClassFromString(@"CSShareManager");
        Class activityUtil = NSClassFromString(@"CSActivityUtil");
        // 用户实际走的面板：父类暴露数据源 setter，子类负责业务分派
        Class sheetBase = NSClassFromString(@"ISBlockDiversifiedActionSheetView");
        Class ocrPresenter = NSClassFromString(@"CSOcrResultsBottomExportPresenter");

        if (!shareManager && !activityUtil && !sheetBase && !ocrPresenter) {
            CSFS_LOG(@"target classes not registered yet, will retry");
            return;
        }

        BOOL anyOCR = NO;

        // ── 第零优先级：修掉「转换失败」的网络误判 ────────────────────
        // Reachability 是 app 自带的第三方类（classref 已实证到 name="Reachability"），
        // 只需替换 -currentReachabilityStatus 一处；未置位强制标记时行为完全不变。
        Class reachCls = NSClassFromString(@"Reachability");
        if (reachCls) {
            BOOL hr = CSFSHookInstance(reachCls,
                                       NSSelectorFromString(@"currentReachabilityStatus"),
                                       (IMP)CSFS_currentReachabilityStatus,
                                       (IMP *)&gOrigReachabilityStatus);
            CSFS_LOG(@"Reachability hook=%d", (int)hr);
        } else {
            CSFS_LOG(@"WARN: Reachability 未找到，转换失败可能仍会出现");
        }

        // ── 第一优先级：OCR 结果页导出面板（真机确认的真实路径）──────
        if (sheetBase) {
            BOOL h1 = CSFSHookInstance(sheetBase,
                                       NSSelectorFromString(@"setHorizontallyDataSource:"),
                                       (IMP)CSFS_setHorizontallyDataSource,
                                       (IMP *)&gOrigSetHorizontalDS);
            BOOL h2 = CSFSHookInstance(sheetBase,
                                       NSSelectorFromString(@"setVerticallyListDataSource:"),
                                       (IMP)CSFS_setVerticallyDataSource,
                                       (IMP *)&gOrigSetVerticalDS);
            CSFS_LOG(@"sheet base hooks: horizontal=%d vertical=%d", (int)h1, (int)h2);
            anyOCR = anyOCR || h1 || h2;
        } else {
            CSFS_LOG(@"WARN: ISBlockDiversifiedActionSheetView 未找到，"
                     @"面板数据源 hook 未安装");
        }

        if (ocrPresenter) {
            // 先注入保存动作，再挂点击拦截（顺序反了会调到空方法）
            class_addMethod(ocrPresenter,
                            NSSelectorFromString(@"csfs_doSaveToFiles:"),
                            (IMP)CSFS_doSaveToFiles, "v@:@");
            BOOL h3 = CSFSHookInstance(ocrPresenter,
                                       NSSelectorFromString(@"actionSheetClickItemAndShareWithFileWay:withItemTitle:withAllPage:"),
                                       (IMP)CSFS_clickItemAndShare,
                                       (IMP *)&gOrigClickItem);
            CSFS_LOG(@"ocr presenter click hook=%d", (int)h3);
            anyOCR = anyOCR || h3;
        } else {
            CSFS_LOG(@"WARN: CSOcrResultsBottomExportPresenter 未找到");
        }

        if (shareManager) {
            // ⚠ 这是**唯一**对「导出文档 → Word 分享面板」有效的挂点。
            //   实证：该面板的数据流是
            //     -showShareView → -showOfficeShareView → -officeFileShareViewData
            //     → [CSSheetUtil showSingleSheetWithHeadConfig:dataList:...]
            //   数组直接作为参数传给面板，**不经过任何 dataSource setter**
            //   （setVerticallyListDataSource: 全 App 只有 2 处调用，都在别处）。
            //   所以这条 hook 必须装上，否则任何改动都不会体现在界面上。
            BOOL hOfsvd = CSFSHookInstance(shareManager,
                             @selector(officeFileShareViewData),
                             (IMP)CSFS_officeFileShareViewData,
                             (IMP *)&gOrigOfficeFileShareViewData);
            CSFS_LOG(@"★★★ officeFileShareViewData hook=%d ★★★（这是 Word 面板的唯一入口）",
                     (int)hOfsvd);

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

        // ── v6 路径探针安装（诊断期，定位后随探针函数一起删）──────────
        Class wordBtn = NSClassFromString(@"CSJsonWordEditBottomView");
        if (wordBtn) {
            SEL selEWA = NSSelectorFromString(@"exportWordAction");
            BOOL inst = CSFSHookInstance(wordBtn, selEWA,
                                         (IMP)CSFS_exportWordAction,
                                         (IMP *)&gOrigExportWordAction);
            if (!inst) {
                // exportWordAction 可能是类方法（+），退回 class_getClassMethod
                Method cm = class_getClassMethod(wordBtn, selEWA);
                if (cm) {
                    gOrigExportWordAction = (void (*)(id, SEL))method_setImplementation(cm, (IMP)CSFS_exportWordAction);
                    CSFS_LOG(@"P1 hooked +[CSJsonWordEditBottomView exportWordAction] orig=%p",
                             gOrigExportWordAction);
                } else {
                    CSFS_LOG(@"P1 WARN: exportWordAction 方法不存在（实例+类都找不到）");
                }
            }
        } else {
            CSFS_LOG(@"P1 WARN: CSJsonWordEditBottomView 未找到");
        }

        if (shareManager) {
            BOOL p2 = CSFSHookInstance(shareManager,
                                       NSSelectorFromString(@"showShareView"),
                                       (IMP)CSFS_showShareView,
                                       (IMP *)&gOrigShowShareView);
            CSFS_LOG(@"P2 showShareView hook=%d", (int)p2);

            BOOL p3 = CSFSHookInstance(shareManager,
                                       NSSelectorFromString(@"showOfficeShareView"),
                                       (IMP)CSFS_showOfficeShareView,
                                       (IMP *)&gOrigShowOfficeShareView);
            CSFS_LOG(@"P3 showOfficeShareView hook=%d", (int)p3);
        }

        Class vcBase = NSClassFromString(@"UIViewController");
        if (vcBase) {
            BOOL p4 = CSFSHookInstance(vcBase,
                                       NSSelectorFromString(@"presentViewController:animated:completion:"),
                                       (IMP)CSFS_presentVC,
                                       (IMP *)&gOrigPresentVC);
            CSFS_LOG(@"P4 present hook=%d", (int)p4);
        }

        // ── v7 真面板挂点 ────────────────────────────────────────────
        // CSShareCompositionalMainWaysSectionAdapter.channelArray 是
        // 「导出文档」分享面板（CSSharePanellViewController）条目的唯一来源。
        Class mainWays = NSClassFromString(@"CSShareCompositionalMainWaysSectionAdapter");
        if (mainWays) {
            BOOL h7 = CSFSHookInstance(mainWays,
                                       NSSelectorFromString(@"channelArray"),
                                       (IMP)CSFS_channelArray,
                                       (IMP *)&gOrigChannelArray);
            CSFS_LOG(@"★★★ v7 channelArray hook=%d ★★★（真面板条目来源）", (int)h7);
        } else {
            CSFS_LOG(@"v7 WARN: CSShareCompositionalMainWaysSectionAdapter 未找到");
        }

        // ── v9 面板点击拦截 ──────────────────────────────────────────
        if (mainWays) {
            BOOL h9 = CSFSHookInstance(mainWays,
                                       NSSelectorFromString(@"didselectCellWithIndexPath:"),
                                       (IMP)CSFS_didSelectCell,
                                       (IMP *)&gOrigDidSelectCell);
            CSFS_LOG(@"v9 didSelectCell hook=%d", (int)h9);
        }

        gCSFSInstalled = (gOrigOfficeFileShareViewData != NULL) || anyOCR;
        CSFS_LOG(@"install finished, installed=%d (ocrPath=%d)", (int)gCSFSInstalled, (int)anyOCR);
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

// ── 自证信号 ─────────────────────────────────────────────────────────
// 前四轮反馈全是「装上了但完全没反应」，而我一直无法区分：
//   a) dylib 根本没被 dyld 加载（签名被拒 / 路径解析失败）—— 代码一行都没跑；
//   b) dylib 加载了，但 hook 挂点 / 条目渲染出了问题。
// 这两种情况在面板上看起来一模一样，只能靠用户翻沙盒日志区分，成本太高。
//
// 所以加这个「启动横幅」：App 启动完成 3 秒后弹一次 toast。
//   看到 toast   → dylib 确定已加载，问题在 hook / 渲染层，继续看 CSFS.log；
//   看不到 toast → dyld 压根没加载本 dylib，问题在装载层（签名/路径），
//                  hook 代码写得再对也不会执行。
// 每次 App 冷启动都会弹一次。诊断结束后这行可以删掉。
static void CSFSShowLoadedBanner(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        CSFSToast(@"[补丁v5] 已加载 ✓");
        CSFS_LOG(@"loaded banner shown (启动自证信号已弹出)");
    });
}

__attribute__((constructor))
static void CSFSEntry(void) {
    @try {
        // 版本横幅：装了新版之后，第一件事就是看这行。
        // 日志文件位置见 CSFSLogToFile 内注释（Documents/CSFS.log）。
        CSFS_LOG(@"==========================================================");
        CSFS_LOG(@"CamScannerSaveToFiles v5 loaded (build %s %s)", __DATE__, __TIME__);
        CSFS_LOG(@"日志位置：App 沙盒 Documents/CSFS.log（用「文件」App 可取）");
        CSFS_LOG(@"==========================================================");
        // 启动自证信号：见 CSFSShowLoadedBanner 注释。
        CSFSShowLoadedBanner();
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