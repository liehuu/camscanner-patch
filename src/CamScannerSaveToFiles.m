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
// v24：前置声明。
// 读取导出面板开关的实现放在文件后半（它依赖 CSFSValue / CSFSBoolValue），
// 而 exportWordAction 的 hook 在更早的位置 —— C 没有 hoisting，必须先声明。
static void CSFSReadOptionsFromBottomView(id bottomView);
// v31：同理。清零函数也依赖后面那些全局变量，必须先声明。
// decl_order.py 会把这条算作「定义」，所以必须排在下面的首次使用之前。
static void CSFSResetOptionState(void);

static void CSFS_exportWordAction(id self, SEL _cmd) {
    @try {
        CSFS_LOG(@"P1 exportWordAction hit (%@)", NSStringFromClass([self class]));
        // v31：**先进批次边界清零，再读开关**。
        //
        // 顺序不能反。真机日志（同一进程两次导出）：
        //   第一次 勾选 → mgr 给 1 → merged 1
        //   第二次 取消 → mgr 给 0 → merged 仍是 1   ← 用户看到「选不选都删」
        // 原因是 v27 的 OR 合并跨批次累积。
        // 只清一次不够：必须每次导出都清，因为用户可能在同一份文档上
        // 反复改勾选再导出。
        CSFSResetOptionState();
        // v24：在这里读三个开关。
        // 这是唯一能拿到面板 _originalData（CSOcrPage）的时机 ——
        // 后续解析在后台线程跑，那时面板可能已经销毁。
        CSFSReadOptionsFromBottomView(self);
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
// v32：纯空白 run 的「目标宽度」（页面像素，直接来自 slice.width）。
//
// 为什么必须带这个值：空格 slice 的 text 只是一个 " "，但它在预览里
// 可能是一条横跨十几个字符宽的下划线（合同填空线）。
// 只输出一个空格 → Word 里的下划线只有一个空格那么长，明显不够。
// slice 自己的 width 才是这条线真正的像素宽度，所以把它带进 run，
// 渲染时按「宽度 ÷ 单空格宽」展开成足够多的空格，下划线自然就够长了。
static NSString *const kCSFSRunSpaceW  = @"sw";
// v35：标记「这个空白 run 位于段落末尾」。
// 段尾空白与行中空白的处理**必须分开**：
//   · 行中空白要保留断行点（普通 U+0020），否则 Word 会在一个
//     超长不可断块里找不到折行位置，把断点提前到段落开头，
//     首行内容极少 → jc=both 把首行字距撑成两三倍。
//   · 段尾空白要换成 U+00A0，否则 Word 会把行尾空格连同它的
//     下划线一起裁掉，填空线整条消失（v33 的结论，仍然有效）。
static NSString *const kCSFSRunTail    = @"tail";
// 段落的键
static NSString *const kCSFSParaRuns     = @"runs";
static NSString *const kCSFSParaAlign    = @"jc";
// v21：图片段落。
// 一个段落字典如果带 kCSFSParaImage，就不是文段而是图片段，
// CSFSRenderPara 会输出 <w:drawing> 而不是 <w:r><w:t>。
static NSString *const kCSFSParaImage    = @"img";
static NSString *const kCSFSImgData      = @"d";   // NSData 图片原始字节
static NSString *const kCSFSImgExt       = @"e";   // @"png" / @"jpeg" / @"gif"
static NSString *const kCSFSImgPxW       = @"w";   // 像素宽（NSNumber）
static NSString *const kCSFSImgPxH       = @"h";   // 像素高（NSNumber）
static NSString *const kCSFSImgName      = @"n";   // media/imageN.ext 里的 N

// v22：可疑图片段标记。
//
// 场景：手写转文字之后，识别结果可能**不在**图块里，而是落在隔壁的文字块上。
// 此时图块自身抠不出文字，按「无文字就出图」的规则仍会把手写图片贴进去 ——
// 用户看到的就是「文字有了，手写图还在」。
//
// 处理办法是**延后判定**：先把这类图块标成可疑、照常入列，
// 等全文解析完再问一句「本文档到底有没有手写识别成果」
// （imgText>0 或 sliceTextWin>0）。有 → 证明用户开了手写转文字，
// 这些可疑图就是与该文字重复的底图，丢掉；没有 → 用户没识别，
// 图本身就是内容，保留。
//
// 用「本文档有没有识别成果」来推断模式，比猜 image_category 的取值稳，
// 也不需要知道导出面板上那个开关到底是什么。
static NSString *const kCSFSParaImgSuspect = @"hws";

// ── v24：段落版式（全部来自 JSON 自己的 para 字段，不再拍脑袋）
//
// 实证来源是类和 ivars，不是我猜的：
//   CSOcrPageSegmentPara  → _indent_first_line / _indent_left / _indent_right
//                           _indent_hanging / _tabs / _line_gap
//                           _paragraph_gap / _paragraph_gap_before
//                           _justification / _mostFrequentFontSize
//   CSOcrPageSegmentParaSlice → _add_tabstop / _position
// 这些名字就是 JSON 键名（snake_case），和已经验证过的
// paras / slices / stype / text / image_category 同一套命名。
//
// v23 的错误正是忽略了它们：自己硬编码 200 字符缩进，
// 又把 slice 首尾直接相接 —— 于是「每段都缩进」且「字段全粘连」。
static NSString *const kCSFSParaIndFL    = @"fl";    // 首行缩进（原始值，单位待定）
static NSString *const kCSFSParaIndL     = @"il";    // 左缩进
static NSString *const kCSFSParaIndR     = @"ir";    // 右缩进
static NSString *const kCSFSParaIndH     = @"ih";    // 悬挂缩进
static NSString *const kCSFSParaFloat    = @"fb";    // floating_box：浮动框，不参与缩进
static NSString *const kCSFSParaTabs     = @"tabs";  // 制表位数组（已归一为 twips）
static NSString *const kCSFSParaLineGap  = @"lg";    // 行距
static NSString *const kCSFSParaGapBef   = @"gb";    // 段前
static NSString *const kCSFSParaBasePt   = @"bp";    // mostFrequentFontSize
static NSString *const kCSFSParaRenderL  = @"rl";    // para_render_left（横向基准）
static NSString *const kCSFSRunTab       = @"tab";   // 该 run 前要插 <w:tab/>

// ── v24：导出面板三个开关
//
// 实证：CSOcrPage 的 ivars 里正好有这三个 BOOL，
// 而 CSJsonWordEditBottomView._originalData 的类型就是 CSOcrPage：
//   _hideWrittenImage    B   → 面板「去除手写」
//   _hideStampImage      B   → 面板「去除印章」
//   _handWrittenToImage  B   → 面板「手写转文字」（YES=保留成图）
// 文案侧也一一对应：cs_651_handwrite_01/02/03。
//
// 以前完全没读这三个值，所以用户勾了「去除手写 / 去除印章」也照样输出，
// 这就是「选中了导出来并没有去除」的全部原因。
static BOOL gCSFSHideWritten = NO;
static BOOL gCSFSHideStamp   = NO;
static BOOL gCSFSHandToImage = NO;
static BOOL gCSFSOptKnown    = NO;   // 是否成功读到过（用于日志区分「没读到」和「读到 NO」）
static NSString *gCSFSOptSrc = nil;  // 从哪读到的：page / json / none

// ── v31：每次导出前必须把这些状态清零 ────────────────────────────────────
//
// 真机日志（CSFS.log 11:12 与 11:13 两次导出，同一进程）：
//
//   第一次（勾了去除手写 + 去除印章）：
//     v29 mgr opts: hideWritteImage=有(1) hideStampImage=有(1) | merged w=1 s=1
//   第二次（用户取消勾选，两个都是 0）：
//     v29 mgr opts: hideWritteImage=有(0) hideStampImage=有(0) | merged w=1 s=1
//                                                                        ^^^^^
//   Manager 明明给出了 0，merged 还是 1 —— 用户看到的就是
//   「选不选都没用，都是去除状态」。
//
// 根因是 v27 引入的 OR 合并语义少了一半：
//   OR 是为**同一批次内多来源**设计的（Manager 说 1、同步落后的副本说 0 →
//   信 Manager 的 1）。但它是静态全局，没有「批次」概念，
//   于是上一批的 1 会一直留到下一批，任何一次勾选都变成永久生效。
//
// 修法不是把 OR 改成「最后写入者」——那会退回 v24～v28 的失败态
// （副本同步落后，Manager 的 1 被盖成 0）。
// 而是**在批次边界清零**：每次 exportWordAction 进来自先 reset，
// 然后在本次批次内照旧 OR。两个语义互不干扰。
//
// 注意：不能只清 hide*。seen / handToResolved / optSrc 若不清，
// 「本次有没有读到」的判断会沿用上一批的结论；
// scale 与 layout 也是每次导出重新抓更安全（换页、换文档都会变）。
static void CSFSResetOptionState(void);

// ── v29：开关的**真身**在 CSImageToJsonManager，而且属性名少一个 n ────────
//
// v24～v28 五轮全部失败，最终用三路静态分析定死了根因，两条都致命：
//
// 【错一】属性名拼写不同 —— 这是最要命的一条
//   反汇编 -updateCategoryListViewItemsWithShowFormula:showHandToPrint:
//          showRemoveHand:showRemoveSignet:... 得到：
//
//     1012e4124: bl STUB[hideWrittenImage]      ; 从 Document 读：Writ**t**en
//     1012e414c: bl STUB[setHideWritteImage:]   ; 写到 Manager：Writ**t**e
//
//   两处只差一个 n。名字池里两个都真实存在：
//     hideWrittenImage / setHideWrittenImage:   ← CSOcrPage、Document 用（完整拼写）
//     hideWritteImage  / setHideWritteImage:    ← CSImageToJsonManager 用（少一个 n）
//   前五轮读的一直是完整拼写，落在 Manager 上就永远是 nil →
//   日志里 optKnown=0 seen(w/s/h)=000，五个版本一次没变过。
//
// 【错二】读的对象不对
//   Manager 上的 setter 只被这几个方法写：
//     CSJsonWordEditAdapterManager -updateCategoryListViewItemsWith...
//     CSNewWordEditContainerView   -updateCategoryListViewItemsForWordWith...
//     CSPageReadingAdapterManager  -updateCategoryListViewItemsWith...
//     CSDebugWordRenderViewController -startRenderWithPageID:
//   —— 全是「面板选项变化」时同步进来，即 Manager 持有的才是当前生效值。
//   而真正执行删除的是 Manager 自己的：
//     -removeHandWritten:document:
//     -removeHiddenImagesInSegments:document:
//     -removeHandwrittenFormula:document:
//   入口是 -jsonRemovedHiddenImage:document:，它按开关决定调哪几个。
//
//   所以导出时不该自己解析 JSON 去猜哪些块是手写/印章，
//   而应当把开关**回写**给 Manager，让 app 用它自己的删除逻辑处理 ——
//   这也正是「app 里已经有转换代码，直接调它」的正确落点。
//
// 本文件用下面两个函数按真实拼写读写 Manager，两个名字都试，
// 谁存在用谁（拼写差异只在这一处收口，其余代码不必知道）。
static const char *kCSFSMgrHideWritten[] = { "hideWritteImage", "hideWrittenImage", NULL };
static const char *kCSFSMgrHideStamp[]   = { "hideStampImage", "hideStampImage", NULL };
static const char *kCSFSMgrHasWritten[]  = { "hasWritteImage", "hasWrittenImage", NULL };

// 取 app 单例 CSImageToJsonManager。
// 既试 defaultManager 也试 sharedManager 也试 new ——
// 反汇编显示调用点用的是 +defaultManager（STUB[defaultManager]），
// 但单例命名在不同版本可能改，三个都试一遍成本极低。
static id CSFSImageToJsonManager(void) {
    static id cached = nil;
    static BOOL tried = NO;
    if (tried) return cached;
    tried = YES;
    @try {
        Class cls = NSClassFromString(@"CSImageToJsonManager");
        if (!cls) {
            CSFS_LOG(@"v29 mgr: CSImageToJsonManager 类不存在");
            return nil;
        }
        for (NSString *selName in @[@"defaultManager", @"sharedManager", @"sharedInstance"]) {
            SEL s = NSSelectorFromString(selName);
            if (![cls respondsToSelector:s]) continue;
            IMP imp = [cls methodForSelector:s];
            if (!imp) continue;
            id (*fn)(id, SEL) = (id (*)(id, SEL))imp;
            id v = fn((id)cls, s);
            if (v) {
                cached = v;
                CSFS_LOG(@"v29 mgr: 从 +%@ 拿到 %@", selName, NSStringFromClass([v class]));
                break;
            }
        }
        if (!cached) {
            // 兜底：alloc/init（个别单例的 +defaultManager 是懒加载，
            // 但万一没有这个类方法，直接造一个也能读当前值）
            SEL initSel = NSSelectorFromString(@"init");
            if ([cls instancesRespondToSelector:initSel]) {
                cached = [[cls alloc] init];
                CSFS_LOG(@"v29 mgr: 兜底 alloc/init 得到 %@", NSStringFromClass([cached class]));
            }
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"v29 mgr threw: %@", e.reason);
    }
    return cached;
}

// 按名字表依次尝试读取 BOOL 属性。返回 YES/NO 表示取到的值，
// found 通过指针返回「是否真的读到了」（区分「读到 NO」和「没这个属性」）。
static BOOL CSFSReadBoolFrom(id obj, const char *names[], BOOL *found) {
    if (found) *found = NO;
    if (!obj) return NO;
    for (int i = 0; names[i]; i++) {
        NSString *nm = [NSString stringWithUTF8String:names[i]];
        SEL s = NSSelectorFromString(nm);
        if (![obj respondsToSelector:s]) continue;
        @try {
            IMP imp = [obj methodForSelector:s];
            if (!imp) continue;
            BOOL (*fn)(id, SEL) = (BOOL (*)(id, SEL))imp;
            BOOL v = fn(obj, s);
            if (found) *found = YES;
            return v;
        } @catch (NSException *e) {
            CSFS_LOG(@"v29 read %@ threw: %@", nm, e.reason);
        }
    }
    return NO;
}

// 按名字表依次尝试写 BOOL 属性。返回是否成功写入过一个。
static BOOL CSFSWriteBoolTo(id obj, const char *names[], BOOL value) {
    if (!obj) return NO;
    for (int i = 0; names[i]; i++) {
        NSString *getter = [NSString stringWithUTF8String:names[i]];
        NSString *setterName = [NSString stringWithFormat:@"set%@%@:",
                                [[getter substringToIndex:1] uppercaseString],
                                [getter substringFromIndex:1]];
        SEL s = NSSelectorFromString(setterName);
        if (![obj respondsToSelector:s]) continue;
        @try {
            IMP imp = [obj methodForSelector:s];
            if (!imp) continue;
            void (*fn)(id, SEL, BOOL) = (void (*)(id, SEL, BOOL))imp;
            fn(obj, s, value);
            return YES;
        } @catch (NSException *e) {
            CSFS_LOG(@"v29 write %@ threw: %@", setterName, e.reason);
        }
    }
    return NO;
}

// ── v27：开关「多来源合并」而不是「先找到谁就信谁」 ────────────────────
//
// v25 的错：CSFSPullOptions 里 `if (!hw && !st && !hi) return NO;`
// 只要目标对象**有**这三个字段就 return YES，于是
// CSFSReadOptionsFromBottomView 的第一个来源 bottomView.originalData
// 一旦带上这三个字段（哪怕全是 NO），立刻短路返回，
// v25 特意新加的 context.allPages 分支根本执行不到。
// 用户勾了却导出一模一样 —— 因为它读的是 originalData 这份**未同步的副本**。
//
// 改法：每个来源各自记录，最后合并。
//
// 但**三个开关的合并方向不一样**，不能用同一套规则 ——
// 这是语义问题，不是实现细节：
//
//   hideWrittenImage / hideStampImage  语义是「删掉某类内容」
//       → 合并取 OR（任一来源说删 → 就删）。
//         读到多份说法相反，说明读到的是同步落后的副本；
//         此时按「用户已经明确要求删」执行，才符合他在面板上的动作。
//         代价是需要「少删」偏保守 —— 但用户勾了就是要删，不删才是没生效。
//
//   handWrittenToImage  语义是「保留手写成图」（与上面方向相反）
//       → 合并取**最后一份读到明确的来源**，且在只有 NO 时才确认为 NO。
//         不能取 OR：OR 会让「任何一份副本残留的 YES」把用户这次的
//         「手写转文字」选择压掉，等于悄悄关掉 v22 实测可用的那条路。
//
// 一次拿到所有来源后再定，所以先存「是否见过」与「最后一份的值」。
static BOOL gCSFSSeenWritten = NO;   // 任一来源明确读到 hideWrittenImage 的存在
static BOOL gCSFSSeenStamp   = NO;
static BOOL gCSFSSeenHandTo  = NO;
static BOOL gCSFSHandToResolved = NO; // handWrittenToImage 是否已有确定值

// ═════════════════════════════════════════════════════════════════════
// v25：页面级版式上下文
//
// 为什么需要：App 的排版数值全是「渲染坐标」，必须先乘页面缩放比
// 才能变成 pt。这个换算是从 -[CSOcrPage scale] 反汇编出来的原文：
//
//     double s = 1.0;
//     double rw = self.renderWidth;
//     if (rw > 0) { float pw = self.page_size.width;
//                   if (pw > 0) s = rw / (double)pw; }
//     return s;
//
// 另外两个全局偏好（CSITextEngineSettings）会整体改变字号和行距：
//   fontSizeMode  0/1/2  → 字号 +0 / -1 / +1 pt
//   lineSpaceMode 0/1/2  → 行距倍数 +0 / -0.25 / +0.25
// 反汇编证据：-[CSITextEngineSettings caculateFontSizeWithOriginalFontSize:]
//             -[... caculateLineHeightMultipleWithOriginalLineHeightMultiple:]
// 这两个值不读，预览和导出就永远差一档 —— 跟段落字段读没读无关。
// ═════════════════════════════════════════════════════════════════════
static double  gCSFSPageScale     = 0.0;   // renderWidth / page_size.width，0 = 未知
static const char *gCSFSPageScaleSrc = "-";  // v28：scale 从哪来的（page.scale / computed）
static double  gCSFSPageWidth     = 0.0;   // page_size.width（原始像素）
static double  gCSFSRenderWidth   = 0.0;
static NSInteger gCSFSFontSizeMode  = 0;
static NSInteger gCSFSLineSpaceMode = 0;
static BOOL    gCSFSAiBeautify    = NO;
static NSString *gCSFSPageSrc     = nil;

// v32：全篇被按 width 撑开的空白 run 数（空格 / 填空下划线）。
// 必须放在文件级：统计日志在 CSFSWriteDocxStyled 里，不在 CSFSRenderPara 内，
// 局部 static 取不到 —— 上一轮就是漏了这个，编译会直接报未声明。
// 它属于「一次导出应该重新算」的状态，所以要在下面的重置里清零，
// 否则同一进程导出两次时，第二次的统计会混进第一次的计数。
static long gCSFSSpaceExpandRuns  = 0;
// 上面那个的日志节流计数（每条导出最多打 3 条明细）。
static long gCSFSSpaceExpandLogs  = 0;
// v33：其中换成 NBSP 的下划线空白 run 数。
// 单列的原因是它能一眼回答「线到底画出来了没有」：
// 如果 gCSFSUnderSpaceRuns == 0，而用户仍看到缺线，
// 说明问题在「下划线属性没读到」，不在「Word 裁行尾空格」。
static long gCSFSUnderSpaceRuns   = 0;

// v33：全文正文的字体名，作为「纯空白 run 继承不到邻居」时的兜底。
//
// 为什么必须兜底：styles.xml 的 docDefaults 写的是
//   <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="宋体"/>
// 而空格 U+0020 属 ASCII 区 → Word 按 **Calibri** 渲染。
// Calibri 的空格宽约 0.226em，宋体是 0.5em —— 差一半。
// 纯空白 run 自己的 face 拿不到、邻居也没有（整段就是一条填空线）时，
// 就会掉到这个 Calibri 上，下划线长度直接腰斩。
// 记下全文实际用的正文字体，这种情况就用它，而不是让 Word 用默认西文字体。
static NSString *gCSFSBodyFace   = nil;

// v31：批次边界清零。详见 gCSFSHideWritten 上方 v31 那段注释。
//
// 只清「一次导出应该重新算」的状态，不动永久配置类变量。
// 顺序无所谓，但**必须每个变量都清**：
// 漏一个就会留下「上一批的结论」，而这类残留恰好是最难从日志上看出来的
// —— 它会表现为「日志里 Manager 明明给了 0，输出却还是删掉了」。
static void CSFSResetOptionStateImpl(void) {
    gCSFSHideWritten = NO;
    gCSFSHideStamp   = NO;
    gCSFSHandToImage = NO;
    gCSFSOptKnown    = NO;
    gCSFSOptSrc      = nil;
    gCSFSSeenWritten = NO;
    gCSFSSeenStamp   = NO;
    gCSFSSeenHandTo  = NO;
    gCSFSHandToResolved = NO;
    gCSFSPageSrc     = nil;
    // 版式上下文同样每次重抓：换页 / 换文档后 scale 与全局偏好都会变，
    // 沿用上一次的值会让缩进按错误的分母算。
    gCSFSPageScale    = 0.0;
    gCSFSPageScaleSrc = "-";
    gCSFSPageWidth    = 0.0;
    gCSFSRenderWidth  = 0.0;
    gCSFSFontSizeMode  = 0;
    gCSFSLineSpaceMode = 0;
    gCSFSAiBeautify    = NO;
    // v32：空格展开计数也按批次算，否则第二次导出的统计会把第一次混进来。
    gCSFSSpaceExpandRuns = 0;
    gCSFSSpaceExpandLogs = 0;
    gCSFSUnderSpaceRuns  = 0;
    gCSFSBodyFace        = nil;
}

// 对外入口：带一行日志，便于在真机上确认「确实重置了」。
// 没有这行日志，「开关为什么不生效」和「开关重置了吗」在日志上无法区分。
static void CSFSResetOptionState(void) {
    CSFSResetOptionStateImpl();
    CSFS_LOG(@"v31 reset: 导出批次状态已清零（hideWritten/hideStamp/handToImage/"
             @"seen/scale/layout）—— 上一批的勾选不会渗到这一批");
}

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

// ═════════════════════════════════════════════════════════════════════
// v33：下划线单独一套判据，不能复用 CSFSBoolValue。
//
// font_attribute.underline 的取值在 App 内部是**下划线样式**，不是布尔：
// UIKit 的 NSUnderlineStyle 是 NSUnderlineStyleSingle=1、Thick=2、Double=9，
// 序列化成 JSON 后完全可能是 "single" / "thick" / "double" 这类字符串。
// 而 CSFSBoolValue 只认 "1"/"true"/"yes" —— 于是 "single" 被判成 NO，
// 下划线属性被静默丢弃。这就是「本来有下划线的空格，你只有空格」。
//
// 反过来，明确的否定词（0/false/no/none）必须判 NO，
// 否则所有带 font_attribute 的 run 都会画上下划线。
// ═════════════════════════════════════════════════════════════════════
static BOOL CSFSUnderlineValue(id v) {
    if (!v) return NO;
    if ([v isKindOfClass:[NSNumber class]]) {
        return ([(NSNumber *)v longValue] != 0);
    }
    if ([v isKindOfClass:[NSString class]]) {
        NSString *s = [(NSString *)v lowercaseString];
        if (s.length == 0) return NO;
        if ([s isEqualToString:@"0"] || [s isEqualToString:@"false"] ||
            [s isEqualToString:@"no"]  || [s isEqualToString:@"none"] ||
            [s isEqualToString:@"nil"] || [s isEqualToString:@"null"]) {
            return NO;
        }
        return YES;
    }
    return NO;
}

// ═════════════════════════════════════════════════════════════════════
// v34：这个字体名是不是「中文（东亚）字体」。
//
// 只为一件事存在：判断空白 run 能不能用它算 0.5em。
//
// 背景是实测出来的，不是猜：v33 导出的 document.xml 里 47 个空白 run
// 有 43 个写着 `w:ascii="Calibri"`。空格 U+0020 是 ASCII 字符，Word
// 严格按 w:ascii 取字形 —— Calibri 的空格只有 0.226em，
// 中文宋体是 0.5em，**差 2.2 倍**。v33 按 0.5em 算出 11 个空格，
// Word 里只占 26pt，而 slice.width 是 56pt —— 这就是「还是不够长」。
//
// 而中文汉字在 Calibri 里没有字形，Word 会自己 fallback 到宋体，
// 所以**汉字看着是正常的，只有空格被悄悄压扁了** —— 这正是这个缺陷
// 从 v32 到 v33 两轮都没被看出来的原因。
// ═════════════════════════════════════════════════════════════════════
static BOOL CSFSIsCJKFace(NSString *f) {
    if (![f isKindOfClass:[NSString class]] || f.length == 0) return NO;

    // 1) 字体名本身带汉字：宋体 / 仿宋 / 楷体 / 黑体 / 微软雅黑 …
    for (NSUInteger i = 0; i < f.length; i++) {
        unichar ch = [f characterAtIndex:i];
        if ((ch >= 0x2E80 && ch <= 0x9FFF) ||   // CJK 部首 ~ 统一表意文字
            (ch >= 0xF900 && ch <= 0xFAFF) ||   // CJK 兼容表意文字
            (ch >= 0xFF00 && ch <= 0xFFEF)) {   // 全角形式
            return YES;
        }
    }

    // 2) 拼音名：SimSun / NSimSun / Songti SC / STFangsong / PingFang SC …
    NSString *l = [f lowercaseString];
    static NSString *const kStems[] = {
        @"song", @"sun", @"kai", @"fang", @"hei", @"ming",
        @"pingfang", @"yuanti", @"libian", @"hannoto", @"notosanscjk",
        @"notoserifcjk", @"sourcehanserif", @"sourcehansans", @"msung", @"nsimsun"
    };
    for (NSUInteger i = 0; i < sizeof(kStems) / sizeof(kStems[0]); i++) {
        if ([l rangeOfString:kStems[i]].location != NSNotFound) return YES;
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

// ─────────────────────────────────────────────────────────────────────
// v19：统一取值 + 结构 dump（修 v18 的致命缺陷）
//
// v18 为什么什么都没导出来（已用主二进制静态分析证实）：
//   slice 的 style 属性类型编码是
//       T@"CSTranslateRawPageSegmentParaSliceStyle",&,N,V_style
//   即 style 是一个**模型对象**，不是 NSDictionary。
//   v18 却写 [style objectForKey:@"font_color"] —— 对象上没有
//   objectForKey:，respondsToSelector 返回 NO，直接走「no style」分支
//   返回纯文本 run。表现与 v17 一模一样，看不出是两回事。
//
//   而 JSON 走 NSJSONSerialization 得到字典，走 YYModel/MJExtension
//   映射得到对象（二进制里 YYModel 出现 24 次，MJExtension 1 次，
//   两条路都真实存在）。所以取值必须两态通吃，不能赌其中一种。
//
//   [obj valueForKey:] 在 getter 不存在时抛 NSUnknownKeyException，
//   未捕获即崩宿主 —— 违反本文件设计要点第 2 条。故先 respondsToSelector
//   再取，外面再包 @try 兜底，双保险。
// ─────────────────────────────────────────────────────────────────────
static id CSFSValue(id obj, NSString *key) {
    if (!obj || key.length == 0) return nil;
    if ([obj isKindOfClass:[NSDictionary class]]) {
        return [(NSDictionary *)obj objectForKey:key];
    }
    // 字符串/数字这类叶子节点没有属性可探，直接放弃
    if ([obj isKindOfClass:[NSString class]] || [obj isKindOfClass:[NSNumber class]]) {
        return nil;
    }
    SEL sel = NSSelectorFromString(key);
    if (![obj respondsToSelector:sel]) return nil;
    @try {
        return [obj valueForKey:key];
    } @catch (NSException *e) {
        return nil;
    }
}

// 把任意对象的真实形状写进日志。
//
// 这是唯一能在设备上把「style 到底长什么样」定死的手段：
// 静态分析只能看到全局按字母序合并的属性名池，判不出类归属
// （font_color / font_face / font_style / font_attribute 在池里相邻，
//   但相邻只说明名字相近，不说明同属一个类）。
// 用 class_copyPropertyList 拿的是**这个类自己的**属性表，没有歧义。
static NSString *CSFSDescribeShape(id obj) {
    if (!obj) return @"(nil)";
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSArray *ks = [(NSDictionary *)obj allKeys];
        if (ks.count > 40) ks = [ks subarrayWithRange:NSMakeRange(0, 40)];
        return [NSString stringWithFormat:@"dict(%lu){%@}",
                (unsigned long)[(NSDictionary *)obj count],
                [ks componentsJoinedByString:@","]];
    }
    if ([obj isKindOfClass:[NSString class]]) {
        return [NSString stringWithFormat:@"str(%@)", obj];
    }
    if ([obj isKindOfClass:[NSNumber class]]) {
        return [NSString stringWithFormat:@"num(%@)", obj];
    }
    Class cls = [obj class];
    NSMutableString *out = [NSMutableString stringWithFormat:@"%@{",
                            NSStringFromClass(cls)];
    unsigned int n = 0;
    objc_property_t *props = class_copyPropertyList(cls, &n);
    unsigned int lim = n < 40 ? n : 40;
    for (unsigned int i = 0; i < lim; i++) {
        const char *nm = property_getName(props[i]);
        const char *at = property_getAttributes(props[i]);
        if (i) [out appendString:@" "];
        // 只保留类型编码的 T 段，@ 符号太多会把日志冲爆
        [out appendFormat:@"%s(%s)", nm ? nm : "?", at ? at : ""];
    }
    if (props) free(props);
    [out appendString:@"}"];
    return out;
}

// v22 前向声明。
// CSFSWhiteSpaceSet 定义在文件后半段（v14 那一块），但 v22 的文字判定
// 函数要用它。C 不允许调用未声明函数，与其把那段函数搬过来
// （搬动会打乱 v14 以来段落顺序，diff 变成一片红），不如补一条原型。
static id CSFSWhiteSpaceSet(void);

// ═════════════════════════════════════════════════════════════════════
// v21：图片导出
//
// 需求：文档里插入的图片要能进 Word。
// v16 起块类型过滤把 type != "PARA" 的整块 continue 掉了，
// 实证样本 27 块 = 25 PARA + 1 IMAGE + 1 LINE —— **IMAGE 就是这样丢的**。
// v16 当时的目的是去掉空段落，代价是把图也一起扔了。
//
// ⚠ 字段名不敢赌，所以这里**不按名字取，按内容特征认**。
//   二进制里能静态证实的信息只有：
//     imagePath     T@"NSString"     image_key  T@"NSString"
//     image_category T@"NSString"    （值 HANDWRITTEN / STAMP）
//     box_left/top/right/bottom Tf/Td，z_index/positionh/positionv Tq
//   但没有任何证据能证明 IMAGE 块用哪个键挂图片本体。
//   于是：把 block 当树递归扫，**只有二进制魔数对得上才算图片**。
//   名字猜错也能捞到；反过来宁可捞不到，也不能把非图片当图塞进文档。
// ═════════════════════════════════════════════════════════════════════

// 按魔数判图片格式。返回 @"png"/@"jpeg"/@"gif"，不是图片返回 nil。
static NSString *CSFSImageExt(NSData *d) {
    if (![d isKindOfClass:[NSData class]] || d.length < 12) return nil;
    const unsigned char *p = (const unsigned char *)d.bytes;
    if (!p) return nil;
    if (p[0] == 0x89 && p[1] == 0x50 && p[2] == 0x4E && p[3] == 0x47) return @"png";
    if (p[0] == 0xFF && p[1] == 0xD8 && p[2] == 0xFF) return @"jpeg";
    if (p[0] == 0x47 && p[1] == 0x49 && p[2] == 0x46 && p[3] == 0x38) return @"gif";
    return nil;
}

// 从文件头解析像素宽高（不依赖 UIImage，避免在后台队列里碰 UIKit）。
// 解析不出来返回 NO，调用方用兜底尺寸。
static BOOL CSFSImagePixelSize(NSData *d, NSString *ext,
                               unsigned long *ow, unsigned long *oh) {
    const unsigned char *p = (const unsigned char *)d.bytes;
    NSUInteger n = d.length;
    if (!p || n < 16) return NO;

    if ([ext isEqualToString:@"png"]) {
        // IHDR：签名 8 字节 + 长度 4 + "IHDR" 4 → 宽高在 16..23，大端
        if (n < 24) return NO;
        unsigned long w = ((unsigned long)p[16] << 24) | ((unsigned long)p[17] << 16)
                        | ((unsigned long)p[18] << 8)  |  (unsigned long)p[19];
        unsigned long h = ((unsigned long)p[20] << 24) | ((unsigned long)p[21] << 16)
                        | ((unsigned long)p[22] << 8)  |  (unsigned long)p[23];
        if (w == 0 || h == 0 || w > 100000 || h > 100000) return NO;
        *ow = w; *oh = h;
        return YES;
    }
    if ([ext isEqualToString:@"gif"]) {
        // 逻辑屏幕宽高：偏移 6..9，小端
        if (n < 10) return NO;
        unsigned long w = (unsigned long)p[6] | ((unsigned long)p[7] << 8);
        unsigned long h = (unsigned long)p[8] | ((unsigned long)p[9] << 8);
        if (w == 0 || h == 0) return NO;
        *ow = w; *oh = h;
        return YES;
    }
    if ([ext isEqualToString:@"jpeg"]) {
        // 扫段找 SOF：D8 之后逐段跳，段长在 offset+2（大端，含自身 2 字节）
        NSUInteger i = 2;
        int guard = 0;
        while (i + 9 < n && guard++ < 4096) {
            if (p[i] != 0xFF) { i++; continue; }
            unsigned char m = p[i + 1];
            // SOF0..SOF15，排除 DHT(C4) / JPG(C8) / DAC(CC)
            if (m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC) {
                unsigned long h = ((unsigned long)p[i + 5] << 8) | p[i + 6];
                unsigned long w = ((unsigned long)p[i + 7] << 8) | p[i + 8];
                if (w == 0 || h == 0) return NO;
                *ow = w; *oh = h;
                return YES;
            }
            NSUInteger seglen = ((NSUInteger)p[i + 2] << 8) | p[i + 3];
            if (seglen < 2) return NO;
            i += 2 + seglen;
        }
        return NO;
    }
    return NO;
}

// 把一段 NSData 包装成图片信息字典；不是图片返回 nil。
static NSDictionary *CSFSImageInfoFromData(NSData *d) {
    if (![d isKindOfClass:[NSData class]]) return nil;
    // 太小的数据不可能是有效图片，顺手挡掉图标级别的干扰
    if (d.length < 64) return nil;
    NSString *ext = CSFSImageExt(d);
    if (!ext) return nil;
    unsigned long w = 0, h = 0;
    if (!CSFSImagePixelSize(d, ext, &w, &h)) {
        // 尺寸解析失败但魔数是对的：仍然导出，用 4:3 兜底
        w = 400; h = 300;
    }
    NSMutableDictionary *info = [NSMutableDictionary dictionaryWithCapacity:5];
    [info setObject:d forKey:kCSFSImgData];
    [info setObject:ext forKey:kCSFSImgExt];
    [info setObject:[NSNumber numberWithUnsignedLong:w] forKey:kCSFSImgPxW];
    [info setObject:[NSNumber numberWithUnsignedLong:h] forKey:kCSFSImgPxH];
    return info;
}

// 在任意 JSON 子树里找图片。
//
// 优先看「名字像图片」的键（imagePath / path / data / url…），
// 再退回全量遍历。两者最终都要过 CSFSImageInfoFromData 的魔数关，
// 所以名字猜错不会导致误判，只是决定先看哪里。
static NSDictionary *CSFSFindImage(id obj, int depth) {
    if (!obj || depth > 6) return nil;

    if ([obj isKindOfClass:[NSData class]]) {
        return CSFSImageInfoFromData((NSData *)obj);
    }

    if ([obj isKindOfClass:[NSString class]]) {
        NSString *s = (NSString *)obj;
        if (s.length < 8 || s.length > 8 * 1024 * 1024) return nil;
        NSString *low = [s lowercaseString];
        // ① 本地路径
        if ([low hasSuffix:@".png"] || [low hasSuffix:@".jpg"] ||
            [low hasSuffix:@".jpeg"] || [low hasSuffix:@".gif"]) {
            NSData *fd = [NSData dataWithContentsOfFile:s];
            if (fd) {
                NSDictionary *info = CSFSImageInfoFromData(fd);
                if (info) return info;
            }
        }
        // ② base64（长的纯 base64 串才试，否则白光扫一遍很浪费）
        if (s.length > 128) {
            NSData *bd = [[NSData alloc] initWithBase64EncodedString:s options:0];
            if (bd) {
                NSDictionary *info = CSFSImageInfoFromData(bd);
                if (info) return info;
            }
        }
        return nil;
    }

    if ([obj isKindOfClass:[NSArray class]]) {
        NSArray *arr = (NSArray *)obj;
        NSUInteger cap = arr.count < 64 ? arr.count : 64;
        for (NSUInteger i = 0; i < cap; i++) {
            NSDictionary *r = CSFSFindImage([arr objectAtIndex:i], depth + 1);
            if (r) return r;
        }
        return nil;
    }

    // 字典 / 模型对象：先试高可信键名，再全量
    static NSString *const kHint[] = {
        @"imageData", @"image", @"img", @"picture", @"pic",
        @"imagePath", @"path", @"filePath", @"localPath", @"src", @"url",
        @"data", @"value", @"content"
    };
    int hintCount = (int)(sizeof(kHint) / sizeof(kHint[0]));
    for (int i = 0; i < hintCount; i++) {
        NSDictionary *r = CSFSFindImage(CSFSValue(obj, kHint[i]), depth + 1);
        if (r) return r;
    }

    NSMutableArray *keys = [NSMutableArray arrayWithCapacity:8];
    if ([obj isKindOfClass:[NSDictionary class]]) {
        [keys addObjectsFromArray:[(NSDictionary *)obj allKeys]];
    } else {
        unsigned int n = 0;
        objc_property_t *props = class_copyPropertyList([obj class], &n);
        unsigned int lim = n < 48 ? n : 48;
        for (unsigned int i = 0; i < lim; i++) {
            const char *nm = property_getName(props[i]);
            if (nm) [keys addObject:[NSString stringWithUTF8String:nm]];
        }
        if (props) free(props);
    }
    for (NSString *k in keys) {
        NSDictionary *r = CSFSFindImage(CSFSValue(obj, k), depth + 1);
        if (r) return r;
    }
    return nil;
}

// 把一个值压成一行短描述。
// 关键作用是让 NSData 现形：CSFSDescribeShape 只打 key 名和类型，
// 看不到某个键下面是不是挂着几 MB 的图片字节。
static NSString *CSFSBriefValue(id v, int depth) {
    if (!v) return @"nil";
    if ([v isKindOfClass:[NSString class]]) {
        NSString *s = (NSString *)v;
        if (s.length > 90) {
            return [NSString stringWithFormat:@"str(%lu)\"%@...\"",
                    (unsigned long)s.length, [s substringToIndex:90]];
        }
        return [NSString stringWithFormat:@"str\"%@\"", s];
    }
    if ([v isKindOfClass:[NSNumber class]]) {
        return [NSString stringWithFormat:@"num(%@)", v];
    }
    if ([v isKindOfClass:[NSData class]]) {
        NSData *d = (NSData *)v;
        const unsigned char *p = (const unsigned char *)d.bytes;
        NSUInteger n = d.length < 8 ? d.length : 8;
        NSMutableString *hx = [NSMutableString stringWithCapacity:16];
        for (NSUInteger i = 0; i < n; i++) [hx appendFormat:@"%02x", p[i]];
        return [NSString stringWithFormat:@"data(%lu hex:%@)",
                (unsigned long)d.length, hx];
    }
    if ([v isKindOfClass:[NSArray class]]) {
        return [NSString stringWithFormat:@"array(%lu)", (unsigned long)[(NSArray *)v count]];
    }
    if ([v isKindOfClass:[NSDictionary class]]) {
        return [NSString stringWithFormat:@"dict(%lu)", (unsigned long)[(NSDictionary *)v count]];
    }
    return NSStringFromClass([v class]);
}

// 递归描述一个块：key = 值摘要。
// 只在图片「没找到」时调用一次 —— 那时唯一的线索就是这块到底装了什么。
static NSString *CSFSDescribeDeep(id obj, int depth) {
    if (!obj) return @"(nil)";
    if (depth > 2) return @"...";
    if (![obj isKindOfClass:[NSDictionary class]] &&
        ![obj isKindOfClass:[NSArray class]]) {
        // 模型对象：先取属性名，再逐个取值
        unsigned int n = 0;
        objc_property_t *props = class_copyPropertyList([obj class], &n);
        NSMutableArray *names = [NSMutableArray arrayWithCapacity:8];
        unsigned int lim = n < 14 ? n : 14;
        for (unsigned int i = 0; i < lim; i++) {
            const char *nm = property_getName(props[i]);
            if (nm) [names addObject:[NSString stringWithUTF8String:nm]];
        }
        if (props) free(props);
        if (names.count == 0) return NSStringFromClass([obj class]);
        NSMutableString *o = [NSMutableString string];
        for (NSString *k in names) {
            if (o.length) [o appendString:@" "];
            id v = CSFSValue(obj, k);
            if ([v isKindOfClass:[NSArray class]] || [v isKindOfClass:[NSDictionary class]]) {
                [o appendFormat:@"%@=%s", k, [CSFSBriefValue(v, depth) UTF8String]];
            } else {
                [o appendFormat:@"%@=%s", k, [CSFSBriefValue(v, depth) UTF8String]];
            }
        }
        return o;
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        NSArray *a = (NSArray *)obj;
        NSUInteger cap = a.count < 6 ? a.count : 6;
        NSMutableString *o = [NSMutableString stringWithFormat:@"[%lu]{", (unsigned long)a.count];
        for (NSUInteger i = 0; i < cap; i++) {
            if (i) [o appendString:@", "];
            [o appendFormat:@"%s", [CSFSBriefValue([a objectAtIndex:i], depth) UTF8String]];
        }
        [o appendString:@"}"];
        return o;
    }
    NSDictionary *d = (NSDictionary *)obj;
    NSArray *ks = [d allKeys];
    NSUInteger cap = ks.count < 14 ? ks.count : 14;
    NSMutableString *o = [NSMutableString stringWithFormat:@"{%lu ", (unsigned long)ks.count];
    for (NSUInteger i = 0; i < cap; i++) {
        NSString *k = [ks objectAtIndex:i];
        id v = [d objectForKey:k];
        if (i) [o appendString:@" "];
        [o appendFormat:@"%@=%s", k, [CSFSBriefValue(v, depth) UTF8String]];
    }
    [o appendString:@"}"];
    return o;
}

// 把图片信息渲染成一个居中的内联图片段落。
// seq 只用于生成不重复的 rId / 文件名，必须调用方保证唯一。
//
// 单位换算：
//   像素 → EMU 按 96 DPI 解释，1 px = 914400/96 = 9525 EMU；
//   正文可用宽度 = kCSFSContentTwips，1 twip = 635 EMU。超宽等比缩小。
// ═════════════════════════════════════════════════════════════════════
// v37：内容区宽度 —— 版心宽度第一次有实证，不再是「Word 默认边距」。
//
// 根因（2026-10-30 对照实验）：w:pgMar 四周写死 1440 twips（72pt / 2.54cm），
// 版心只有 451.3pt；而原文档正文几乎贴边。拿同一份真机导出的 docx，
// 只改左右边距，用 Word 转 PDF、pymupdf 逐行量 bbox：
//
//   边距   版心      「根据…」首行收尾    「第一条」首行收尾   总行数
//   1440   451.3pt   法律、法（41 字）    5 单（44 字）       60
//   1080   487.3pt   法规规定，（45 字）  单元．了（47 字）   55
//    800   515.3pt   在平（47 字）        层2 号（56 字）     52  ← 与截图逐行一致
//    720   523.3pt   在平等、（49 字）    层2 号（56 字）     52
//
// 「在平」「层2 号」正是手机预览截图里的折行点；第二/四/六/十二条在
// 1440 下全是 3 行，800 下全部回到 2 行，与截图一致。
//
// 再次验证：只改左右 800 与四周全改 800 **逐行完全一致**（行数、字数、
// x0/x1、首尾文字全同）→ 上下边距不参与折行，只影响每页行数。
// 因此只改左右，上下保持 1440，改动面收到最小。
//
// ⚠ 这个值同时是五处判据的基准（制表位归一化上限、lineW、空白宽度上限、
//   均分制表位、缩进上限）。版心改了而它们不改，就会重演
//   「判据在跑、分支从不触发」（v35 的 squeeze 一次没触发就是这样）。
// ═════════════════════════════════════════════════════════════════════
static const double kCSFSContentTwips = 10306.0;   // v37：A4 11906 − 左右边距各 800

static NSString *CSFSRenderImagePara(NSDictionary *img, long seq) {
    NSData *d = [img objectForKey:kCSFSImgData];
    if (![d isKindOfClass:[NSData class]] || d.length == 0) return @"<w:p/>";
    NSString *ext = [img objectForKey:kCSFSImgExt];
    if (ext.length == 0) return @"<w:p/>";
    // 编号由调用方在建图片段时写进 kCSFSImgName，这里统一取，
    // 保证 rId / media 文件名 / docPr id 三者同号且全局唯一。
    NSNumber *nn = [img objectForKey:kCSFSImgName];
    if (nn) seq = [nn longValue];
    if (seq < 1) seq = 1;
    NSNumber *nw = [img objectForKey:kCSFSImgPxW];
    NSNumber *nh = [img objectForKey:kCSFSImgPxH];
    double pxw = nw ? [nw doubleValue] : 400.0;
    double pxh = nh ? [nh doubleValue] : 300.0;
    if (pxw < 1) pxw = 1;
    if (pxh < 1) pxh = 1;

    double cx = pxw * 9525.0;
    double cy = pxh * 9525.0;
    const double kMaxCx = kCSFSContentTwips * 635.0;   // v37：随版心同步，勿写死
    if (cx > kMaxCx) {
        double k = kMaxCx / cx;
        cx = kMaxCx;
        cy = cy * k;
    }
    long lcx = (long)(cx + 0.5);
    long lcy = (long)(cy + 0.5);
    if (lcx < 1) lcx = 1;
    if (lcy < 1) lcy = 1;

    NSString *rid = [NSString stringWithFormat:@"rIdImg%ld", seq];
    NSString *fname = [NSString stringWithFormat:@"image%ld.%@", seq, ext];

    // 注意：docPr 的 id 在整篇文档里必须唯一，用 seq 即可（seq 从 1 递增）
    return [NSString stringWithFormat:
        @"<w:p><w:pPr><w:jc w:val=\"center\"/></w:pPr><w:r><w:drawing>"
        @"<wp:inline distT=\"0\" distB=\"0\" distL=\"0\" distR=\"0\">"
        @"<wp:extent cx=\"%ld\" cy=\"%ld\"/>"
        @"<wp:docPr id=\"%ld\" name=\"Picture %ld\"/>"
        @"<a:graphic><a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/picture\">"
        @"<pic:pic>"
        @"<pic:nvPicPr><pic:cNvPr id=\"%ld\" name=\"%@\"/><pic:cNvPicPr/></pic:nvPicPr>"
        @"<pic:blipFill><a:blip r:embed=\"%@\"/>"
        @"<a:stretch><a:fillRect/></a:stretch></pic:blipFill>"
        @"<pic:spPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"%ld\" cy=\"%ld\"/></a:xfrm>"
        @"<a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></pic:spPr>"
        @"</pic:pic></a:graphicData></a:graphic>"
        @"</wp:inline></w:drawing></w:r></w:p>",
        lcx, lcy, seq, seq, seq, fname, rid, lcx, lcy];
}


// ═════════════════════════════════════════════════════════════════════
// v22：文字优先
//
// 现象：导出 Word 时开了「手写转文字」，文档里的手写部分仍然是图片，
//       而那些字本该是纯文字。
//
// 根因（在 v21 自己身上）：slice 循环里图片分支排在最前，判据只有
// slice.stype 一个字符串，命中就 continue —— 把 CSFSParseSlice 整段跳过。
// 可是「手写转文字」之后，手写区的 slice **仍然带 handwrite 类 stype**
// （App 得靠它区分手写区和印刷区），同时 text 已经被 OCR 填好。
// 于是文字被 continue 掉、笔迹图被塞进文档，与用户看到的完全一致。
//
// 修正原则：**「有识别文字」是硬优先级，与 stype 无关。**
// 图片只是兜底，不是与文字并列的选项。
// 这个方向是安全的：图片模式下的图片 slice 不带 text；
// 一旦带 text，说明 App 已经识别过，导出文字才是用户的预期。
// ═════════════════════════════════════════════════════════════════════

// 判断一个字符串是不是「路径/URL」。
// 用途：CSFSSliceText 要按别名试探文字字段，其中 content/value 这类
// 键可能装的是图片路径。把路径当正文写进 Word，就是一张图变成
// 一行 "file:///var/mobile/.../image.jpg" —— 比丢文字更糟。
static BOOL CSFSLooksLikePath(NSString *s) {
    if (![s isKindOfClass:[NSString class]] || s.length == 0) return NO;
    if ([s hasPrefix:@"/"] || [s hasPrefix:@"file://"]) return YES;
    if ([s containsString:@"://"]) return YES;
    // 只有「整串就是个文件名」才判路径：正文里出现 "见 image.png" 这种
    // 句子不该被排除，所以加了长度上限。
    if (s.length <= 160) {
        NSString *low = [s lowercaseString];
        NSArray *exts = @[@".png", @".jpg", @".jpeg", @".gif",
                          @".heic", @".webp", @".tiff", @".bmp", @".pdf"];
        for (NSString *e in exts) {
            if ([low hasSuffix:e]) return YES;
        }
    }
    return NO;
}

// v31：是不是「纯空白」（但非空串）。
//
// 单独抽出来，因为它在两处的语义完全不同：
//   · CSFSSliceText 里 → 纯空白**是内容**，要保留（见那里的长注释）
//   · 段落级判空     → 整段都是纯空白才是「空段落」，可以丢
// 混成一个判断就会出现「为了丢掉空段落，把段内的空格也丢了」。
//
// 注意只认空格/制表/换行/全角空格（U+3000）：OCR 常把中文排版里的
// 缩进输出成全角空格，那也是最典型的「带下划线的空格」载体。
static BOOL CSFSIsPureWhiteSpace(NSString *s) {
    if (![s isKindOfClass:[NSString class]] || s.length == 0) return NO;
    NSUInteger n = s.length;
    for (NSUInteger i = 0; i < n; i++) {
        unichar c = [s characterAtIndex:i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
            c == 0x00A0 || c == 0x3000) {
            continue;
        }
        return NO;
    }
    return YES;
}

// 取 slice 的文字。text 优先，别名兜底。
//
// 为什么要别名：手写识别结果不保证落在 text 上。二进制里能看到
// content / recognizeText 这类键名，但层级归属无法静态确定。
// 逐个试探比赌一个更可靠，代价只是几次取值。
// 全部候选都要过「非空、非纯空白、不像路径」三关。
// ═════════════════════════════════════════════════════════════════════
// v24：导出面板三个开关的读取
//
// 为什么必须读：用户勾了「去除手写」「去除印章」，导出照样两个都在。
// 原因不是判据写错，而是**压根没读这两个开关** —— 面板状态存在
// CSJsonWordEditBottomView._originalData（类型 CSOcrPage）上，
// 我们以前从没碰过它。
//
// 两个来源，面板优先、JSON 兜底：
//   ① -[CSJsonWordEditBottomView originalData] → CSOcrPage 的三个 BOOL
//   ② JSON 顶层同名键（App 落盘时可能一起写进去）
// 两个来源都没有时保持上次的值，不覆盖 —— 宁可沿用，也不要用
// 「读不到就当 NO」把用户已经勾上的选项悄悄关掉。
// ═════════════════════════════════════════════════════════════════════
// ═════════════════════════════════════════════════════════════════════
// v25：手写 / 印章的身份判定 —— 与 App 完全对齐
//
// 反汇编 -[CSOcrPageSegment customImageCategoryType] 的原文：
//     NSString *c = self.image_category;
//     if ([c localizedCaseInsensitiveCompare:@"HANDWRITTEN"] == Same) return 1;
//     if ([c localizedCaseInsensitiveCompare:@"STAMP"]       == Same) return 2;
//     return 0;
// 而 -[CSOcrPageSegment isStampImage] 就是 `return [self customImageCategoryType] == 2`。
//
// 两个字符串常量在 __cfstring 里紧邻（…"HANDWRITTEN\0STAMP\0"…），
// 所以这条判据是**严格相等**，不是 containsString。
// v24 用 containsString:@"stamp" 近似，正好也能命中，但它同时会命中
// "nostamp"、"stamp_removed" 这类值 —— 判据的边界不能靠巧合。
// ═════════════════════════════════════════════════════════════════════
static NSInteger CSFSCategoryType(id block) {
    id c = CSFSValue(block, @"image_category");
    if (![c isKindOfClass:[NSString class]]) c = CSFSValue(block, @"imageCategory");
    if (![c isKindOfClass:[NSString class]]) return 0;
    NSString *s = [(NSString *)c uppercaseString];
    if ([s isEqualToString:@"HANDWRITTEN"]) return 1;
    if ([s isEqualToString:@"STAMP"])       return 2;
    // 兼容带后缀的写法（HANDWRITTEN_TEXT 之类），仍然按前缀认，
    // 但日志里会打出原值，方便下一轮确认要不要收紧。
    if ([s hasPrefix:@"HANDWRITTEN"]) return 1;
    if ([s hasPrefix:@"STAMP"])       return 2;
    return 0;
}

// 前置声明：CSFSPullOptions / CSFSReadOptionsFromBottomView 都会用到，实现在下面。
// decl_order.py（CI 语法闸门之一）把前置声明也算作「定义」并要求早于首次使用，
// 所以这两条必须排在 CSFSPullOptions 之前 —— v25 曾把它们放在后面，
// 于是 CSFSPullOptions 里对 CSFSCaptureLayoutContext 的调用早于声明 12 行，CI 挂。
static id CSFSFindPageObject(id obj, int depth);
static void CSFSCaptureLayoutContext(id page);

// 从一个来源收集开关。
//
// v27 关键改动：**不再短路**。
//   v24/v25 的写法是「这个来源有这三个字段 → 就认定读到了 → return YES」，
//   于是 CSFSReadOptionsFromBottomView 里排第一的 bottomView.originalData
//   只要带上字段（哪怕全是同步落后的 NO），后面的 context.allPages 就永远不执行。
//   v25 以为「换了入口」，实际上一个入口都没换 —— 行为与 v24 完全一致。
//
//   现在改成：每个来源只把「自己看到的」记进 gCSFSSeenXxx，最后合并取 OR。
//   三个来源全跑完才算完，任一来源说勾了就是勾了。
//   字段不存在时不再 return NO 终止，而是记一笔「这个来源没提供」继续下一个。
//
//   返回 YES 表示「本次至少从这个来源读到了字段」，用于让调用方拼日志，
//   但调用方**不再据此提前返回**。
static BOOL CSFSPullOptions(id src, NSString *from) {
    if (!src) return NO;
    @try {
        // ═══════════════════════════════════════════════════════════
        // v30：**先抓版式上下文，再做早退判断**。
        //
        // 这是 scale 一直等于 0.0000 的真正原因 —— 不是取不到，
        // 是那一行代码从来没被执行过。
        //
        // v25 把 CSFSCaptureLayoutContext(src) 放在函数末尾，
        // 而它上面第 2981 行有一句：
        //     if (!hw && !st && !hi) return NO;
        // 真机上 CSOcrPage 的 hideWrittenImage 等字段一旦一个都没有
        // （v27 日志实证：optKnown=0 src=(none) seen=000），
        // 这句就直接 return 了，末尾的 CaptureLayoutContext 永远跑不到。
        //
        // 后果链：gCSFSPageScale 恒为 0 →
        //   CSFSIndentTwips 走 fallback →
        //   v25 日志全程 "why=px@200dpi scale=0.0000" →
        //   缩进全部按 595/1654 估算 → 排版不像。
        //
        // scale 与开关是**互相独立**的两件事：开关读不到不代表
        // 页面不认识自己的尺寸。所以必须无条件先抓。
        // ═══════════════════════════════════════════════════════════
        CSFSCaptureLayoutContext(src);

        id hw = CSFSValue(src, @"hideWrittenImage");
        id st = CSFSValue(src, @"hideStampImage");
        id hi = CSFSValue(src, @"handWrittenToImage");
        if (!hw && !st && !hi) return NO;
        gCSFSSeenWritten = YES;
        gCSFSSeenStamp   = YES;
        gCSFSSeenHandTo  = YES;
        BOOL w = CSFSBoolValue(hw);
        BOOL s = CSFSBoolValue(st);
        BOOL h = CSFSBoolValue(hi);
        // 合并规则按语义分（详见 gCSFSSeenWritten 处的长注释）：
        //   hideWrittenImage / hideStampImage → OR（说删就删）
        //   handWrittenToImage                → 以最后一份明确读到为准（不 OR）
        if (w) gCSFSHideWritten = YES;
        if (s) gCSFSHideStamp   = YES;
        // handToImage 只要本来源真的给了字段，就用它的值覆盖（后读到的更新）。
        if (hi) {
            gCSFSHandToImage   = h;
            gCSFSHandToResolved = YES;
        }
        gCSFSOptKnown    = YES;
        // 来源名按实际贡献拼，别再用「最后写入者」——
        // 合并语义下「最后写入者」会误导排查。
        //
        // presyntax.py 的 P5 只放行 @protocol 里声明过的 selector 和系统白名单。
        // stringByAppendingFormat: 不在白名单里，而把它加进 @protocol 又要维护
        // 一份假的 NSString 接口声明，所以这里用白名单里的 stringByAppendingString:
        // 手工拼（from 里本来就只有 "context.allPages" 这类固定串，不涉格式化）。
        NSString *tag = (w || s || h) ? from : [from stringByAppendingString:@"(no)"];
        if (gCSFSOptSrc.length) {
            gCSFSOptSrc = [gCSFSOptSrc stringByAppendingString:@"+"];
            gCSFSOptSrc = [gCSFSOptSrc stringByAppendingString:tag];
        } else {
            gCSFSOptSrc = tag;
        }
        gCSFSPageSrc     = from;
        // v25：同一次拿到 page 就顺带把版式上下文取走，
        // 免得后面再去找一遍（面板那时可能已经销毁）。
        CSFSCaptureLayoutContext(src);
        CSFS_LOG(@"v27 opts(%@) hideWritten=%d hideStamp=%d handToImage=%d"
                 @" | merged w=%d s=%d h=%d",
                 from, (int)w, (int)s, (int)h,
                 (int)gCSFSHideWritten, (int)gCSFSHideStamp, (int)gCSFSHandToImage);
        return YES;
    } @catch (NSException *e) {
        CSFS_LOG(@"v24 opts(%@) threw: %@", from, e.reason);
        return NO;
    }
}

static void CSFSReadOptionsFromBottomView(id bottomView) {
    if (!bottomView) {
        CSFS_LOG(@"v24 opts: bottomView is nil");
        return;
    }
    // ═══════════════════════════════════════════════════════════════
    // v28：真机日志定死了前四轮为什么一直读不到开关
    //
    // 日志证据（CSFS.log，三次导出六次输出全部一致）：
    //     v27 stats: optKnown=0 src=(none) seen(w/s/h)=000
    //     v24 opts: not found on CSJsonWordEditBottomView
    // 即：三个来源一个都没拿到字段。而静态分析证明 CSOcrPage 确实有
    // hideWrittenImage / hideStampImage / handWrittenToImage 三个属性
    // （见 propowner.py 输出）。所以问题不是「字段在不在」，
    // 而是「我拿到的那个对象是 nil」。
    //
    // 为什么 originalData 是 nil —— 用 callers_sel.py 反查 setter：
    //     -[CSJsonWordEditBottomView setOriginalData:] 的全部调用者只有两个：
    //         -aiBeautifyAction
    //         -dismissAIBeautifyViewController:
    // 也就是说，这个属性只在用户点「AI 美化」时才被赋值。
    // 用户正常导出时它**永远是 nil**。
    // 前四轮（v24 起）一直从这个 nil 对象读 → 读到 nil → 全是 NO。
    // 这是「勾了跟不勾一样」的最终机制，v27 的合并也只是在合并三个 nil。
    //
    // 真正活着的 CSOcrPage 在这里（同一套反查链上）：
    //     -[CSJsonWordEditModel ocrPage]        ← 返回 T@"CSOcrPage"
    //     -[CSOcrPage setHideStampImage:] 的调用者包含
    //         CSJsonWordEditAdapterManager -updateCategoryListViewItems...showRemoveSignet:...
    //     即开关就是通过 model.ocrPage 这条链写下去的。
    // 而 bottomView 上恰好有 currentAIEditModel(T@"CSJsonWordEditModel")。
    //
    // 所以正确顺序是：先 model.ocrPage，再 context.allPages，
    // originalData 降到最后（它常常是 nil，但 nil 时不该耽误别人）。
    // ═══════════════════════════════════════════════════════════════

    // ① CSImageToJsonManager 单例 —— v29 新增，真正的生效值在这里
    //
    // 前面五轮之所以全部失败，就是因为一直没看这个对象（详见 gCSFSHideWritten
    // 上方 v29 那段长注释）。它由 -updateCategoryListViewItemsWith... 在
    // 面板选项每次变化时同步写入，是「当前生效」的那一份。
    // 注意属性名少一个 n（hideWritteImage），所以走名字表，不硬写。
    BOOL sawMgr = NO;
    id mgr = CSFSImageToJsonManager();
    if (mgr) {
        BOOL fw = NO, fs = NO;
        BOOL mw = CSFSReadBoolFrom(mgr, kCSFSMgrHideWritten, &fw);
        BOOL ms = CSFSReadBoolFrom(mgr, kCSFSMgrHideStamp, &fs);
        // hasWritteImage 不是「去除手写」，而是「这篇文档里有手写图」，
        // 意义不同，只用来打日志佐证，不参与合并。
        BOOL fh = NO;
        BOOL mh = CSFSReadBoolFrom(mgr, kCSFSMgrHasWritten, &fh);
        if (fw || fs) {
            sawMgr = YES;
            if (mw) gCSFSHideWritten = YES;
            if (ms) gCSFSHideStamp   = YES;
            // 有手写图时，「手写转文字」的反面就是「保留成图」。
            // 这里不猜方向，只记录，交给后面的内容判定。
            gCSFSSeenWritten = YES;
            gCSFSSeenStamp   = YES;
            if (fh) gCSFSSeenHandTo = YES;
            gCSFSOptKnown = YES;
            gCSFSOptSrc = [NSString stringWithFormat:@"mgr(hw=%d st=%d hasHW=%d)",
                           (int)mw, (int)ms, (int)mh];
        }
        CSFS_LOG(@"v29 mgr opts: hideWritteImage=%@(%d) hideStampImage=%@(%d)"
                 @" hasWritteImage=%@(%d) | merged w=%d s=%d",
                 fw ? @"有" : @"无", (int)mw,
                 fs ? @"有" : @"无", (int)ms,
                 fh ? @"有" : @"无", (int)mh,
                 (int)gCSFSHideWritten, (int)gCSFSHideStamp);
    } else {
        CSFS_LOG(@"v29 mgr opts: 拿不到 CSImageToJsonManager 单例");
    }

    // ② currentAIEditModel.ocrPage —— v28 的主来源，降为次要
    //
    // 它的属性名是完整拼写 hideWrittenImage，与 Manager 不同名。
    // 两者指同一件事，任一为 YES 即视为要删（OR 合并，见上面的语义说明）。
    BOOL gotModel = NO;
    id model = CSFSValue(bottomView, @"currentAIEditModel");
    if (model) {
        id mp = CSFSValue(model, @"ocrPage");
        gotModel = CSFSPullOptions(mp, @"currentAIEditModel.ocrPage");
        if (!gotModel) {
            CSFS_LOG(@"v28 opts: model=%@ but ocrPage=%@（ocrPage 也空）",
                     NSStringFromClass([model class]), mp ? @"非空但无字段" : @"nil");
        }
    } else {
        CSFS_LOG(@"v28 opts: currentAIEditModel=nil");
    }

    // ③ context.allPages —— 编辑页中枢，多页时取第 0 页
    BOOL gotPages = NO;
    id ctx = CSFSValue(bottomView, @"context");
    if (ctx) {
        id pages = CSFSValue(ctx, @"allPages");
        id page = CSFSFindPageObject(pages, 0);
        gotPages = CSFSPullOptions(page, @"context.allPages");
        if (!gotPages) {
            CSFS_LOG(@"v28 opts: context ok, allPages=%@（count=%lu）",
                     pages ? @"非空" : @"nil",
                     (unsigned long)([pages isKindOfClass:[NSArray class]]
                                     ? [(NSArray *)pages count] : 0));
        }
    } else {
        CSFS_LOG(@"v28 opts: context=nil");
    }

    // ④ bottomView.originalData —— 只有点过 AI 美化才非 nil，放最后
    id od = CSFSValue(bottomView, @"originalData");
    BOOL gotOrig = CSFSPullOptions(od, @"bottomView.originalData");
    if (!od) {
        CSFS_LOG(@"v28 opts: originalData=nil（正常现象：它只由 "
                 @"aiBeautifyAction / dismissAIBeautifyViewController: 赋值）");
    }

    // ⑤ bottomView 自己（兜底，理论上是 view 不会有这些字段）
    BOOL gotSelf = CSFSPullOptions(bottomView, @"bottomView");

    if (!gCSFSOptKnown) {
        CSFS_LOG(@"v24 opts: not found on %@ shape=%@",
                 NSStringFromClass([bottomView class]), CSFSDescribeShape(bottomView));
    } else {
        CSFS_LOG(@"v29 opts: FINAL hideWritten=%d hideStamp=%d handToImage=%d"
                 @" (srcs: mgr=%d model=%d allPages=%d originalData=%d self=%d)",
                 (int)gCSFSHideWritten, (int)gCSFSHideStamp, (int)gCSFSHandToImage,
                 (int)sawMgr, (int)gotModel, (int)gotPages, (int)gotOrig, (int)gotSelf);
    }
}

// 在任意形状的对象里挖出一个 CSOcrPage：
//   · 对象自身响应 hideWrittenImage/hideStampImage → 就是它
//   · 数组 → 逐个元素下探（只看前 8 个，够用且不会在大文档上耗时）
//   · 模型对象 → 试 ocrPage / page 两个键
// 全程 respondsToSelector 保护，不认识的形状直接放弃，不抛异常。
static id CSFSFindPageObject(id obj, int depth) {
    if (!obj || depth > 4) return nil;
    @try {
        if ([obj respondsToSelector:NSSelectorFromString(@"hideWrittenImage")] ||
            [obj respondsToSelector:NSSelectorFromString(@"hideStampImage")]) {
            return obj;
        }
        if ([obj isKindOfClass:[NSArray class]]) {
            NSArray *arr = (NSArray *)obj;
            NSUInteger n = MIN(arr.count, (NSUInteger)8);
            for (NSUInteger i = 0; i < n; i++) {
                id r = CSFSFindPageObject([arr objectAtIndex:i], depth + 1);
                if (r) return r;
            }
            return nil;
        }
        for (NSString *k in @[@"ocrPage", @"page", @"originalData"]) {
            id v = CSFSValue(obj, k);
            if (v) {
                id r = CSFSFindPageObject(v, depth + 1);
                if (r) return r;
            }
        }
    } @catch (NSException *e) {
        CSFS_LOG(@"v25 findPage threw: %@", e.reason);
    }
    return nil;
}

// ═════════════════════════════════════════════════════════════════════
// v25：把页面的版式上下文抓下来（scale / page_size / 全局字号行距偏好）
//
// 这段不产出任何输出，只是让后面的换算有正确的分母。
// 拿不到时保持 0，换算函数会走「不缩放」的分支并记日志 ——
// 绝不能因为拿不到就崩，也不能因为拿不到就悄悄按猜的值算。
// ═════════════════════════════════════════════════════════════════════
static void CSFSCaptureLayoutContext(id page) {
    if (!page) { CSFS_LOG(@"v25 layout: page nil, scale unknown"); return; }
    @try {
        // ── v28：优先直接读 page.scale ────────────────────────────────
        //
        // 之前一直自己算 renderWidth / page_size.width，
        // 真机日志里全程 scale=0.0000 —— 说明这两条都取空，
        // 于是所有缩进退化成 px@200dpi 估值，排版必然不像。
        //
        // 静态分析（propowner.py 输出）证明 CSOcrPage 自己就有：
        //     scale       [Td,N,V_scale]      ← App 算好的渲染缩放比
        //     renderWidth [Td,N,V_renderWidth]
        //     page_size   [T@"CSOcrPageSize",C,N,V_page_size]
        // 有现成的就别自己推。先读 scale，失败再退回自算。
        double rw = CSFSDoubleValue(CSFSValue(page, @"renderWidth"));
        double pw = 0.0;
        id ps = CSFSValue(page, @"page_size");
        if (ps) {
            // page_size 是 CSOcrPageSize 模型（不是 NSValue / NSDictionary），
            // 取的是 width getter；字典分支只作兼容。
            if ([ps respondsToSelector:@selector(width)]) {
                pw = [(NSNumber *)[ps performSelector:@selector(width)] doubleValue];
            }
            if (!(pw > 0) && [ps isKindOfClass:[NSDictionary class]]) {
                id w = [(NSDictionary *)ps objectForKey:@"width"];
                if (!w) w = [(NSDictionary *)ps objectForKey:@"w"];
                pw = CSFSDoubleValue(w);
            }
        }

        double s = CSFSDoubleValue(CSFSValue(page, @"scale"));
        const char *src = "page.scale";
        if (!(s > 0))
        {
            // scale 属性拿不到时的退路：自己算，但日志里标出来。
            src = "computed";
            if (rw > 0 && pw > 0) s = rw / pw;
        }
        gCSFSRenderWidth = rw;
        gCSFSPageWidth   = pw;
        gCSFSPageScale   = (s > 0) ? s : 0.0;
        gCSFSPageScaleSrc = src;

        // 全局偏好：影响字号和行距，缺一档就差一档
        id cs = CSFSValue(page, @"clientSettings");
        if (cs) {
            gCSFSFontSizeMode  = (NSInteger)CSFSDoubleValue(CSFSValue(cs, @"fontSizeMode"));
            gCSFSLineSpaceMode = (NSInteger)CSFSDoubleValue(CSFSValue(cs, @"lineSpaceMode"));
            gCSFSAiBeautify    = CSFSBoolValue(CSFSValue(cs, @"aiBeautifyEnable"));
        }
        CSFS_LOG(@"v28 layout: renderW=%.1f pageW=%.1f scale=%.4f from=%s"
                 @" fontSizeMode=%ld lineSpaceMode=%ld aiBeautify=%d",
                 rw, pw, gCSFSPageScale, gCSFSPageScaleSrc,
                 (long)gCSFSFontSizeMode, (long)gCSFSLineSpaceMode, (int)gCSFSAiBeautify);
    } @catch (NSException *e) {
        CSFS_LOG(@"v25 layout threw: %@", e.reason);
    }
}

// ═════════════════════════════════════════════════════════════════════
// v24：版式数值归一化
//
// 硬约束：这些字段（indent_first_line / line_gap / box_* / tabs）
// 的**单位没有任何静态证据**。ivar 类型只说「是整数/浮点」，
// 不说是 twips、像素、字符数还是 1/100 pt，JSON 也不带单位说明。
//
// 所以按数量级分档，并把原始值和选中的解释都写进日志。
// 四种解释的典型值相差 10 倍以上，分档是稳的：
//   两字符缩进 @11pt ≈ 440 twips ≈ 2 字符 ≈ 22 pt ≈ 2200 (1/100pt)
// 下一轮拿日志一看就能定死，不用再猜。
// ═════════════════════════════════════════════════════════════════════
// v37：kCSFSContentTwips 已上移到 CSFSRenderImagePara 之前 ——
//      图片宽度上限也要用它，而 static const 必须先声明后使用。
//      定义处见「v37：内容区宽度」注释块（含 1440/1080/800/720 四档实测表）。

// ═════════════════════════════════════════════════════════════════════
// v25：缩进数值 → twips
//
// App 的原文（同 setupParaStyle 反汇编）：
//     headIndent          = page.scale * indent_hanging    * k
//     firstLineHeadIndent = page.scale * indent_first_line * k
//     k = isCellPara ? 0.8 : 1.0
//
// 也就是说 indent_* 是**页面像素**，乘 scale(=renderWidth/pageWidth)
// 变成渲染 pt。NSParagraphStyle 的单位是 pt，docx 也是 pt（1pt=20twips），
// 所以换算到 docx 就是 scale*raw*20 —— 与预览同一个 pt 值，视觉才对得上。
//
// 没有 scale 时退两步：
//   · raw 很小（≤12）→ 按字符数算，raw*字号pt
//   · 否则按 A4 宽度比例折回（1654px≈A4@200dpi）
// 两条都不是精确值，所以日志里会标出用的哪一条，便于下一轮定死。
// ═════════════════════════════════════════════════════════════════════
static double CSFSIndentTwips(id v, double basePt, const char **why) {
    double raw = CSFSDoubleValue(v);
    if (!(raw != 0.0)) {
        if (why) *why = "none";
        return 0.0;
    }
    // ═══════════════════════════════════════════════════════════════
    // v30：缩进换算 —— 按 -[CSWordEditFlowDataManager
    //      setupParaStyleWithAttributeString:para:ocrPage:segment:isCellPara:]
    //      的反汇编原文，不再有「字符数」「200dpi」两条猜测分支。
    //
    // 原文（0x10147dc98 起，全为逐条实证）：
    //
    //   10147dc88: bl STUB[floating_box]
    //   10147dc98: tbnz w23,#0 → 整段跳过缩进
    //
    //   10147dc9c: cmp  w28, #0            ; w28 = isCellPara（第6参数）
    //   10147dca4: ldr  d0, = 0.8          ; @0x1088ca678
    //   10147dcac: fcsel d9, d0, 1.0, ne   ; isCellPara ? 0.8 : 1.0
    //
    //   ; ② 悬挂缩进（与③互斥）
    //   10147dcb4: bl STUB[indent_hanging]
    //   10147dcb8: cmp  x0, #1 ; b.lt → 跳过
    //   10147dcc8: scvtf d0, x0
    //   10147dccc: fmul  d0, d8, d0        ; d8 = ocrPage.scale
    //   10147dcd0: fmul  d0, d9, d0        ; × (0.8 | 1.0)
    //   10147dcd8: bl STUB[setHeadIndent:]
    //   10147dce0: bl STUB[indent_hanging]
    //   10147dce4: cmp  x0, #0 ; b.gt → 结束（首行不再设）
    //
    //   ; ③ 首行缩进
    //   10147dcf0: bl STUB[indent_first_line]
    //   10147dcf4: cbz  x0 → 跳过
    //   10147dd00: scvtf d0, x0
    //   10147dd04: fmul  d0, d8, d0        ; × scale
    //   10147dd08: fmul  d0, d9, d0        ; × (0.8 | 1.0)
    //   10147dd10: bl STUB[setFirstLineHeadIndent:]
    //
    // 两个要点，都是前几轮猜错的：
    //   · 乘的是 ocrPage.scale，**不是** A4/200dpi 折算，也**不是**字号；
    //   · 全函数只设 headIndent / firstLineHeadIndent，
    //     **indent_left / indent_right 一次都没用** ——
    //     所以 docx 里也不该写 w:left / w:right（v29 之前一直在写）。
    //
    // scale 未知时不能假装知道：退成 1.0（等于「渲染坐标未缩放」），
    // 并在 why 里标出来，日志一眼可辨。
    // ═══════════════════════════════════════════════════════════════
    double sign = (raw > 0) ? 1.0 : -1.0;
    double a = fabs(raw);
    double scale = gCSFSPageScale;
    const char *n;
    if (scale > 0.0) {
        n = "raw*scale";
    } else {
        scale = 1.0;
        n = "raw*scale?scale=1";
    }
    // isCellPara 目前恒为 NO（我们不对表格单元格走这条路径），故 ×1.0。
    double pt = a * scale;
    if (why) *why = n;
    (void)basePt;   // 缩进与字号无关 —— 保留参数只为不改调用点
    return sign * pt * 20.0;   // pt → twips
}

// ═════════════════════════════════════════════════════════════════════
// v25：行距 —— 按 App 的真实公式算，不再猜单位
//
// 反汇编 -[CSWordEditDataManager setupParaStyleWithAttributeString:
//          para:ocrPage:segment:isCellPara:] 得到的原文：
//
//     if (page.clientSettings.aiBeautifyEnable)
//         multiple = 1.25;                       // 常量 @0x1088cdc50
//     else {
//         multiple = para.line_gap / (para.style.font_size * 1.44);
//         multiple = [clientSettings caculateLineHeightMultiple:
//                        multiple];             // lineSpaceMode ±0.25, clamp>=1
//     }
//     [paragraphStyle setLineHeightMultiple:multiple];
//
// 1.44 是反汇编里的 immediate double（@0x1088cbfb8）。
// 代入真实数据 line_gap=20 / font=11 → 20/(11*1.44)=1.263，
// 与上一轮从预览截图量出来的行距 24px/字高19px=1.26 完全吻合。
// v24 把 line_gap 直接当 twips 用（20 twips 会被判非法丢弃），
// 所以行距一直停在 Word 默认的 1.0 —— 这是「排版还是不对」的主因。
//
// OOXML 侧：lineRule=auto 时 w:line 以 1/240 行为单位，所以 w:line = 240*multiple。
// ═════════════════════════════════════════════════════════════════════
static long CSFSLineTwipsFromGap(id v, double fontPt, const char **why) {
    double gap = CSFSDoubleValue(v);
    if (!(gap > 0.0)) { if (why) *why = "none"; return 0; }

    // ═══════════════════════════════════════════════════════════════
    // v30：行距 —— 补上 clamp，这是「排版还是不对」的第二个真因。
    //
    // 前几轮算出的 originalMultiple 是对的（真机日志
    // gap=25.94 / 11pt → 1.637x，与手算 25.94/(11×1.44) 完全一致），
    // 错在**没有再过 App 的第二道修正**。
    //
    // 反汇编 -[CSITextEngineSettings
    //   caculateLineHeightMultipleWithOriginalLineHeightMultiple:
    //   lineSpacingMode:isExport:] 的真实实现（0x1015294a0，真身；
    //   0x101529458 那个只是转调，w3=0 表示非导出）：
    //
    //   1015294a0: cmp x2,#2 ; b.eq L2
    //   1015294a8: cmp x2,#1 ; b.ne L_cbnz
    //   1015294b0: d1 = -0.25 ; b L_add          ; mode==1 → -0.25
    //   1015294b8: L2: d1 = +0.25                 ; mode==2 → +0.25
    //   1015294bc: L_add: d0 = d0 + d1
    //   1015294e4: L_cbnz: cbnz x2 → L_cmp1
    //                      mov v1,d0
    //   1015294ec:          tbz w3,#0 → L_cmp1   ; mode==0 且 isExport==0
    //                                            ;   → 原值，**直接进 clamp**
    //   1015294c0: L_cmp1: fcmp d0, 1.0 ; b.mi → 取 1.0
    //   1015294cc:          d1 = 1.5
    //   1015294d0:          fcmp d0, 1.5
    //   1015294d4:          mov v1,d0
    //   1015294d8:          b.le → 返回 v1
    //   1015294dc:          d1 = 1.5            ; 超过 1.5 → 压到 1.5
    //   1015294f0: 返回 v1
    //
    // 也就是说 **无论 lineSpaceMode 是 0/1/2，出口一律被夹到 [1.0, 1.5]**。
    // 上一轮只在 mode 1/2 时改，mode 0 时直接把 1.637 写进
    // <w:spacing w:line="393">，比 App 自己导出的版本行距大一档 ——
    // 这就是「排版看起来还是不对」的直接原因。
    //
    // aiBeautify 分支不经过这里：setupParaStyle 在
    // 0x10147db18 处 cbz w27 直接 setLineHeightMultiple:1.25 并跳到
    // 0x10147dc84，压根不调 caculateLineHeightMultiple。
    // ═══════════════════════════════════════════════════════════════
    double multiple;
    const char *n;
    if (gCSFSAiBeautify) {
        multiple = 1.25;                 // 常量 @0x1088cdc50，不 clamp
        n = "aiBeautify";
    } else {
        double basePt = (fontPt > 1.0 && fontPt < 200.0) ? fontPt : 11.0;
        multiple = gap / (basePt * 1.44);   // 常量 @0x1088cbfb8
        if (gCSFSLineSpaceMode == 1)      multiple -= 0.25;
        else if (gCSFSLineSpaceMode == 2) multiple += 0.25;
        // 导出路径必须 clamp —— 与 App 导出同一口径
        if (multiple < 1.0) multiple = 1.0;
        if (multiple > 1.5) multiple = 1.5;
        n = "gap/formula+clamp";
    }
    if (multiple > 10.0) multiple = 10.0;      // 上限，防脏数据把行距拉爆

    long line = (long)(multiple * 240.0 + 0.5);
    if (line < 240) line = 240;
    if (why) *why = n;
    return line;
}

// 制表位：先按 twips 解读；若整体超出页面，按最大值等比压回内容宽。
// 这样即使单位是像素也能出一个「比例正确」的结果，而不是把 tab
// 甩到页面外（Word 会把越界 tab 当默认 tab 处理，反而更乱）。
static NSArray *CSFSNormalizeTabs(id raw, double basePt, const char **why) {
    if (why) *why = "-";
    if (![raw isKindOfClass:[NSArray class]]) return nil;
    NSArray *arr = (NSArray *)raw;
    if (arr.count == 0) return nil;

    NSMutableArray *vals = [NSMutableArray arrayWithCapacity:arr.count];
    double maxv = 0.0;
    for (id e in arr) {
        double d = CSFSDoubleValue(e);
        if (d <= 0) continue;
        [vals addObject:[NSNumber numberWithDouble:d]];
        if (d > maxv) maxv = d;
    }
    if (vals.count == 0) return nil;

    double scale = 1.0;
    const char *n = "twips";
    if (maxv > kCSFSContentTwips * 1.2) {
        scale = kCSFSContentTwips / maxv;   // 等比压回
        n = "scaled";
    } else if (maxv < 100.0) {
        scale = basePt * 20.0;              // 字符数
        n = "chars";
    } else if (maxv < kCSFSContentTwips * 0.15) {
        // 最大值还不到页宽的 15% —— 这组值不可能是 twips。
        // 正常制表位至少要能到达页面中部（两列的右列就在 50% 附近）；
        // 若真按 twips 用，所有 tab 会挤在左边一小块，
        // 比「不设制表位」还难看。这种情况交回调用方均分。
        if (why) *why = "reject-too-small";
        return nil;
    }
    if (why) *why = n;

    NSMutableArray *out = [NSMutableArray arrayWithCapacity:vals.count];
    double last = 0.0;
    for (NSNumber *e in vals) {
        double t = [e doubleValue] * scale;
        if (t <= last + 1.0) continue;      // 必须严格递增，否则 Word 忽略
        if (t > kCSFSContentTwips) break;
        [out addObject:[NSNumber numberWithDouble:t]];
        last = t;
    }
    return out.count ? out : nil;
}

static NSString *CSFSSliceText(id sl) {
    static NSArray *keys = nil;
    if (!keys) {
        keys = @[@"text", @"content", @"ocrText", @"ocr_text",
                 @"recognizeText", @"recognize_text",
                 @"handwriteText", @"handwrite_text",
                 @"resultText", @"string"];
    }
    // v31：`ws`（CSFSWhiteSpaceSet）原本只服务于那行「trim 后判空」，
    // 那行已删除，这里一并去掉，避免未使用变量告警。
    // 纯空白的判定现在完全交给 CSFSIsPureWhiteSpace。
    for (NSString *k in keys) {
        id v = CSFSValue(sl, k);
        if (![v isKindOfClass:[NSString class]]) continue;
        NSString *s = (NSString *)v;
        if (s.length == 0) continue;
        // ═══════════════════════════════════════════════════════════
        // v31：**纯空白必须保留，不能再当「没文字」丢掉**。
        //
        // 用户反馈：「文字之间有空格，或者带下划线的空格你都没识别出来」。
        //
        // 根因就在这里。原判据是
        //     if ([s stringByTrimming...].length == 0) continue;
        // 纯空白直接 continue → 这个 slice 拿不到文字 →
        //   · CSFSParseSlice 返回 nil → 空格消失，两侧文字贴在一起
        //   · 「带下划线的空格」（填空横线）通常是
        //     text=" " + font_attribute.underline=1，
        //     因为 text 先被丢掉，下划线属性也一起丢了 →
        //     整条填空线消失，看起来就是「没识别出来」
        //
        // 更关键的是：**空格在 OCR 的 JSON 里是一个独立 slice**。
        // 它与相邻文字 slice 之间的间隔不体现在 text 里，而体现在
        // slice 的 position/width 上；一旦我们把这个 slice 丢掉，
        // 就无法再从别处恢复这个间隔 —— 这不是「少一个字符」，
        // 是整段排版错位（两列被粘成一串）。
        //
        // 所以这里的判断要分两件事：
        //   ① 纯空白  → **是合法内容**，直接返回（空格本身就是内容）
        //   ② 空串    → 仍然跳过（没有任何字符）
        // 只有真正的空串才算「没文字」。
        // 注意不能顺手 trim：首尾空格在两端都是内容
        // （"___ 甲方" 这种靠前导空格对齐的排版很常见）。
        // ═══════════════════════════════════════════════════════════
        if (CSFSIsPureWhiteSpace(s)) {
            // 纯空白：保留原样（不 trim），它是合法的排版内容
            return s;
        }
        // v31：原来这里还有一行
        //     if ([s stringByTrimmingCharactersInSet:ws].length == 0) continue;
        // 现在它是死代码（纯空白在上面就 return 了，走到这里必然不是纯空白），
        // 但故意删掉 —— 留着会让下一个维护者以为「空格还是会被丢」，
        // 也会让 check_v31 的 S1 判据一直红。既有行为由上面那个分支保证。
        if (CSFSLooksLikePath(s)) continue;
        return s;
    }
    return nil;
}

// v21：判断一个 slice 是不是「图片片段」，是则返回图片信息。
//
// 依据：slice.stype 的类型编码是 T@"NSString"（不是 long），
// 且字符串池里同时出现 "paraSlices" 和 "imageSlices" ——
// 说明 slice 按类型分家，stype 就是那个类型字段。
//
// ⚠ 但 stype 的**具体取值**没有任何静态证据（二进制里只有键名，没有枚举值）。
//   所以这里不按「等于 image」精确匹配，而是看它**是否含有**图片语义的片段。
// v22：单独抽出来，因为统计日志要回答一个只有它能回答的问题 ——
//   「这个切片本来会被当成图片，是因为有文字才变成文字的」有多少个。
//   没有这个数，下一轮无法区分「App 没识别」和「我们判错了」。
static BOOL CSFSSTypeLooksImage(id sl) {
    id st = CSFSValue(sl, @"stype");
    if (![st isKindOfClass:[NSString class]]) return NO;
    NSString *s = [(NSString *)st lowercaseString];
    if (s.length == 0) return NO;
    return ([s containsString:@"image"] || [s containsString:@"img"] ||
            [s containsString:@"pic"] || [s containsString:@"stamp"] ||
            [s containsString:@"handwrit"] || [s containsString:@"photo"]);
}

// v22：在 stype 之前先加一道文字关 —— 有文字就不再考虑图。
static NSDictionary *CSFSSliceImageInfo(id sl) {
    // v22：文字优先。这一条必须排在 stype 判定之前：
    // 手写转文字后 stype 仍是 handwrite，但 text 已经填好了。
    if (CSFSSliceText(sl) != nil) return nil;
    if (!CSFSSTypeLooksImage(sl)) return nil;
    return CSFSFindImage(sl, 0);
}

// 把 JSON 里的一个 slice 解析成 run 字典。
// 解析失败也要返回一个只有文字的 run —— 宁可少格式，不能丢文字。
//
// diagnosticPtr：由调用方传入，首次解析时置 YES，把「真实结构」dump 一次。
// 为什么非要这段：字段名来自 Mach-O objc 元数据反推，键名已证实存在
// （font_color / font_face / font_style 是 T@"NSString",C,N；
//   font_attribute 是 T@"CSTranslateRawPageFont"），
// 但**层级归属**（谁挂在谁下面）无法靠静态分析确定。
// 这段 dump 一旦拿到日志，就能一次性定死，不用再猜。
static NSMutableDictionary *CSFSParseSlice(id sl, BOOL *diagnosticPtr) {
    // v22：文字统一走 CSFSSliceText（text 优先 + 别名兜底 + 排除路径）。
    // 原来只认 text，手写转文字的结果如果落在别的键上就整段丢字。
    NSString *t = CSFSSliceText(sl);
    if (t.length == 0) return nil;

    NSMutableDictionary *run = [NSMutableDictionary dictionaryWithCapacity:8];
    [run setObject:t forKey:kCSFSRunText];

    id style = CSFSValue(sl, @"style");

    if (diagnosticPtr && !*diagnosticPtr) {
        *diagnosticPtr = YES;
        CSFS_LOG(@"v21 DIAG slice %@", CSFSDescribeShape(sl));
        CSFS_LOG(@"v21 DIAG style %@", CSFSDescribeShape(style));
    }

    // 两路候选：style 优先，slice 自己兜底（万一 JSON 是扁平结构）。
    // style 若是字符串（样式名如 "body"）则不能当取值源，跳过。
    id sources[2];
    int nSrc = 0;
    if (style && ![style isKindOfClass:[NSString class]]) sources[nSrc++] = style;
    sources[nSrc++] = sl;

    id c = nil, f = nil, szObj = nil, attr = nil;
    for (int i = 0; i < nSrc; i++) {
        if (!c)     c     = CSFSValue(sources[i], @"font_color");
        if (!f)     f     = CSFSValue(sources[i], @"font_face");
        if (!szObj) szObj = CSFSValue(sources[i], @"font_size");
        if (!attr)  attr  = CSFSValue(sources[i], @"font_attribute");
    }

    // v23：font_attribute 才是字体属性的真正载体（类型就是
    // CSTranslateRawPageFont），上面只从它身上取了 bold/italic/underline，
    // 漏了字号和字体名。
    // 取值顺序 style → font_attribute → slice：前两者是专门的对象，
    // 比 slice 上的散字段更可能是权威值。
    if (!szObj) szObj = CSFSValue(attr, @"font_size");
    if (!szObj) szObj = CSFSValue(attr, @"size");
    if (!szObj) szObj = CSFSValue(attr, @"fontSize");
    if (!f)     f     = CSFSValue(attr, @"font_face");
    if (!c)     c     = CSFSValue(attr, @"font_color");

    if ([c isKindOfClass:[NSString class]]) {
        NSString *hex = CSFSNormalizeHexColor((NSString *)c);
        if (hex) [run setObject:hex forKey:kCSFSRunColor];
    }
    if ([f isKindOfClass:[NSString class]] && [(NSString *)f length] > 0) {
        [run setObject:(NSString *)f forKey:kCSFSRunFace];
    }
    // 字号合理性检查：OCR 偶尔给出 0 或离谱值（如 1000），
    // 越界的字号在 Word 里会被当成损坏样式，宁可不设。
    double sz = CSFSDoubleValue(szObj);
    if (sz > 2.0 && sz < 200.0) {
        [run setObject:[NSNumber numberWithDouble:sz] forKey:kCSFSRunSize];
    }

    // font_attribute 是 CSTranslateRawPageFont 对象（也可能被序列化成字典），
    // 同样两态通吃。bold/italic/underline 三项的声明类型都是 NSString，
    // 实际值可能是 "1"/"0"/"true"/"false"，CSFSBoolValue 都已覆盖。
    if (attr) {
        if (CSFSBoolValue(CSFSValue(attr, @"bold"))) {
            [run setObject:[NSNumber numberWithBool:YES] forKey:kCSFSRunBold];
        }
        if (CSFSBoolValue(CSFSValue(attr, @"italic"))) {
            [run setObject:[NSNumber numberWithBool:YES] forKey:kCSFSRunItalic];
        }
        if (CSFSUnderlineValue(CSFSValue(attr, @"underline"))) {
            [run setObject:[NSNumber numberWithBool:YES] forKey:kCSFSRunUnderline];
        }
    }

    // v33 诊断：纯空白 slice 到底拿没拿到 style / font_attribute。
    // 这是「该有下划线却没有」的定性依据，最多打 4 条。
    if (CSFSIsPureWhiteSpace(t)) {
        static long blankDiag = 0;
        if (blankDiag < 4) {
            blankDiag++;
            CSFS_LOG(@"v33 DIAG blank slice: style=%@ attr=%@ underRaw=%@"
                     @" face=%@ size=%@ len=%lu",
                     style ? NSStringFromClass([style class]) : @"(nil)",
                     attr ? CSFSDescribeShape(attr) : @"(nil)",
                     CSFSValue(attr, @"underline") ?: @"(nil)",
                     [run objectForKey:kCSFSRunFace] ?: @"(nil)",
                     [run objectForKey:kCSFSRunSize] ?: @"(nil)",
                     (unsigned long)t.length);
        }
    }

    // v24：这个 slice 前面该插制表符。
    //
    // add_tabstop 是 CSOcrPageSegmentParaSlice 的 ivar，App 自己就用它
    // 表示「本格与前一格之间是制表对齐」。v23 完全忽略它，把 slice
    // 首尾直连 —— 于是「出租方：董瀚霖身份证号：…（以下简称甲方）」
    // 挤成一串，而预览里是三列。这是行内版式对不上的直接原因。
    if (CSFSBoolValue(CSFSValue(sl, @"add_tabstop"))) {
        [run setObject:[NSNumber numberWithBool:YES] forKey:kCSFSRunTab];
    }

    // ═══════════════════════════════════════════════════════════════
    // v32：把 slice 的 width 带进 run —— 这是「下划线不够长」的解药。
    //
    // 用户反馈：
    //   「空格带下划线的长度应该不对，预览时看到虽然没有文字，
    //     但是下划线很长，你这个明显不够长，甚至有的本来有下划线的
    //     空格，你只有空格。」
    //
    // 原因很直接：空格 slice 的 text 就是一个 " "，v31 把它原样写进
    // Word，Word 就只画一个空格宽的下划线。但预览里那条线是
    // **slice.width 个像素**宽 —— 合同填空线常见的十几个字符宽。
    //
    // 这个 width 字段一直在 JSON 里（v21 DIAG slice 的键列表就有 width），
    // 但此前从来没被读过（全文件搜 @\"width\" 只命中一处无关代码）。
    // 现在读出来，渲染时按「宽度 ÷ 单空格宽」展开成够多的空格，
    // 下划线长度就与预览一致了。
    //
    // 只对**纯空白** run 记这个值：普通文字 run 的宽度由字体自然决定，
    // 强行加宽反而会把字距拉坏。
    // ═══════════════════════════════════════════════════════════════
    if (CSFSIsPureWhiteSpace(t)) {
        double sw = CSFSDoubleValue(CSFSValue(sl, @"width"));
        if (sw > 0.0) {
            [run setObject:[NSNumber numberWithDouble:sw] forKey:kCSFSRunSpaceW];
        }
    }

    return run;
}

// v22：para.justification → w:jc 合法值。
//
// 抽成函数的原因很实际：v21 这段内联在 para 循环里，v22 的 IMAGE 块
// 也要生成文字段落，如果各写一份，两处迟早会漂。
// 注意 w:jc 的合法取值只有 left / center / right / both / distribute，
// **不存在 "justify"**，写成 justify 会被 Word 静默忽略。
static NSString *CSFSMapJustification(id just) {
    NSString *justStr = nil;
    if ([just isKindOfClass:[NSString class]]) {
        justStr = (NSString *)just;
    } else if ([just isKindOfClass:[NSNumber class]]) {
        justStr = [(NSNumber *)just stringValue];
    }
    if (justStr.length == 0) return nil;
    NSString *j = [justStr lowercaseString];
    if ([j isEqualToString:@"center"] || [j isEqualToString:@"1"]) return @"center";
    if ([j isEqualToString:@"right"] || [j isEqualToString:@"right_align"] ||
        [j isEqualToString:@"2"]) return @"right";
    if ([j isEqualToString:@"both"] || [j isEqualToString:@"justify"] ||
        [j isEqualToString:@"justified"] || [j isEqualToString:@"3"]) return @"both";
    return nil;
}

// v22：把「一个块里已有的识别文字」抽成 styled 段落数组。
//
// 这个函数存在的唯一理由：
//   开了「手写转文字」之后，手写区在 JSON 里仍然是一个 IMAGE 块
//   （版面语义上它确实是图），识别结果压在块内部。
//   只要块里能抠出文字，就必须按文字导出，不能插图。
//
// 两条路径，先结构化后兜底：
//   ① block.paras[].slices[] —— 与普通 PARA 块完全一致的结构，最可靠
//   ② block 自身的文字字段（text / content / ocrText …）—— 兜底，
//      同样要过「非空、非纯空白、不像路径」三关
// 返回的每个元素就是一个 para 字典（kCSFSParaRuns + 可选 kCSFSParaAlign）。
static NSArray *CSFSBlockTextParas(id block) {
    NSMutableArray *out = [NSMutableArray array];
    if (!block) return out;

    // ① 结构化路径
    id paras = CSFSValue(block, @"paras");
    if ([paras isKindOfClass:[NSArray class]]) {
        for (id para in (NSArray *)paras) {
            id slices = CSFSValue(para, @"slices");
            if (![slices isKindOfClass:[NSArray class]]) continue;
            NSMutableArray *runs = [NSMutableArray array];
            for (id sl in (NSArray *)slices) {
                // 这里**不判图**：能走到 CSFSBlockTextParas 的前提就是
                // 调用方已经决定「有文字就用文字」，图片分支不再参与。
                NSMutableDictionary *run = CSFSParseSlice(sl, NULL);
                if (!run) continue;
                [runs addObject:run];
            }
            if (runs.count == 0) continue;
            NSMutableDictionary *p = [NSMutableDictionary dictionaryWithCapacity:2];
            [p setObject:runs forKey:kCSFSParaRuns];
            NSString *jc = CSFSMapJustification(CSFSValue(para, @"justification"));
            if (jc) [p setObject:jc forKey:kCSFSParaAlign];
            [out addObject:p];
        }
    }
    if (out.count > 0) return out;

    // ② 块自身字段兜底。CSFSSliceText 已经带三关校验，直接复用。
    NSString *own = CSFSSliceText(block);
    if (own.length > 0) {
        NSMutableDictionary *run = [NSMutableDictionary dictionaryWithCapacity:1];
        [run setObject:own forKey:kCSFSRunText];
        NSMutableDictionary *p = [NSMutableDictionary dictionaryWithCapacity:1];
        [p setObject:[NSMutableArray arrayWithObject:run] forKey:kCSFSParaRuns];
        NSString *jc = CSFSMapJustification(CSFSValue(block, @"justification"));
        if (jc) [p setObject:jc forKey:kCSFSParaAlign];
        [out addObject:p];
    }
    return out;
}

// v22：把 styled 段落数组拼成纯文本，用于「同一段文字是否已存在」的判断。
// 只取文字，不管格式 —— 去重要比的是内容。
static NSString *CSFSParasPlainText(NSArray *paras) {
    NSMutableString *m = [NSMutableString string];
    for (NSDictionary *p in paras) {
        id rs = [p objectForKey:kCSFSParaRuns];
        if (![rs isKindOfClass:[NSArray class]]) continue;
        for (NSDictionary *r in (NSArray *)rs) {
            id t = [r objectForKey:kCSFSRunText];
            if ([t isKindOfClass:[NSString class]]) [m appendString:(NSString *)t];
        }
        [m appendString:@"\n"];
    }
    return m;
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

// v20：把一段段落字典渲染成完整的 <w:p>…</w:p>。
//
// ⚠ v18/v19 在这里漏了最外层的 <w:p>，只输出了 <w:pPr>+<w:r> 裸片段。
//   后果不是「格式丢失」而是**整个文件打不开**：
//   Word 报「在试图打开文件时遇到错误」，因为
//     · CT_Body 只允许块级元素（p/tbl/sdt…），body 下直接出现 pPr/r 是违规
//     · CT_P 里 pPr 的 maxOccurs=1，且必须在首位，不能夹在 run 之间
//   这是比 v17「无法读取的内容」更前置的错误 —— Word 连容错解析都不做。
//
// Word 的字号单位是「半磅」(half-point)，所以 pt × 2。
// 颜色写成 <w:color w:val="FF0000"/>，不带 # 号，否则 Word 会忽略这个属性。
//
// ⚠ <w:rPr> 的子元素是 xsd:sequence，顺序错 Word 同样拒收。
//   ECMA-376 规定的顺序（节选）：
//     rStyle → rFonts → b → bCs → i → iCs → … → color → … → sz → szCs
//     → highlight → u → …
//   所以 rFonts 必须写在 b 前面，u 必须写在 sz 后面。
//   v19 把 rFonts 写在 color 之后、u 写在最前，两个位置都是错的。
// ═════════════════════════════════════════════════════════════════════
// v32：把「一个空格」撑成「预览里那么宽」。
//
// 用户原话：
//   「空格带下划线的长度应该不对，预览时看到虽然没有文字，但是下划线很长，
//     你这个明显不够长，甚至有的本来有下划线的空格，你只有空格。」
//
// 两件事必须同时成立才对得上预览：
//   ① 下划线属性要带上（v31 已经修好了 text 被丢的问题，但只带一个空格）
//   ② 空格的**个数**要按 slice.width 展开 —— 一个空格的宽度只代表
//      「一个半角字」，而预览里那条填空线可能横跨十几个字。
//
// 换算链条（全部有据，不猜）：
//   slice.width        页面像素
//   × gCSFSPageScale   → 渲染 pt（与 App setupParaStyle 里同一个 scale）
//   ÷ 字号(pt)         → 该字号下一个半角空格的个数
//                        半角空格宽 ≈ 0.5 em，em = 字号 pt
//   所以 n = 渲染pt ÷ (0.5 × 字号)
//
// 没有 scale 时（真机日志 scale=0.0000）退一步：按 A4 内容宽度折算。
// 1654px ≈ A4@200dpi，与 CSFSIndentTwips 的退路保持同一口径，
// 保证「宽度」和「缩进」两处不会各用一套比例。
// ═════════════════════════════════════════════════════════════════════
// ═════════════════════════════════════════════════════════════════════
// v35：估算一个 run 在 Word 里占多宽（pt）
//
// 为什么必须估：Word 是**流式排版**，而 OCR 给的是**绝对版面**。
// 只要某行的自然宽度比页宽多出几个 pt，Word 就折行；
// 折行之后 `jc=both` 会把「除末行以外的每一行」强行撑满页宽 ——
// 于是「出 租 方 ：」被拉成两倍多字距。用户说的「乱七八糟」就是这个。
//
// 真机实测（v34 导出的 docx → Word → PDF，用 pymupdf 逐字量 bbox）：
//   p1「出租方：…」 自然宽 470.4pt，页宽 451.3pt，超 19.1pt
//      → 折成 2 行 → 首行字距 24.2pt（10.5pt 的字本应步进 10.5pt，撑到 2.3 倍）
//   p3「中介方：…」 自然宽 463.3pt，超 12.0pt
//      → 折成 4 行 → 「中」「介」「方：」各自被撑成一行
//
// 那 19pt 从哪来？`22018220040518001x` 这 18 个字符用 Calibri 渲染，
// 实测占 134.3pt（0.71em/字符）；宋体数字是 0.5em，只需 94.5pt。
// v34 只统一了**空白 run** 的字体，文字 run 还是 Calibri —— 差出 40pt。
//
// 结论：① 字体要统一到中文字体；② 每段写入前必须做一次宽度预算。
// ═════════════════════════════════════════════════════════════════════
static double CSFSEstRunWidthPt(NSDictionary *r, double paraPt) {
    NSString *t = [r objectForKey:kCSFSRunText];
    if (![t isKindOfClass:[NSString class]] || t.length == 0) return 0.0;

    double fs = CSFSDoubleValue([r objectForKey:kCSFSRunSize]);
    if (!(fs > 2.0) || fs > 200.0) fs = paraPt;
    if (!(fs > 2.0) || fs > 200.0) fs = 11.0;

    // 空白 run 有 slice.width（版面实测值），比按字符数估算准得多。
    double sw = CSFSDoubleValue([r objectForKey:kCSFSRunSpaceW]);
    if (CSFSIsPureWhiteSpace(t) && sw > 0.0) return sw;

    double w = 0.0;
    NSUInteger n = t.length;
    for (NSUInteger i = 0; i < n; i++) {
        unichar c = [t characterAtIndex:i];
        // 汉字与全角标点 1em；ASCII / 半角 0.5em。
        // 宋体里数字字母确实是 0.5em —— 这条只在字体统一之后才成立，
        // 也正是上面那条 40pt 差额的来源。
        w += (c >= 0x2E80) ? fs : (fs * 0.5);
    }
    // v35：实测校正系数 1.06。
    // 从导出的 PDF 逐字量 advance：10.5pt 的宋体全角字实测占 11.1pt
    // （10.6 的墨水宽 + 侧边距）。按 1.0em 估会系统性偏小 6% ——
    // p1 就是差这一点点，估算说「装得下」，Word 说「装不下」。
    // 宁可估大一点被多压 6% 的空白，也不要估小了整行折行、
    // 再被 jc=both 撑成两倍字距。
    return w * 1.06;
}

// ═════════════════════════════════════════════════════════════════════
// v36：宽度预算的结论用位标志返回。
//
// v35 只返回一个 BOOL（「要不要改左对齐」），装不下第二个结论。
// 而真机第一轮就暴露出：这段既需要「别缩进」，也需要「保持两端对齐」，
// 用一个 BOOL 表达就只能二选一。
// ═════════════════════════════════════════════════════════════════════
#define kCSFSFitLeft      1   // jc 建议改成 left
#define kCSFSFitNoIndent  2   // 清掉首行缩进：缩进是这段折行的唯一原因

// ═════════════════════════════════════════════════════════════════════
// v36：把空白 run 按比例缩 —— **宽度字段和字符数必须一起改**。
//
// v35 只改了 kCSFSRunSpaceW（只参与估算），而写 XML 时走的是
// text.length。真机日志铁证：
//   v35 tailfit: tailSum=114.0 noTail=331.0 avail=429.3 ratio=0.836
// 报着「压到 83.6%」，导出 XML 里那个 run 仍然是原样的 22 个空格
// （转成 11 个 NBSP）—— 宽度字段压根不进 XML。
// 结果是：估算按压过的算（说装得下），实际按没压的排（照样折行），
// 两头都不对，还看不出是哪儿的问题。
// ═════════════════════════════════════════════════════════════════════
static void CSFSScaleSpaceRuns(NSMutableArray *runs, BOOL onlyTail, double ratio) {
    if (!(ratio > 0.0) || ratio >= 0.999) return;
    NSUInteger cnt = [runs count];
    for (NSUInteger i = 0; i < cnt; i++) {
        id o = [runs objectAtIndex:i];
        if (![o isKindOfClass:[NSMutableDictionary class]]) continue;
        NSMutableDictionary *r = (NSMutableDictionary *)o;
        if (onlyTail && ![[r objectForKey:kCSFSRunTail] boolValue]) continue;
        NSString *t = [r objectForKey:kCSFSRunText];
        if (!CSFSIsPureWhiteSpace(t) || t.length == 0) continue;
        double sw = CSFSDoubleValue([r objectForKey:kCSFSRunSpaceW]);
        if (sw > 0.0) {
            [r setObject:[NSNumber numberWithDouble:sw * ratio]
                  forKey:kCSFSRunSpaceW];
        }
        NSUInteger nn = (NSUInteger)((double)t.length * ratio + 0.5);
        if (nn < 1) nn = 1;
        if (nn != t.length) {
            NSMutableString *ns = [NSMutableString stringWithCapacity:nn];
            for (NSUInteger k = 0; k < nn; k++) [ns appendString:@" "];
            [r setObject:ns forKey:kCSFSRunText];
        }
    }
}

// ═════════════════════════════════════════════════════════════════════
// v35：段落宽度预算 —— 保证「本来一行」的段落不被挤成两行
//
// 判据只有三条，宁可不动也不乱动：
//   ① 自然宽度 ≤ 可用宽度        → 装得下，一个字节都不改
//   ② 自然宽度 > 可用宽度 × 1.9  → 这是长段落，文字本来就要折好几行，
//                                  压空白只会让行数更多，放弃
//   ③ 只有「差几十 pt 就能一行装下」的段落才按比例压空白
//
// 只压**有 slice.width 的空白**，不动文字、不动缩进 ——
// 文字宽度是 OCR 识别出来的事实，空白宽度才是可以商量的排版量。
// ═════════════════════════════════════════════════════════════════════
static int CSFSFitParaWidth(NSMutableArray *runs, double paraPt, long indentTw,
                            BOOL *outDropIndent) {
    if (outDropIndent) *outDropIndent = NO;
    if (![runs isKindOfClass:[NSMutableArray class]] || [runs count] == 0) return 0;

    double lineW = kCSFSContentTwips / 20.0;
    if (!(lineW > 40.0)) return 0;

    double indentPt = (double)indentTw / 20.0;
    if (indentPt < 0.0 || indentPt > lineW * 0.5) indentPt = 0.0;
    double avail = lineW - indentPt;
    if (!(avail > 60.0)) return 0;

    NSUInteger cnt = [runs count];
    double total = 0.0, spaceSum = 0.0, tailSum = 0.0, noTail = 0.0;
    for (NSUInteger i = 0; i < cnt; i++) {
        NSDictionary *r = [runs objectAtIndex:i];
        double w = CSFSEstRunWidthPt(r, paraPt);
        total += w;
        BOOL isTail = [[r objectForKey:kCSFSRunTail] boolValue] &&
                      CSFSIsPureWhiteSpace([r objectForKey:kCSFSRunText]);
        if (isTail) tailSum += w; else noTail += w;
        double sw = CSFSDoubleValue([r objectForKey:kCSFSRunSpaceW]);
        if (sw > 0.0 && CSFSIsPureWhiteSpace([r objectForKey:kCSFSRunText])) {
            spaceSum += sw;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // v35：段尾留白是「填充」，不是「内容」，必须自适应剩余宽度。
    //
    // 真机 p3 是：中介方：+ 43 空格 + 3 空格 + 经纪人：+ 22 空格
    // 前面 43 个空格是版面实测宽度（225pt，要画下划线，不能动），
    // 后面 22 个空格是「经纪人：」到行尾的填充 —— 而 App 给的
    // 页宽和 Word 的页宽并不完全一致，这截填充按原值写出去
    // 正好把行顶爆，折行后 jc=both 又把「中」「介」「方：」撑开。
    //
    // 填充没有语义，裁短不改变任何文字位置；
    // 而它后面的东西根本不存在，所以「裁到剩余宽度」是零损失的。
    // ═══════════════════════════════════════════════════════════════
    // ═══════════════════════════════════════════════════════════════
    // v36：缩进是这段折行的**唯一原因** → 顶格，不缩进。
    //
    // 真机第一轮（v35）导出 PDF 后逐行量 bbox 的实测：
    //   p1 出租方  缩进 21pt，内容 413.7pt → 408.3pt 装得下 → 一行 ✓
    //   p2 承租方  缩进 21pt，内容 442.0pt → 装不下 → 折掉「方）」2 字
    //   p3 中介方  缩进 21pt，内容 451.5pt → 装不下 → 折掉「人：」
    // 而 App 预览截图里这三段都是**顶格**的（「出租方：」与下面
    // 「根据《中华人民共和国民法典》」左边缘对齐，见用户截图）。
    //
    // 顶格后：p2 需 442.0 < 451.3 ✓；p3 需 451.5 ≈ 451.3（差 0.2pt）。
    // 也就是说这 21pt 缩进是折行的全部原因 —— 与空白长短无关。
    // v35 一直在压空白（而且只改宽度字段没改字符数，等于没压）。
    //
    // 判据刻意保守，四条同时成立才清缩进：
    //   · 有缩进（> 1pt），否则谈不上「去掉」
    //   · 加了缩进装不下
    //   · 顶格后装得下（total ≤ 整行宽 × 估算偏差容差）
    //   · 不是长段落（长段落本来就要折好几行，缩进不是原因）
    // 四条的实质是：「同一段话，缩进就两行、顶格就一行」——
    // 这种时候版式让位于行数。
    //
    // ═══════════════════════════════════════════════════════════════
    // 【为什么容差是 1.18，不是 1.06】
    //
    // 估算是**系统性偏大**的：v35 日志与 Word 实测对照
    //   p1 估算 459.9pt / 真实 413.7pt → 偏大 11.2%
    // 因为字宽模型是粗的（汉字按 1em、半角按 0.5em），
    // 而真实文本里全角标点、连字符、字距都会吃掉一些。
    //
    // 按 1.06 卡上限，反推真机三段估算值：
    //   p2 442.0 × 1.112 ≈ 491.5   > 451.3 × 1.06 = 478.4  ✗
    //   p3 451.5 × 1.112 ≈ 502.1   > 478.4                 ✗
    // 也就是说 1.06 会让这条分支**一次都不触发** —— 改动白写，
    // 而且日志里只会看到 overflow，看不出是阈值卡掉了。
    // 这跟 v35 的 squeeze 一次没跑是同一个坑：阈值按"我以为的
    // 误差"定，而不是按"实测到的误差"定。
    //
    // 1.18 = 11.2% 偏差 + 6% 余量。上界的安全边际来自另一侧：
    // 长段落估算在 900~4000pt，远大于 451.3 × 1.18 = 532.5，
    // 不会因为放宽而被误判成"顶格就好"。
    //
    // 【但这次三段其实不走这条分支】
    // 日志里 `fallback-2chars` 出现 3 次 → 说明 fl 字段就是 0，
    // 也就是 OCR 明确说了「顶格」。删掉兜底之后 indFirst 本来就是 0，
    // indentPt = 0，这条分支连条件都不满足 —— 三段自动顶格。
    //
    // 所以本次修复的主路径是「删兜底」（I 组），这里只是保险：
    // 万一将来某个文档 OCR 真的给了 fl > 0，但加缩进会折行，
    // 才由它来清。**不要因为真机上 branch 没触发就去调这个系数** ——
    // 没触发恰恰是正常的。
    // ═══════════════════════════════════════════════════════════════
    int flags = 0;
    if (indentPt > 1.0 && total > avail && total <= lineW * 1.18 &&
        total > avail * 0.6) {
        flags |= kCSFSFitNoIndent;
        if (outDropIndent) *outDropIndent = YES;
        CSFS_LOG(@"v36 dropindent: total=%.1f availInd=%.1f lineW=%.1f（顶格才放得下）",
                 total, avail, lineW);
        avail = lineW;
        indentPt = 0.0;
        // ═══════════════════════════════════════════════════════════
        // 顶格之后**不再压任何空白**，直接出结论。
        //
        // 理由是估算本身偏大：实测 p1 估算 459.9pt、Word 真实排 413.7pt，
        // 偏大 11%。按这个数去「挤进一行」，会把 p1 那 18 个空格
        // 压掉 13% —— 而那 18 个空格正是用户要的身份证下划线长度，
        // 实际根本不需要压。v35 的 squeeze 就是这样误伤的。
        //
        // 缩进既然是折行的唯一原因，去掉缩进就够了；
        // 剩下的余量问题交给对齐（单行段落改不改 jc 没有视觉差别，
        // 多行段落改了正好避免 jc=both 撑开字距）。
        // ═══════════════════════════════════════════════════════════
        double rem0 = fmod(total, avail);
        if (rem0 > 0.0 && rem0 < avail * 0.5 && total < avail * 1.35) {
            flags |= kCSFSFitLeft;
        }
        return flags;
    }

    if (tailSum > 0.0) {
        double room = avail - noTail;
        if (room < 2.0) room = 2.0;
        double target = room * 0.97;
        if (tailSum > target) {
            double r2 = target / tailSum;
            if (r2 < 0.05) r2 = 0.05;
            CSFSScaleSpaceRuns(runs, YES, r2);
            CSFS_LOG(@"v35 tailfit: tailSum=%.1f noTail=%.1f avail=%.1f ratio=%.3f",
                     tailSum, noTail, avail, r2);
            total = noTail + target;
        }
    }

    if (total <= avail) return flags;              // ① 装得下

    // ═══════════════════════════════════════════════════════════════
    // v35：只差 5% 以内的段落，压一点留白把它挤进一行。
    //
    // 真机 p2（承租方）自然宽 442pt、可用 430pt，只超 12pt ——
    // 折行后第二行只剩「方）」三个字，和预览里「承租方」独占一行的
    // 样子差得很远。这 12pt 摊到 47 个字符上，每字只要挤 0.26pt
    // （≈5 twips），比折出一行残字自然得多。
    //
    // 但压的对象只能是**留白**，而且限制在 50% 以内：
    //   · 压的是空白 run 的宽度 = 下划线长度，压过头就退回
    //     「你这个明显不够长」；
    //   · 估算本身有 ±5% 误差，所以这条只用于「差一点点」的情形，
    //     差得多的段落宁可折行也不动它的长度。
    // ═══════════════════════════════════════════════════════════════
    if (total <= avail * 1.05 && spaceSum > 1.0) {
        double need = total - avail * 0.99;
        double ratio = (spaceSum - need) / spaceSum;
        if (ratio >= 0.5 && ratio < 0.999) {
            CSFSScaleSpaceRuns(runs, NO, ratio);
            CSFS_LOG(@"v35 squeeze: total=%.1f avail=%.1f spaceSum=%.1f ratio=%.3f",
                     total, avail, spaceSum, ratio);
            return flags;                          // 挤进一行了，保持两端对齐
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // 差得多的段落：**不压行中空白**，只放弃两端对齐。
    //
    // 曾经写过一版「按比例压缩空白直到装下」，实测不可取：
    // 空白宽度就是用户反复要求的「下划线长度」，压它就是退回
    // v32 的老毛病（「你这个明显不够长」）。
    //
    // 折行本身不是问题 —— 长段落人人都在折行。真正难看的是
    // jc=both 把「除末行外的每一行」强行撑满：
    //   p1 末行只剩 44pt（10% 行宽）→ 首行 24 个单元要摊掉 257pt
    //   → 每字多 10.7pt → 10.5pt 的字步进 24.2pt，2.3 倍
    // 只要这一段改成左对齐，折行位置和字距都恢复正常。
    // ═══════════════════════════════════════════════════════════════
    double rem = fmod(total, avail);
    BOOL suggestLeft = (rem > 0.0 && rem < avail * 0.5) && (total < avail * 1.35);
    if (suggestLeft) flags |= kCSFSFitLeft;
    CSFS_LOG(@"v35 overflow: total=%.1f avail=%.1f rem=%.1f left=%d",
             total, avail, rem, (int)suggestLeft);
    return flags;
}

// ═════════════════════════════════════════════════════════════════════
// v34：纯空白 run 的样式补齐 —— 修「长度不够」与「多画了假下划线」
//
// 这一版是被真机导出的 document.xml 直接推翻 v33 两条判断之后重写的，
// 两条都不是猜出来的，是对着 47 个空白 run 逐条数出来的：
//
// 【推翻一】v33 说「空白 run 没有字体所以腰斩」，只对了一半
//   实测：47 个空白 run 里 43 个**都有** rFonts，写的是
//     <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri"/>
//   它们不缺字体，缺的是「能撑住 0.5em 的字体」。
//   U+0020 属于 ASCII，Word 严格按 w:ascii 取字形：
//     Calibri 空格 0.226em × 10.5pt = 2.37pt
//     宋体   空格 0.500em × 10.5pt = 5.25pt      差 2.2 倍
//   按 0.5em 算出 11 个空格，Word 里只占 26pt，而 slice.width = 56pt。
//   这正是「有的空格下划线还是不够长」。
//   而 v33 的兜底只在 face **为空**时触发，face 明明是 "Calibri"，
//   兜底一次都没跑（日志 fillBody 恒为 0）——
//   **兜底把错误本身藏起来了**，这已经是这个项目里第二次栽在兜底上。
//
//   所以判据不能是「有没有字体」，必须是「这个字体撑不撑得住 0.5em」。
//   空格是看不见的，换掉字体名不改变任何视觉，只把宽度修正回来。
//
// 【推翻二】v33 用「宽度 ÷ 字号 ≥ 2em」猜下划线，是错的
//   把 v32 与 v33 导出的同一份文档逐条对齐：
//     v32 空白 run 47 个，带下划线 21 个
//     v33 空白 run 47 个，带下划线 26 个
//   多出来的 5 个全部落在合同末尾的签字区：
//     prev='董瀚霖'      next='乙方：'       len=12
//     prev='地址：'      next='地址：'       len=26
//     prev='地址：'      next='电话：'       len=25
//     prev='9845254499'  next='电话：'       len=5
//     prev='5586699161'  next='签订日期：'   len=4
//   这些空白是用来把「乙方：」「电话：」推到行右侧的**排版留白**，
//   宽度当然远超 2em —— 宽度只能说明「这儿空着」，不能说明「这儿有根线」。
//   缩进、居中留白、签名区空白，宽度全都比 2em 大。用户报的
//   「本来不应该有下划线的地方也出现了下划线」就是这 5 条。
//
//   所以补线只认**数据**：slice 自己带 underline 才画。
//   不按宽度猜，也不从邻居继承 —— 继承同样是猜（「地址：」那格本身
//   就没有线）。少一根线，远好过多一根假线。
//
// 保留 v33 做对的部分：字号缺失时从邻居继承、以及 NBSP 换行尾空格。
// ═════════════════════════════════════════════════════════════════════
static int CSFSFixSpaceRuns(NSMutableArray *runs, double paraPt, long indentTw) {
    if (![runs isKindOfClass:[NSMutableArray class]] || [runs count] == 0) return 0;

    static long fixLogCount = 0;   // 明细日志最多 6 条，防刷屏
    NSUInteger cnt = [runs count];
    long fillSize = 0, faceFix = 0, fillBody = 0, underNative = 0;
    long textFaceFix = 0, tailDrop = 0, tabDrop = 0;

    // ── 定下「空白 run 该用的字体」────────────────────────────────
    //
    // 要求只有一条：空格宽度 = 0.5em，也就是必须是中文字体。
    // 优先用全文正文字体（它多半就是 SimSun），但它很可能是 Calibri，
    // 那就退一步在全文里找任何一个中文名，再不行才用「宋体」。
    //
    // 注意这里**必须覆盖原文体**，不能只在为空时兜底 ——
    // 见上面「推翻一」：空白 run 的 face 几乎都是非空的 Calibri。
    if (!CSFSIsCJKFace(gCSFSBodyFace)) {
        gCSFSBodyFace = nil;
        for (NSUInteger i = 0; i < cnt && gCSFSBodyFace.length == 0; i++) {
            NSDictionary *c = [runs objectAtIndex:i];
            if (CSFSIsPureWhiteSpace([c objectForKey:kCSFSRunText])) continue;
            NSString *cf = [c objectForKey:kCSFSRunFace];
            if (CSFSIsCJKFace(cf)) gCSFSBodyFace = [cf copy];
        }
        if (gCSFSBodyFace.length == 0) gCSFSBodyFace = @"宋体";
    }
    NSString *wideFace = gCSFSBodyFace;

    for (NSUInteger i = 0; i < cnt; i++) {
        id obj = [runs objectAtIndex:i];
        if (![obj isKindOfClass:[NSMutableDictionary class]]) continue;
        NSMutableDictionary *r = (NSMutableDictionary *)obj;

        NSString *t = [r objectForKey:kCSFSRunText];

        // ═══════════════════════════════════════════════════════════
        // v35：**文字 run 的字体也要统一**，不能只管空白。
        //
        // v34 漏了这一半。真机导出的 p1 里
        //   <w:rFonts w:ascii="Calibri"/> 22018220040518001x
        // 这 18 个字符实测占 134.3pt（0.71em/字符），
        // 换成宋体后只需 94.5pt（0.5em）—— 一条 run 就差 40pt，
        // 正好把整行顶过页宽 19pt，折行后触发字距撑开。
        //
        // 数字、字母、标点一律跟中文走同一套字体，是这份合同的原始版式
        // （预览截图里身份证号与该行中文同宽），不是我们另立的规矩。
        // ═══════════════════════════════════════════════════════════
        if (!CSFSIsPureWhiteSpace(t)) {
            NSString *tf = [r objectForKey:kCSFSRunFace];
            if (![tf isKindOfClass:[NSString class]]) tf = nil;
            if (!CSFSIsCJKFace(tf)) {
                [r setObject:wideFace forKey:kCSFSRunFace];
                textFaceFix++;
            }
            continue;
        }

        // 1) 字体：不是中文字体就换掉（空格宽度才有 0.5em）
        NSString *face0 = [r objectForKey:kCSFSRunFace];
        if (![face0 isKindOfClass:[NSString class]]) face0 = nil;
        if (!CSFSIsCJKFace(face0)) {
            if (fixLogCount < 6) {
                fixLogCount++;
                BOOL wasCalibri =
                    ([face0.lowercaseString rangeOfString:@"calibri"].location != NSNotFound);
                CSFS_LOG(@"v34 spcfix: face %@ -> %@ (该字体空格 %.3fem，"
                         @"换成 0.500em 才能对上 slice.width) len=%lu",
                         face0.length > 0 ? face0 : @"(nil)", wideFace,
                         wasCalibri ? 0.226 : 0.0,
                         (unsigned long)t.length);
            }
            if (face0.length == 0) fillBody++; else faceFix++;
            [r setObject:wideFace forKey:kCSFSRunFace];
        }

        // 2) 字号：缺失时从同段相邻文字 run 继承（版式继承，不是猜）
        if ([r objectForKey:kCSFSRunSize] == nil) {
            for (NSInteger j = (NSInteger)i - 1; j >= 0; j--) {
                NSDictionary *c = [runs objectAtIndex:(NSUInteger)j];
                if (CSFSIsPureWhiteSpace([c objectForKey:kCSFSRunText])) continue;
                if ([c objectForKey:kCSFSRunSize]) {
                    [r setObject:[c objectForKey:kCSFSRunSize] forKey:kCSFSRunSize];
                    fillSize++;
                }
                break;
            }
        }

        // 3) 下划线：只统计，不修改。
        //    v33 在这里按 em>=2.0 补线，制造了 5 条假线（见函数头注释）。
        if ([[r objectForKey:kCSFSRunUnderline] boolValue]) underNative++;
    }

    // ═══════════════════════════════════════════════════════════════
    // v35：行尾空白丢弃 —— 但**带下划线的不能丢**。
    //
    // 真机 p3（中介方）行末挂着 22 个空格 = 115.5pt，
    // 整行自然宽 442.3pt + 缩进 21pt = 463.3pt，比页宽多 12pt。
    // 折行后 jc=both 就把「中」「介」「方：」各自撑成一行。
    //
    // 行尾留白在 Word 里没有任何排版意义 —— 它唯一的作用
    // 就是把段落顶出边界。制表位、右对齐才是表达「推到行右」的手段。
    //
    // 但 v35 第一版把带下划线的段尾空白也删了，那等于把
    // 「出租方：张三______」这种挂在段尾的填空线整条抹掉。
    // 判据必须是「有没有下划线」，不是「在不在段尾」。
    // ═══════════════════════════════════════════════════════════════
    NSInteger lastKeep = -1;
    for (NSInteger i = (NSInteger)cnt - 1; i >= 0; i--) {
        NSDictionary *c = [runs objectAtIndex:(NSUInteger)i];
        NSString *ct = [c objectForKey:kCSFSRunText];
        BOOL ws = CSFSIsPureWhiteSpace(ct);
        BOOL und = [[c objectForKey:kCSFSRunUnderline] boolValue];
        // 文字 run，或者「带下划线且确实有字符」的空白 run —— 都得留
        if (!ws || (und && [ct isKindOfClass:[NSString class]] && ct.length > 0)) {
            lastKeep = i;
            break;
        }
    }
    if (lastKeep >= 0 && (NSUInteger)lastKeep + 1 < cnt) {
        for (NSUInteger i = (NSUInteger)lastKeep + 1; i < cnt; i++) {
            id o = [runs objectAtIndex:i];
            if (![o isKindOfClass:[NSMutableDictionary class]]) continue;
            NSMutableDictionary *r = (NSMutableDictionary *)o;
            NSString *ct = [r objectForKey:kCSFSRunText];
            if ([ct isKindOfClass:[NSString class]] && ct.length > 0 &&
                CSFSIsPureWhiteSpace(ct)) {
                [r setObject:@"" forKey:kCSFSRunText];
                [r setObject:[NSNumber numberWithDouble:0.0] forKey:kCSFSRunSpaceW];
                [r setObject:[NSNumber numberWithBool:YES] forKey:kCSFSRunTail];
                tailDrop++;
            }
        }
    }
    // v35：把「真正落在段尾的那个空白 run」标出来，供渲染时决定是否换 NBSP。
    if (lastKeep >= 0 && (NSUInteger)lastKeep < cnt) {
        id o = [runs objectAtIndex:(NSUInteger)lastKeep];
        if ([o isKindOfClass:[NSMutableDictionary class]]) {
            NSMutableDictionary *lr = (NSMutableDictionary *)o;
            NSString *lt = [lr objectForKey:kCSFSRunText];
            if ([lt isKindOfClass:[NSString class]] && lt.length > 0 &&
                CSFSIsPureWhiteSpace(lt)) {
                [lr setObject:[NSNumber numberWithBool:YES] forKey:kCSFSRunTail];
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // v35：删掉与「已展开空白」重复的 tab。
    //
    // 真机 p3 的 run 序列是：
    //   中介方： | 43 个空格（sw=225.8）| <w:tab pos=4513> | 3 个空格 | 经纪人：
    //
    // 43 个空格已经把「经纪人：」推到 225pt 处，Tab 又推一次 ——
    // Word 发现当前位置已越过 4513 twips 的制表位，就跳到**下一个**
    // 默认制表位（每 720 twips），实际落在 297pt。两者相加把整行顶爆，
    // 折成 3 行，每行只有一两个字，再被 jc=both 撑到两端。
    // 这是 p3「中 介 方」那种惨状的全部原因。
    //
    // 空白和 tab 是同一件事的两种表达，留一个就够。
    // 保留空白（它是版面实测宽度），删掉 tab。
    // ═══════════════════════════════════════════════════════════════
    for (NSUInteger i = 1; i < cnt; i++) {
        id o = [runs objectAtIndex:i];
        if (![o isKindOfClass:[NSMutableDictionary class]]) continue;
        NSMutableDictionary *r = (NSMutableDictionary *)o;
        if (![[r objectForKey:kCSFSRunTab] boolValue]) continue;

        id po = [runs objectAtIndex:i - 1];
        if (![po isKindOfClass:[NSMutableDictionary class]]) continue;
        NSDictionary *pv = (NSDictionary *)po;
        NSString *pt2 = [pv objectForKey:kCSFSRunText];
        double pw = CSFSDoubleValue([pv objectForKey:kCSFSRunSpaceW]);
        BOOL ws = CSFSIsPureWhiteSpace(pt2);
        if (ws && (pw > 0.0 || [pt2 length] >= 3)) {
            [r setObject:[NSNumber numberWithBool:NO] forKey:kCSFSRunTab];
            tabDrop++;
        }
    }

    // v35：宽度预算放在最后一步 —— 字体、行尾、tab 都已定稿，
    // 这时候估出来的宽度才和真正写进 XML 的一致。
    // v36：返回位标志（左对齐 / 清缩进），不再只回一个 BOOL。
    BOOL dropIndent = NO;
    int fitFlags = CSFSFitParaWidth(runs, paraPt, indentTw, &dropIndent);
    if (dropIndent) fitFlags |= kCSFSFitNoIndent;

    if (fillSize || faceFix || fillBody || textFaceFix || tailDrop || tabDrop ||
        dropIndent) {
        CSFS_LOG(@"v35 spcfix para: faceFix=%ld textFaceFix=%ld fillBody=%ld"
                 @" fillSize=%ld underNative=%ld tailDrop=%ld tabDrop=%ld"
                 @" dropInd=%d face=%@ pt=%.1f ind=%ld left=%d",
                 faceFix, textFaceFix, fillBody, fillSize, underNative, tailDrop, tabDrop,
                 (int)dropIndent, wideFace, paraPt, indentTw,
                 (int)((fitFlags & kCSFSFitLeft) != 0));
    }
    return fitFlags;
}

static NSString *CSFSExpandSpaceRun(NSString *text, double sliceWidthPx,
                                    double fontSizePt, double *outSpTw) {
    if (outSpTw) *outSpTw = 0.0;
    if (text.length == 0) return text;

    // 只处理「整体是空白」的 run。夹在文字中间的空格照样保留原样，
    // 那种位置的字距由排版引擎自然分配，硬撑会把整行拉散。
    if (!CSFSIsPureWhiteSpace(text)) return text;

    // 宽度不可用就直接原样返回 —— 宁可短，也不能凭空空造出一堆空格。
    if (!(sliceWidthPx > 0.0)) return text;

    // 字号缺省时用一个安全值（11pt 是这份文档的正文档，见日志
    // v21 defaultPt=11.0 / v23 histogram 11pt×161）。
    if (!(fontSizePt > 2.0) || fontSizePt > 200.0) fontSizePt = 11.0;

    // 宽度 → pt
    //
    // ═══════════════════════════════════════════════════════════════
    // v33：**不再乘 200dpi 的 0.3597**。width 的单位就是 pt。
    //
    // 这是 v32 真机日志三条样本反证出来的，不是猜：
    //     w=56.0 pt=10.5 → OCR 原文 11 个空格   56 /(0.5×10.5)=10.67 → 11
    //     w=12.0 pt=10.5 → OCR 原文  2 个空格   12 / 5.25     = 2.29 →  2
    //     w=36.0 pt=10.5 → OCR 原文  7 个空格   36 / 5.25     = 6.86 →  7
    // 三条独立样本全部落在 ±0.35 内 —— 一条恒等式 y=x 摆在这里。
    //
    // 而按 200dpi 折算（×0.3597）得到 3.8 / 0.8 / 2.5，与 OCR 自己给
    // 的空格数差 2~3 倍。v32 之所以没炸，全靠下面「不得少于原文字符数」
    // 那条兜底把结果救了回来；可一旦 OCR 某个填空线只给 1 个空格、
    // width 却很大，算出来仍是偏小的值，兜底就不再救场 ——
    // 这正是用户说的「明显不够长」。
    //
    // 顺带印证：v30 的缩进日志 `raw=22 → firstLine=440 twips`
    // （440 twips = 22pt）说明 para 里的长度字段也是同一套 pt 口径，
    // 两处不该各用一套比例。
    // ═══════════════════════════════════════════════════════════════
    double pt = sliceWidthPx;
    if (gCSFSPageScale > 0.0 && gCSFSPageScale < 1.0) {
        // 真拿到 scale 且明显小于 1（说明 width 是页面像素而非 pt）时才折算。
        // scale 恰为 1.0 属于「占位默认值」，不能拿来乘。
        pt = sliceWidthPx * gCSFSPageScale;
    }

    // v34：行宽上限。
    // 一条空白撑不出比页面内容区更宽的东西。真机里那条
    // `len=56 sz=36`（18pt × 56 = 504pt > 内容区 451pt）的整段空白
    // 就会把整段挤到下一行 —— 溢价比短更难看。
    double maxPt = kCSFSContentTwips / 20.0;
    BOOL clippedPage = NO;
    if (maxPt > 1.0 && pt > maxPt) { pt = maxPt; clippedPage = YES; }

    // pt → 半角空格个数（中文等宽字体的半角空格 = 0.5 em）
    double per = fontSizePt * 0.5;
    if (!(per > 0.1)) per = 5.5;

    // v34：向下取整，**余量用字符间距补**，不再四舍五入。
    // round 会让结果一半偏短一半偏长，而「偏短」正是用户一直在说的那个毛病；
    // floor + 余量能把误差压到 1 twip 以内（1/20 pt）。
    long n = (long)floor(pt / per);
    long rawN = n;                        // 纯换算结果（诊断用）

    // 上限保护：单个 run 最多 200 个空格。
    // 没有上限时，一旦 width 字段的单位不是像素（比如是 1/100 pt），
    // 会算出上万个空格，整段文档直接被撑爆 —— 那比短更糟。
    if (n < 1) n = 1;
    if (n > 200) n = 200;
    long clampedN = n;                    // 夹过上下限、但还没被原长兜底

    // 原有空白里如果已经不止一个字符（偶尔 OCR 直接给 "   "），
    // 以算出来的为准，但不允许比原来少 —— 少就等于又把它弄短了。
    if ((long)text.length > n) n = (long)text.length;

    // 余量（pt）：n 个空格还差多少才等于 slice.width。
    // 摊到每个字符上，交给 <w:spacing> 输出（单位 twips，1pt = 20）。
    // 注意「原长兜底」把 n 拉大后余量会是负数，那种情况不再补。
    double remPt = pt - (double)n * per;
    double spTw = 0.0;
    if (remPt > 0.0 && n > 0) {
        spTw = (remPt * 20.0) / (double)n;
        if (spTw < 0.0) spTw = 0.0;
        if (spTw > 31680.0) spTw = 31680.0;   // CT_SignedTwipsMeasure 上限
    }
    if (outSpTw) *outSpTw = spTw;

    // ══════════════════════════════════════════════════════════════
    // v33：把「算出来的 / 夹过的 / 最终的」三个值全打出来。
    //
    // 这不是多余：v32 的日志只有「→ N 个空格 (原 N)」，
    // 而 v32 的换算是错的（多乘了 0.3597），算出来远小于原长，
    // 结果被下面那条兜底悄悄救回原长 —— 日志看起来「数量正确」，
    // 实际根本没展开。只打最终值等于把缺陷藏起来。
    //
    // srcLen 是 OCR 原文的空格数：
    //   final == srcLen 且 raw < srcLen  → 换算偏小，被兜底救了（长度不会够）
    //   final >  srcLen                  → 真的展开了
    // 下一轮看这一行就能定死「换算系数还对不对」，不用再猜。
    // ══════════════════════════════════════════════════════════════
    if (gCSFSSpaceExpandLogs < 5) {
        gCSFSSpaceExpandLogs++;
        CSFS_LOG(@"v34 space: w=%.1f pt=%.1f fs=%.1f per=%.2f raw=%ld"
                 @" clamped=%ld n=%ld rem=%.2f spTw=%.1f srcLen=%lu clip=%d"
                 @" scale=%.4f",
                 sliceWidthPx, pt, fontSizePt, per, rawN, clampedN, n,
                 remPt, spTw, (unsigned long)text.length, (int)clippedPage,
                 gCSFSPageScale);
    }

    NSMutableString *s = [NSMutableString stringWithCapacity:(NSUInteger)n];
    for (long i = 0; i < n; i++) [s appendString:@" "];
    return s;
}

static NSString *CSFSRenderPara(NSDictionary *para, double defaultPt) {
    // v28：缩进分支诊断只打一次，用于定死「为什么 ih 有值却没走 hanging」。
    static BOOL indentDiagDone = NO;
    // v32：空格展开的日志计数已提到文件级（gCSFSSpaceExpandLogs），
    // 这样第二次导出也能打到明细，而不是只有第一次。
    // v21：图片段优先分流。图片段只有 kCSFSParaImage，没有 runs，
    // 走下面的文字分支会产出空段落（图依旧不显示）。
    id img = [para objectForKey:kCSFSParaImage];
    if ([img isKindOfClass:[NSDictionary class]]) {
        return CSFSRenderImagePara((NSDictionary *)img, 1);
    }

    NSMutableString *out = [NSMutableString stringWithString:@"<w:p>"];

    // ── v24：段落属性一律按 JSON 自己的字段生成
    //
    // v23 的错就在于「不读字段、自己编规则」：无条件加 200 字符缩进，
    // 于是标题以外的每一段都被推了两格；同时 slice 首尾直连，
    // 于是同行多字段全粘在一起。两条都不是 XML 错，所以结构校验看不出来。
    //
    // 现在按 App 的 campo 走：
    //   indent_first_line → <w:ind w:firstLine>
    //   tabs              → <w:tabs>
    //   line_gap          → <w:spacing w:line>
    //   justification     → <w:jc>
    //
    // ⚠ 输出顺序必须严格照 CT_PPrBase 的 sequence：
    //   tabs → spacing → ind → jc
    //   顺序错一项，Word/WPS 静默忽略，不报错。
    id align = [para objectForKey:kCSFSParaAlign];
    BOOL alignLeftish = (align == nil) ||
                        ([align isKindOfClass:[NSString class]] &&
                         ([(NSString *)align isEqualToString:@"both"] ||
                          [(NSString *)align isEqualToString:@"left"]));

    // 本段基准字号：para 自己的 mostFrequentFontSize 优先，
    // 它比「全文众数」更贴近这一段（标题段就是用自己的大字号算缩进）。
    double paraPt = CSFSDoubleValue([para objectForKey:kCSFSParaBasePt]);
    if (!(paraPt > 2.0 && paraPt < 200.0)) paraPt = defaultPt;
    // v25：基准字号同样要叠 fontSizeMode 的那一档，
    // 否则用它推出来的「两字符缩进」和行距都会偏。
    if (gCSFSFontSizeMode == 1)      paraPt -= 1.0;
    else if (gCSFSFontSizeMode == 2) paraPt += 1.0;

    // v35：本段实际占用的左缩进（twips），供下面的宽度预算减去。
    // 缩进和空白是两笔独立开销，预算时必须一起算 ——
    // 只算空白不算缩进，就正好是 p1/p3 超页宽的那 12~19pt。
    long fitIndentTw = 0;

    NSMutableString *pPr = [NSMutableString string];

    // v28：把决定缩进分支走向的三个输入打一次。
    // 日志里 ih=258（有悬挂缩进）却一次都没走 hanging 分支，
    // 说明卡在 alignLeftish 或 floating 上，而不是值本身。
    if (indentDiagDone == NO) {
        indentDiagDone = YES;
        CSFS_LOG(@"v28 ind branch: align=%@ leftish=%d fl=%@ il=%@ ih=%@",
                 align ?: @"(nil)", (int)alignLeftish,
                 [para objectForKey:kCSFSParaFloat] ?: @"(nil)",
                 [para objectForKey:kCSFSParaIndL] ?: @"(nil)",
                 [para objectForKey:kCSFSParaIndH] ?: @"(nil)");
    }

    // 1) 制表位
    id runsObj = [para objectForKey:kCSFSParaRuns];
    long tabCount = 0;
    if ([runsObj isKindOfClass:[NSArray class]]) {
        for (NSDictionary *r0 in (NSArray *)runsObj) {
            if ([[r0 objectForKey:kCSFSRunTab] boolValue]) tabCount++;
        }
    }
    if (tabCount > 0) {
        const char *tabWhy = "-";
        NSArray *tabs = CSFSNormalizeTabs([para objectForKey:kCSFSParaTabs], paraPt, &tabWhy);
        if (!tabs) {
            // 没有可用 tabs：按字段数均分内容宽。
            // 均分不精确（预览里各列宽窄不一），但比「全部粘成一串」
            // 和无脑默认制表位（每 720 twips）都更接近原样。
            NSMutableArray *gen = [NSMutableArray array];
            for (long i = 1; i <= tabCount; i++) {
                double pos = kCSFSContentTwips * (double)i / (double)(tabCount + 1);
                [gen addObject:[NSNumber numberWithDouble:pos]];
            }
            tabs = gen;
            tabWhy = "even";
        }
        if (tabs.count > 0) {
            // 直接往 pPr 上 append，不经中间变量。
            // 这样「tabs 排在 ind 之前」这件事在源码里就是可验证的 ——
            // 中间变量会让字面量位置与真实输出顺序脱钩，检查器只看得到
            // 字面量在哪儿，看不出 append 到哪儿，那种检查是假的。
            [pPr appendString:@"<w:tabs>"];
            for (NSNumber *n in tabs) {
                [pPr appendFormat:@"<w:tab w:val=\"left\" w:pos=\"%ld\"/>",
                    (long)([n doubleValue] + 0.5)];
            }
            [pPr appendString:@"</w:tabs>"];
            CSFS_LOG(@"v24 tabs n=%lu why=%s first=%ld", (unsigned long)tabs.count, tabWhy,
                     (long)([[tabs objectAtIndex:0] doubleValue] + 0.5));
        }
    }

    // 2) 行距与段前
    {
        const char *lgWhy = "-";
        long line = CSFSLineTwipsFromGap([para objectForKey:kCSFSParaLineGap], paraPt, &lgWhy);
        if (line > 0) {
            if (line >= 240 && line <= 2400) {
                [pPr appendFormat:@"<w:spacing w:line=\"%ld\" w:lineRule=\"auto\"/>", line];
                CSFS_LOG(@"v25 spacing line=%ld (=%.3fx, raw=%@ why=%s pt=%.1f)",
                         line, (double)line / 240.0,
                         [para objectForKey:kCSFSParaLineGap] ?: @"(nil)", lgWhy, paraPt);
            }
        }
    }

    // 3) 缩进 —— 严格照 -[CSWordEditFlowDataManager
    //    setupParaStyleWithAttributeString:para:ocrPage:segment:isCellPara:]
    //
    // 反汇编原文（0x10147dc84 起，指令级实证）：
    //   ① para.floating_box 为真  → 整段不设任何缩进
    //   ② para.indent_hanging >= 1 → headIndent          = scale * hanging * k
    //      且 **indent_hanging > 0 时直接结束**，首行缩进一律不设（互斥）
    //   ③ 否则 para.indent_first_line != 0 → firstLineHeadIndent = scale * fl * k
    //   k = isCellPara ? 0.8 : 1.0
    //
    // v30 修掉两处实质性错误：
    //   A) indent_left / indent_right —— 整个函数**一次都没读**
    //      （全函数只有 STUB[indent_hanging] 与 STUB[indent_first_line]），
    //      所以 docx 里也不该凭空写 w:left / w:right。v29 及以前一直在写，
    //      等于给每段多加了一份 App 根本不存在的左右缩进。
    //   B) 悬挂缩进只写 w:left —— 语义错了。
    //      App 设的是 headIndent=X 且 firstLineHeadIndent=0，
    //      即「首行顶格、其余行缩 X」。只写 w:left=X 会让**首行也缩进**，
    //      整体右移一格。OOXML 的等价写法是 w:left=X + w:hanging=X。
    // v36：缩进「先算值、后落笔」。
    //   要不要缩进不只看 OCR 的 indent_first_line，还要看宽度预算：
    //   若加了缩进会让本来一行的段落折行、去掉缩进就正好一行，那就不缩。
    //   所以这里只把值算出来，等 CSFSFixSpaceRuns 的结论回来再写 pPr。
    long indHang = 0;        // >0：悬挂缩进（首行顶格，其余行缩进）
    long indFirst = 0;       // >0：首行缩进
    if (alignLeftish) {
        BOOL floating = CSFSBoolValue([para objectForKey:kCSFSParaFloat]);
        if (!floating) {
            double hangRaw = CSFSDoubleValue([para objectForKey:kCSFSParaIndH]);
            double hangT = CSFSIndentTwips([para objectForKey:kCSFSParaIndH],
                                           paraPt, NULL);
            double flT = CSFSIndentTwips([para objectForKey:kCSFSParaIndFL],
                                         paraPt, NULL);

            long lim = (long)(kCSFSContentTwips * 0.9);
            if (hangRaw >= 1.0 && hangT > 0.0 && hangT < lim) {
                // ② 悬挂缩进：首行顶格，其余行缩 hangT
                indHang = (long)(hangT + 0.5);
            } else if (flT > 0.0 && flT < lim) {
                // ③ 首行缩进
                indFirst = (long)(flT + 0.5);
                // 首行缩进是首行的实际开销，宽度预算要减掉它。
                // 悬挂缩进（上面那个分支）首行顶格，开销为 0，故不设。
                fitIndentTw = indFirst;
            }
            // ═══════════════════════════════════════════════════════
            // v36：删掉「fl 为 0 或缺失 → 兜底两字符缩进」。
            //
            // 反汇编原文 ③ 是 `cbz x0 → 跳过`：**fl 为 0 就跳过，不设缩进**。
            // v30 却写成了「字段缺失 → 兜底两字符」，把「顶格」这个
            // 明确状态当成了「数据缺失」，给每一段都补了 22pt。
            //
            // 真机后果（v35 导出 PDF 逐行量 bbox）：
            //   承租方：缩进 21pt 后内容 442pt，可用只剩 430.3pt
            //          → 折掉「方）」两个残字
            //   中介方：缩进 21pt 后内容 451.5pt → 折掉「人：」
            // 而预览截图里这两段都是顶格的。**兜底把正确的顶格改坏了**，
            // 这是本项目第三次栽在「兜底掩盖真相」上（前两次是字体兜底、
            // indent 兜底）。
            // ═══════════════════════════════════════════════════════
            if (indHang == 0 && indFirst == 0) {
                CSFS_LOG(@"v36 ind none: fl=%@ ih=%@（顶格，不缩进）",
                         [para objectForKey:kCSFSParaIndFL] ?: @"(nil)",
                         [para objectForKey:kCSFSParaIndH] ?: @"(nil)");
            }
        } else {
            CSFS_LOG(@"v30 ind skipped: floating_box");
        }
    }

    // 4) 对齐
    //
    // v35：run 级修正必须提前到 jc 之前 —— 它要回一个「这段是否建议左对齐」，
    // 而这个结论要写进 jc。原来的顺序是「先写 pPr、再修 run」，
    // 于是宽度预算算出来的结论只能丢掉，等于白算。
    id runs = [para objectForKey:kCSFSParaRuns];
    BOOL runsOK = [runs isKindOfClass:[NSArray class]] && [(NSArray *)runs count] > 0;
    int paraFitFlags = 0;
    if (runsOK) {
        paraFitFlags = CSFSFixSpaceRuns((NSMutableArray *)runs, paraPt, fitIndentTw);
    }

    // 2) 缩进落笔 —— 必须在 jc 之前（CT_PPrBase 的顺序是 ind → jc）
    if (paraFitFlags & kCSFSFitNoIndent) {
        if (indFirst > 0) {
            CSFS_LOG(@"v36 ind drop: firstLine=%ld → 0（加缩进会折行，顶格刚好一行）",
                     indFirst);
        }
        indFirst = 0;
    }
    if (indHang > 0) {
        [pPr appendFormat:@"<w:ind w:left=\"%ld\" w:hanging=\"%ld\"/>", indHang, indHang];
        CSFS_LOG(@"v30 ind hanging left=%ld hanging=%ld (scale=%.4f)",
                 indHang, indHang, gCSFSPageScale);
    } else if (indFirst > 0) {
        // firstLineChars 是 Word 扩展（按字符自适应字号），
        // firstLine 是标准属性（twips）。两个都写：
        // Word 优先前者，WPS/LibreOffice 只认后者。
        long chars = (long)((double)indFirst / (paraPt * 20.0) * 100.0 + 0.5);
        if (chars < 1) chars = 1;
        if (chars > 2000) chars = 2000;
        [pPr appendFormat:@"<w:ind w:firstLineChars=\"%ld\" w:firstLine=\"%ld\"/>",
            chars, indFirst];
        CSFS_LOG(@"v30 ind firstLine=%ld (pt=%.1f scale=%.4f)",
                 indFirst, paraPt, gCSFSPageScale);
    } else if (paraFitFlags & kCSFSFitNoIndent) {
        // v36：本来是「有缩进」、因为会折行才清成「顶格」的段落，
        // 给 1pt 的右边距垫。
        // 这类段落是「顶格刚好一行」的临界情形：实测 p3 顶格后
        // 需要 451.5pt 而版心 451.3pt，只差 0.2pt 就折掉「人：」。
        // 1pt = 0.35mm，肉眼不可见，但足以吃掉估算误差和 twips 取整。
        [pPr appendString:@"<w:ind w:right=\"-20\"/>"];
        CSFS_LOG(@"v36 ind pad: right=-20tw（临界段落留 1pt 余量）");
    }

    // v35：标题段强制居中。
    // 真机 p0 是 <w:jc w:val="right"/> —— 因为那一段里混了一个右对齐的
    // 红色编号「0004025」，OCR 按整段估出了 right。
    // 但预览里「房屋租赁合同」是居中的（截图里能直接看出来），
    // 导出的却整行贴到右边，这是用户说「乱」的直观来源之一。
    //
    // 判据用字号：段内出现 ≥ 正文 1.5 倍的字号，说明它是标题，
    // 标题的居中与编号是否靠右无关。只改 jc，不动字号和颜色。
    if ([align isKindOfClass:[NSString class]] && !alignLeftish) {
        if ([runs isKindOfClass:[NSArray class]]) {
            for (NSDictionary *rr in (NSArray *)runs) {
                double s0 = CSFSDoubleValue([rr objectForKey:kCSFSRunSize]);
                if (s0 > defaultPt * 1.5 && s0 < 200.0) {
                    CSFS_LOG(@"v35 title center: sz=%.1f defaultPt=%.1f was=%@",
                             s0, defaultPt, align);
                    align = @"center";
                    break;
                }
            }
        }
    }
    // v35：折行余量太小 → 改左对齐，避免 jc=both 把首行字距撑成两倍。
    // 只覆盖 both，不动 center/right（标题与右对齐是刻意的）。
    if ((paraFitFlags & kCSFSFitLeft) && [align isKindOfClass:[NSString class]] &&
        [(NSString *)align isEqualToString:@"both"]) {
        align = @"left";
        CSFS_LOG(@"v35 align: both -> left（折行余量 <50%%，两端对齐会撑开字距）");
    }
    if ([align isKindOfClass:[NSString class]] && [(NSString *)align length] > 0) {
        [pPr appendFormat:@"<w:jc w:val=\"%@\"/>", align];
    }
    if (pPr.length > 0) {
        [out appendFormat:@"<w:pPr>%@</w:pPr>", pPr];
    }

    if (!runsOK) {
        [out appendString:@"<w:r><w:t xml:space=\"preserve\"></w:t></w:r></w:p>"];
        return out;
    }

    // v33：纯空白 run 补齐字体/字号/下划线。
    // 必须在整段 runs 就绪、XML 还没写的时候做，
    // 因为继承要看「同段相邻的文字 run」，单条 run 自己没有上下文。
    // v35：这次调用已经上移到 jc 之前（见上面 paraSuggestLeft），
    // 这里不要再调一次 —— 重复调用会把已经压过的空白再压一遍。

    for (NSDictionary *r in (NSArray *)runs) {
        NSString *text = [r objectForKey:kCSFSRunText];

        // v24：制表符单独成一个 run，且必须排在文字之前。
        // 单独成 run 而不是塞进同一个 <w:r>：部分移动端阅读器
        // 只渲染 run 的第一个子元素，混排会吞掉 tab。
        if ([[r objectForKey:kCSFSRunTab] boolValue]) {
            [out appendString:@"<w:r><w:tab/></w:r>"];
        }
        if (text.length == 0) continue;

        // ═══════════════════════════════════════════════════════════
        // v34：先把这个 run 的「实际字号」「展开后的文本」「字符间距」
        // 全部算出来，再按 CT_RPr 的法定顺序写 rPr。
        //
        // 为什么要提前：<w:spacing> 必须排在 <w:sz> **之前**
        // （ECMA-376 CT_RPr 是 xsd:sequence：… color → spacing → sz → u），
        // 而它自己的值又依赖字号（n = width ÷ (0.5 × 字号)）。
        // v33 把展开放在 sz 之后，spacing 就再也插不进来了 ——
        // 只能在写入前把值都算好。
        // ═══════════════════════════════════════════════════════════
        id szObj = [r objectForKey:kCSFSRunSize];
        double runPt = 0.0;
        if (szObj) {
            double sz = CSFSDoubleValue(szObj);
            if (sz > 2.0 && sz < 200.0) {
                // v25：App 的规则是逐 slice 取自己的 font_size，
                // 只在最后叠一档全局偏移 —— 反汇编
                // -[CSITextEngineSettings caculateFontSizeWithOriginalFontSize:]：
                //     fontSizeMode 1 → -1pt，2 → +1pt，其余原样。
                // 展开空格必须用这个「叠完之后」的字号，
                // 否则算出来的个数与实际排版脱节。
                if (gCSFSFontSizeMode == 1)      sz -= 1.0;
                else if (gCSFSFontSizeMode == 2) sz += 1.0;
            }
            runPt = sz;
        }
        // run 没有自己的字号时，用全文正文档（defaultPt）参与换算。
        if (!(runPt > 2.0) || runPt > 200.0) runPt = defaultPt;

        BOOL emitIsSpace = CSFSIsPureWhiteSpace(text);
        BOOL emitUnder   = [[r objectForKey:kCSFSRunUnderline] boolValue];
        double spaceW    = CSFSDoubleValue([r objectForKey:kCSFSRunSpaceW]);
        NSString *emitText = text;
        double spTw = 0.0;
        if (spaceW > 0.0 && emitIsSpace) {
            // 明细日志统一由 CSFSExpandSpaceRun 内部打
            //（那里能同时给出 raw / n / rem / spTw，
            //  只看最终个数会被兜底骗过去 —— v32 就是这么被骗的）。
            emitText = CSFSExpandSpaceRun(text, spaceW, runPt, &spTw);
            gCSFSSpaceExpandRuns++;
        }

        // 下面这段的**书写顺序就是 XML 输出顺序**，必须严格照 ECMA-376 的
        // CT_RPr sequence 排，不能按「先想到哪个写哪个」。改动前先回看上面的注释。
        NSMutableString *rPr = [NSMutableString string];

        // 1) rFonts —— 除 rStyle 外必须排第一。
        // 同时写 ascii/hAnsi/eastAsia：中文文档只写 hAnsi 不起作用，
        // Word 会按 eastAsia 走。
        NSString *face = [r objectForKey:kCSFSRunFace];
        if (face.length > 0) {
            NSString *fe = CSFSXMLEscape(face);
            [rPr appendFormat:
                @"<w:rFonts w:ascii=\"%@\" w:hAnsi=\"%@\" w:eastAsia=\"%@\" w:cs=\"%@\"/>",
                fe, fe, fe, fe];
        }
        // 2) 粗体
        if ([[r objectForKey:kCSFSRunBold] boolValue])   [rPr appendString:@"<w:b/><w:bCs/>"];
        // 3) 斜体
        if ([[r objectForKey:kCSFSRunItalic] boolValue]) [rPr appendString:@"<w:i/><w:iCs/>"];
        // 4) 颜色
        NSString *color = [r objectForKey:kCSFSRunColor];
        if (color.length == 6) {
            [rPr appendFormat:@"<w:color w:val=\"%@\"/>", color];
        }
        // 5) 字符间距 —— v34：补上「向下取整丢掉的那点宽度」。
        //
        //    空白 run 展开成 n 个空格后，还会有不到一个空格的零头。
        //    v32/v33 用四舍五入处理这个零头，结果一半偏短一半偏长 ——
        //    而「偏短」正是用户一直在说的毛病。改成 floor + 余量后，
        //    n 个空格 + n×spTw 的合计宽度能对到 1 twip（1/20 pt）以内。
        //
        //    必须排在 color 之后、sz 之前，位置写错 Word 会静默忽略。
        if (spTw >= 1.0) {
            long spInt = (long)(spTw + 0.5);
            if (spInt > 31680) spInt = 31680;
            [rPr appendFormat:@"<w:spacing w:val=\"%ld\"/>", spInt];
        }
        // 6) 字号：sz 是半磅。只对「与默认不同」的 run 写字号，
        //    否则每个 run 都带 sz，XML 体积翻倍且不利于后续统一改样式。
        //
        //    v25：取消 v23 的「20% 归并」，理由见上面字体那一节的注释。
        if (szObj && defaultPt > 2.0 && defaultPt < 200.0 &&
            runPt > 2.0 && runPt < 200.0 && fabs(runPt - defaultPt) > 0.1) {
            long hp = (long)(runPt * 2.0 + 0.5);
            // 越界字号 Word 会当损坏处理，直接钳进合法区间
            if (hp < 1) hp = 1;
            if (hp > 3276) hp = 3276;
            [rPr appendFormat:@"<w:sz w:val=\"%ld\"/><w:szCs w:val=\"%ld\"/>", hp, hp];
        }
        // 7) 下划线 —— 必须排在 sz 之后
        if (emitUnder) {
            [rPr appendString:@"<w:u w:val=\"single\"/>"];
        }

        // ═══════════════════════════════════════════════════════════
        // v32：纯空白 run 按 slice.width 撑开 —— 让下划线长得跟预览一样。
        //
        // 放在这里（rPr 已经算好、<w:t> 还没写）有两个原因：
        //   · 展开只影响文字内容，不影响格式属性，所以可以晚于 rPr；
        //   · 但必须在 CSFSXMLEscape(text) 之前换掉 text，
        //     否则写出去的还是一个空格。
        // ═══════════════════════════════════════════════════════════
        // ═══════════════════════════════════════════════════════════
        // v33：带下划线的空白一律换成**不换行空格 U+00A0**。
        //
        // 这是「有的下划线还是不出来」的最后一道保险，原因很实在：
        // Word 会裁掉**行尾空格**（连它的下划线一起裁），
        // 而合同填空线有相当一部分正好落在行尾、
        // 后面紧跟的就是换行 —— 于是线一条不剩。
        // `xml:space="preserve"` 只保证 XML 解析层不丢空白，
        // 不代表 Word 排版时保留行尾空格的下划线。
        //
        // U+00A0 在排版上**不是空格**：不会被裁剪、不会被折叠、
        // 也不会成为断行点（填空线本来就不该在中间断）。
        // 宽度与普通空格一致（宋体里同为 0.5em），
        // 所以换成它不会改变长度，只保证线画出来。
        //
        // v35 更正：只对**段落末尾**的空白这么换。
        // v33/v34 是无条件换，结果是行中每一条填空线都变成了
        // 不可断的块 —— 「22018220040518001x + 7 个 NBSP + （以下简称甲方）」
        // 连成一整块 255pt，前一行放不下就整体下移，
        // 首行只剩 194pt 的内容却被 jc=both 撑满 451pt，
        // 字距变成 2.3 倍。用户说的「乱七八糟」正是这么来的。
        // 行中空白保留普通空格 = 保留断行点，Word 才能在正确位置折行。
        // ═══════════════════════════════════════════════════════════
        BOOL emitAtTail = [[r objectForKey:kCSFSRunTail] boolValue];
        if (emitIsSpace && emitUnder && emitAtTail && emitText.length > 0) {
            // ═══════════════════════════════════════════════════════
            // v35：NBSP 是**全角**的，个数必须折半。
            //
            // v33 的注释写着「宽度与普通空格一致（宋体里同为 0.5em）」——
            // 这句是错的。用 Word 逐字符量位置实测（10.5pt，字体全写 SimSun）：
            //     U+0020 普通空格  0.5255em →  5.25pt
            //     U+00A0 NBSP      1.0490em → 10.50pt
            //     U+3000 全角空格  1.0490em → 10.50pt
            // 也就是说 NBSP 正好是普通空格的**两倍宽**。
            //
            // 后果是连锁的：段尾那条填空线换成 NBSP 后长度翻倍 →
            // 段落比页宽多出几十 pt → 折行 → jc=both 把首行撑成
            // 两三倍字距。用户看到的「乱七八糟」根子就在这里。
            //
            // 按 2:1 折半后总宽完全不变，线该多长还是多长。
            // ═══════════════════════════════════════════════════════
            NSUInteger tn = emitText.length;
            NSUInteger nbCount = (tn + 1) / 2;     // 每 2 个普通空格 = 1 个 NBSP
            if (nbCount < 1) nbCount = 1;
            NSMutableString *nb = [NSMutableString stringWithCapacity:nbCount];
            for (NSUInteger k = 0; k < nbCount; k++) [nb appendString:@"\u00A0"];
            emitText = nb;
            gCSFSUnderSpaceRuns++;
            if (gCSFSUnderSpaceRuns <= 8) {
                CSFS_LOG(@"v35 nbsp: %lu 普通空格 -> %lu NBSP（NBSP 为 1em，折半保宽度）",
                         (unsigned long)tn, (unsigned long)nbCount);
            }
        }

        if (rPr.length > 0) {
            [out appendFormat:@"<w:r><w:rPr>%@</w:rPr><w:t xml:space=\"preserve\">%@</w:t></w:r>",
                rPr, CSFSXMLEscape(emitText)];
        } else {
            [out appendFormat:@"<w:r><w:t xml:space=\"preserve\">%@</w:t></w:r>",
                CSFSXMLEscape(emitText)];
        }
    }
    [out appendString:@"</w:p>"];
    return out;
}

// v18：正文由段落字典数组渲染。
// 每个元素是 NSMutableDictionary：
//   kCSFSParaRuns  → NSArray<NSMutableDictionary*> 文本片段
//   kCSFSParaAlign → NSString 可选，w:jc 取值（center/right/both）
// defaultPt 取全文出现最多的字号，作为 Normal 的基准，
// 这样「标题比正文大」这件事在 Word 里能被体现出来（标题写 sz，正文继承）。
static BOOL CSFSWriteDocxStyled(NSArray *paras, double defaultPt, NSString *outPath) {
    CSFSCrashTrace("docx21: enter");

    // ── v21：先收集图片段。
    // media 部件、document.xml.rels 的关系、[Content_Types] 的 Default
    // 三处都必须与正文里的 r:embed 一一对应，缺一处 Word 就打不开 ——
    // 所以统一从 paras 里收集，不另开一条传递路径。
    NSMutableArray *images = [NSMutableArray array];
    for (NSDictionary *p in paras) {
        if (![p isKindOfClass:[NSDictionary class]]) continue;
        id img = [p objectForKey:kCSFSParaImage];
        if (![img isKindOfClass:[NSDictionary class]]) continue;
        NSData *d = [(NSDictionary *)img objectForKey:kCSFSImgData];
        NSString *e = [(NSDictionary *)img objectForKey:kCSFSImgExt];
        if ([d isKindOfClass:[NSData class]] && d.length > 0 && e.length > 0) {
            [images addObject:img];
        }
    }

    NSMutableString *body = [NSMutableString string];
    for (NSDictionary *p in paras) {
        [body appendString:CSFSRenderPara(p, defaultPt)];
    }
    if (body.length == 0) [body appendString:@"<w:p/>"];

    long defHalfPt = (long)(defaultPt * 2.0 + 0.5);
    if (defHalfPt < 4 || defHalfPt > 400) defHalfPt = 24;   // 兜底 12pt

    // ⚠ <w:pgMar> 的 header / footer / gutter 在 ECMA-376 里标的是
    //   use="required"，缺一个 Word 就按损坏处理。v19 只写了四边，
    //   这是除「漏 w:p」之外的第二个致命项。
    //
    // v21：根元素补 r / wp / a / pic 四个命名空间声明。
    //   <w:drawing> 里用到 r:embed、wp:inline、a:graphic、pic:pic，
    //   只要有一个前缀没声明，XML 就是 ill-formed，Word 直接判损坏。
    NSString *docXml = [NSString stringWithFormat:
        @"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        @"<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\""
        @" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\""
        @" xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\""
        @" xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\""
        @" xmlns:pic=\"http://schemas.openxmlformats.org/drawingml/2006/picture\">"
        @"<w:body>%@<w:sectPr><w:pgSz w:w=\"11906\" w:h=\"16838\"/>"
        // ═══════════════════════════════════════════════════════════
        // v37：左右边距 1440 → 800。
        //
        // 1440 twips = 72pt = 2.54cm 是 **Word 默认值**，从来没和原文档
        // 核对过。它把版心压成 451.3pt，于是每行比手机预览少 5~8 个汉字，
        // 折行点整体前移，后面的行全部错位 —— 用户报的「每行文字数目
        // 跟预览很多不一样」就是这个。v32~v36 一直在 451.3pt 里调缩进、
        // 压空白、加负右缩进，都是围着这个错值打转。
        //
        // 800 → 版心 10306 twips = 515.3pt，与截图逐行一致（见上方
        // kCSFSContentTwips 的四档实测表）。只改左右，上下保持 1440。
        // ═══════════════════════════════════════════════════════════
        @"<w:pgMar w:top=\"1440\" w:right=\"800\" w:bottom=\"1440\" w:left=\"800\""
        @" w:header=\"851\" w:footer=\"992\" w:gutter=\"0\"/>"
        @"</w:sectPr></w:body></w:document>",
        body];

    // ── [Content_Types].xml：图片扩展名要单独声明 Default，
    //    否则 Word 不知道 .png/.jpeg 是什么部件，报「无法读取的内容」。
    NSMutableString *ctXml = [NSMutableString stringWithString:
        @"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        @"<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
        @"<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
        @"<Default Extension=\"xml\" ContentType=\"application/xml\"/>"];
    {
        // 去重（同一份文档里 png/jpeg 混用是常见的）
        NSMutableArray *exts = [NSMutableArray arrayWithCapacity:4];
        for (NSDictionary *img in images) {
            NSString *e = [img objectForKey:kCSFSImgExt];
            if (![exts containsObject:e]) [exts addObject:e];
        }
        for (NSString *e in exts) {
            NSString *mime = @"image/png";
            if ([e isEqualToString:@"jpeg"]) mime = @"image/jpeg";
            else if ([e isEqualToString:@"gif"]) mime = @"image/gif";
            [ctXml appendFormat:@"<Default Extension=\"%@\" ContentType=\"%@\"/>", e, mime];
        }
    }
    [ctXml appendString:
        @"<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>"
        @"<Override PartName=\"/word/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml\"/>"
        @"</Types>"];

    NSString *relsXml =
        @"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        @"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        @"<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>"
        @"</Relationships>";

    // ── document.xml.rels：每个图片一条关系，Id 必须与正文 r:embed 完全对应。
    NSMutableString *docRelsXml = [NSMutableString stringWithString:
        @"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        @"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        @"<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/>"];
    for (NSDictionary *img in images) {
        NSNumber *nn = [img objectForKey:kCSFSImgName];
        long seq = nn ? [nn longValue] : 1;
        NSString *e = [img objectForKey:kCSFSImgExt];
        [docRelsXml appendFormat:
            @"<Relationship Id=\"rIdImg%ld\""
            @" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\""
            @" Target=\"media/image%ld.%@\"/>", seq, seq, e];
    }
    [docRelsXml appendString:@"</Relationships>"];

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
    // v21：图片实体。
    // 必须是 store 型（CSFSZipAddEntry 内部固定 method=0），与 docx 其余部件一致；
    // 用 deflate 也能过，但 store 省掉压缩库依赖，而且图片本身已压缩过。
    for (NSDictionary *img in images) {
        NSData *d = [img objectForKey:kCSFSImgData];
        NSString *e = [img objectForKey:kCSFSImgExt];
        NSNumber *nn = [img objectForKey:kCSFSImgName];
        long seq = nn ? [nn longValue] : 1;
        NSString *name = [NSString stringWithFormat:@"word/media/image%ld.%@", seq, e];
        CSFSZipAddEntry(zipData, cd, name, d);
    }
    CSFSCrashTrace("docx18: parts added");

    uint32_t cdSize = (uint32_t)cd.length;
    uint32_t cdOffset = (uint32_t)zipData.length;
    NSUInteger entryCount = 5 + images.count;
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
    CSFS_LOG(@"v21 docx written=%d paras=%lu imgs=%lu defPt=%.1f size=%lu",
             (int)ok, (unsigned long)paras.count, (unsigned long)images.count,
             defaultPt, (unsigned long)zipData.length);
    // v33：空格统计必须打在**渲染之后**。
    // v32 把它放在解析后、渲染前，于是日志里永远 spaceExpanded=0，
    // 而紧接着的 v32 space 明细又明明打出来了 —— 自相矛盾，
    // 上一轮差点据此判断「展开根本没走」。
    CSFS_LOG(@"v34 space stats: expandedRuns=%ld underNBSP=%ld bodyFace=%@"
             @" (bodyFace 必须是中文字体名；若是 Calibri，空格只有 0.226em)",
             gCSFSSpaceExpandRuns, gCSFSUnderSpaceRuns,
             gCSFSBodyFace ?: @"(nil)");
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
                                    // v19：para 单独一个开关，不然先遍历到 para 就把
                                    // slice 那次 dump 吃掉，等于没 dump
                                    BOOL paraDiagDone = NO;
                                    // v24：段落版式字段只 dump 一次。
                                    // 缩进/制表位/行距的单位没有静态证据，
                                    // 只能靠这一次的真实取值把量级定死。
                                    BOOL layoutDiagDone = NO;
                                    // v21：图片计数（生成 rId / media 文件名 / docPr id）
                                    // 与「图片块结构只 dump 一次」的独立开关。
                                    // 又用独立开关，理由同上：共用 flag 会被先到的分支吃掉。
                                    long imgSeq = 0;
                                    BOOL imgDiagDone = NO;
                                    long imgBlockCount = 0;
                                    // v22：手写转文字相关计数与观测集合。
                                    //   imgTextCount —— 有多少个 IMAGE 块因为有识别文字
                                    //                   而改成文字导出（不插图）
                                    //   imgDupCount  —— 有多少个 IMAGE 块的文字与已有段落重复被跳过
                                    //   blockTypeSet —— 出现过哪些块类型（关键：手写块到底叫什么）
                                    //   seenText     —— 已入列段落的纯文本，用于去重
                                    long imgTextCount = 0;
                                    long imgDupCount = 0;
                                    // v24：三个开关各自的拦截计数。
                                    // 分开计数是为了下一轮能一眼看出
                                    // 「是开关没读到」还是「读到了但判据没命中」。
                                    long hiddenBlockCount = 0;
                                    long stampSkipCount = 0;
                                    long handSkipCount = 0;
                                    // v32：手写判据命中数（cat==1 或 stype 含 handwrit）。
                                    // 与 handSkipCount 成对看，能直接判断判据找没找对：
                                    //   handHW=0             → 判据没找到任何手写，改判据
                                    //   handHW>0 但 skip=0   → 找到了却没删（不该发生）
                                    //   handHW==skip         → 勾选即全删，行为正确
                                    // 历史对照（真机）：
                                    //   v30：handSkip=33 但没勾也删（OR 残留）
                                    //   v31：handSkip=0 / handKeep=33（判据废掉，开关失效）
                                    long handHWCount = 0;
                                    // v32：不再有「保留」分支，handKeepCount /
                                    // handKeepLogCount 已删除。勾了去除手写就一律
                                    // 删掉，不因它有没有识别文字而区别对待 ——
                                    // 这是本轮日志定死的语义（见下方判据块注释）。
                                    // v31：纯空白切片（空格 / 填空下划线）计数。
                                    // 这个数 > 0 才说明空格这条链真的通了。
                                    long spaceSliceCount = 0;
                                    long tabRunCount = 0;
                                    NSMutableSet *blockTypeSet = [NSMutableSet set];
                                    NSMutableSet *seenText = [NSMutableSet set];
                                    // v22：有多少个「stype 本来是图片」的切片
                                    // 因为有文字而改走文字。这个数 > 0 就说明
                                    // 本次修复命中了「手写转文字」那条路径。
                                    long sliceTextWinCount = 0;
                                    NSString *firstSliceImgSType = nil;
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
                                                        // v24：JSON 兜底 —— 若面板没读到，
                                                        // 看看 page 上有没有同名开关。有就用，
                                                        // 没有就不动（不覆盖上面已读到的值）。
                                                        // v27：合并语义下这段变成「所有来源都还没读到」
                                                        // 才补一次；已经读到就不重复跑，避免日志噪音。
                                                        if (!gCSFSOptKnown) CSFSPullOptions(page, @"json.page");
                                                        id blocks = [page objectForKey:@"segments"];
                                                        if (![blocks isKindOfClass:[NSArray class]]) continue;
                                                        for (id block in blocks) {
                                                            // v21：不再要求 block 必须是字典 ——
                                                            // 模型对象也要能取图（CSFSValue 两态通吃）。
                                                            // 原写法在这里 continue，模型对象 block 会整块消失。
                                                            // v16：块类型过滤。
                                                            // 实证样本 27 块 = 25 PARA + 1 IMAGE + 1 LINE。
                                                            id btypeRaw = CSFSValue(block, @"type");
                                                            NSString *bt = [btypeRaw isKindOfClass:[NSString class]]
                                                                         ? (NSString *)btypeRaw : @"PARA";

                                                            // v22：块类型观测。
                                                            // 只认 PARA/IMAGE/LINE 是 v16 的假设，
                                                            // 「手写转文字」很可能引入了新类型
                                                            // （HANDWRITE / TEXT / OCR / NOTE…），
                                                            // 而白名单式过滤会把它们整块吞掉。
                                                            // 每遇到一种新类型打一行 shape ——
                                                            // 这一行能直接看到手写块的字段构成。
                                                            // v24：「去除手写 / 去除印章」的第一道 —— 块级隐藏。
                                                            //
                                                            // CSOcrPageSegment 有 _hiding（BOOL）。App 渲染时
                                                            // 就是靠它把被选项隐掉的块排除在外。
                                                            // 我们以前完全不看这个字段，所以哪怕 App 已经把
                                                            // 块标成隐藏，导出照样会把它吐出来。
                                                            if (CSFSBoolValue(CSFSValue(block, @"hiding"))) {
                                                                hiddenBlockCount++;
                                                                continue;
                                                            }

                                                            if (bt.length > 0 && ![blockTypeSet containsObject:bt]) {
                                                                [blockTypeSet addObject:bt];
                                                                CSFS_LOG(@"v22 new block type: %@ shape=%@",
                                                                         bt, CSFSDescribeShape(block));
                                                            }

                                                            // v21：IMAGE 块导出成图片段落。
                                                            // ⚠ v16 起把非 PARA 一律 continue，图就是这么丢的：
                                                            //   当时的目的是去掉 IMAGE 块产生的空 <w:p/>，
                                                            //   代价是图片一起被扔掉。
                                                            //   LINE 是版式分隔线，仍然跳过。
                                                            if ([bt isEqualToString:@"IMAGE"]) {
                                                                imgBlockCount++;

                                                                // v22：先问「块里有没有已经识别好的文字」。
                                                                // 手写转文字之后，手写区在 JSON 里**仍然是
                                                                // IMAGE 块**（版面语义上它真的是图），
                                                                // 识别结果压在块内部。v21 在这里无条件取图，
                                                                // 等于把识别结果丢掉、再把笔迹图贴回去 ——
                                                                // 正是用户看到的现象。
                                                                //
                                                                // ⚠ 但不能对所有 IMAGE 块都这么干：用户手动插入的
                                                                //   照片/截图同样带着 CamScanner 历史 OCR 缓存，
                                                                //   一律文字化会把真图片变成一堆字。
                                                                //   所以只对「手写类」块放宽：image_category 属于
                                                                //   HANDWRITTEN 一族，或者块里有 paras 结构。
                                                                //   （image_category 的值域在二进制里实证为
                                                                //     HANDWRITTEN / STAMP，STAMP 是指纹印章，不展开。）
                                                                id cat = CSFSValue(block, @"image_category");
                                                                NSString *catStr = [cat isKindOfClass:[NSString class]]
                                                                    ? [(NSString *)cat lowercaseString] : nil;
                                                                BOOL handwriteLike =
                                                                    (catStr.length > 0 &&
                                                                     ([catStr containsString:@"handwrit"] ||
                                                                      [catStr containsString:@"text"] ||
                                                                      [catStr containsString:@"ocr"]));
                                                                BOOL hasParaTree = (CSFSValue(block, @"paras") != nil);

                                                                // ── v24：去除印章（块级）
                                                                //
                                                                // 判据就是 App 自己的 customImageCategoryType：
                                                                // 2 = STAMP、1 = HANDWRITTEN（严格相等）。
                                                                // 只勾了「去除印章」时才拦；没勾就照常输出，
                                                                // 因为印章本身常常就是合同的要件。
                                                                NSInteger catType = CSFSCategoryType(block);
                                                                if (gCSFSHideStamp && catType == 2) {
                                                                    stampSkipCount++;
                                                                    CSFS_LOG(@"v25 hideStamp: skip IMAGE block cat=%@", catStr ?: @"(nil)");
                                                                    continue;
                                                                }

                                                                // ── v25：去除手写（块级）
                                                                //
                                                                // 必须排在下面「文字优先」之前：用户勾的是「删掉手写」，
                                                                // 不是「把手写换成文字」。v22 的文字优先是对的，
                                                                // 但它没让位给这个开关，于是勾了去除手写，
                                                                // 手写的 OCR 文字照样被写进 Word —— 正是用户说的「没去除」。
                                                                //
                                                                // 判据从 v24 的「含 text/ocr 就算手写」收紧成 catType==1：
                                                                // 前者会把带 OCR 结果的普通图块也当手写删掉。
                                                                if (gCSFSHideWritten && catType == 1) {
                                                                    handSkipCount++;
                                                                    CSFS_LOG(@"v25 hideWritten: skip IMAGE block cat=%@", catStr ?: @"(nil)");
                                                                    continue;
                                                                }

                                                                // v22：这个图块是不是「可能是重复的手写底图」。
                                                                // 在 if 内被置 YES，出图时据此打标记。
                                                                BOOL suspectHandwriteImg = NO;
                                                                if (catStr.length > 0 && imgDiagDone == NO) {
                                                                    CSFS_LOG(@"v22 IMAGE block category=%@ handwriteLike=%d paraTree=%d",
                                                                             catStr, (int)handwriteLike, (int)hasParaTree);
                                                                }
                                                                if (handwriteLike || hasParaTree) {
                                                                    NSArray *btParas = CSFSBlockTextParas(block);
                                                                    NSString *plain = CSFSParasPlainText(btParas);
                                                                    NSString *trimmed =
                                                                        [plain stringByTrimmingCharactersInSet:CSFSWhiteSpaceSet()];
                                                                    if (trimmed.length > 0) {
                                                                        if ([seenText containsObject:trimmed]) {
                                                                            imgDupCount++;
                                                                            CSFS_LOG(@"v22 IMAGE block -> text already present, skip image (%lu chars)",
                                                                                     (unsigned long)trimmed.length);
                                                                        } else {
                                                                            [seenText addObject:trimmed];
                                                                            imgTextCount++;
                                                                            CSFS_LOG(@"v22 IMAGE block -> text wins (%lu paras, %lu chars)",
                                                                                     (unsigned long)btParas.count,
                                                                                     (unsigned long)trimmed.length);
                                                                            [styledParas addObjectsFromArray:btParas];
                                                                        }
                                                                        continue;
                                                                    }
                                                                    CSFS_LOG(@"v22 WARN IMAGE block handwrite-like but no text, fall back to image");
                                                                    // v22：先别信这个判断，延后到全文解析完再定。
                                                                    // 见 kCSFSParaImgSuspect 的注释。
                                                                    suspectHandwriteImg = YES;
                                                                }

                                                                NSDictionary *found = CSFSFindImage(block, 0);
                                                                if (imgDiagDone == NO) {
                                                                    imgDiagDone = YES;
                                                                    // 找到时只打形状（短）；
                                                                    // 没找到时打深度内容 —— 那一行是
                                                                    // 下一轮唯一能定位「图藏哪了」的线索。
                                                                    if (found) {
                                                                        CSFS_LOG(@"v21 DIAG image block -> FOUND shape=%@",
                                                                                 CSFSDescribeShape(block));
                                                                    } else {
                                                                        CSFS_LOG(@"v21 DIAG image block -> NOT FOUND deep=%@",
                                                                                 CSFSDescribeDeep(block, 0));
                                                                    }
                                                                }
                                                                if (found) {
                                                                    imgSeq++;
                                                                    NSMutableDictionary *info =
                                                                        [NSMutableDictionary dictionaryWithDictionary:found];
                                                                    [info setObject:[NSNumber numberWithLong:imgSeq]
                                                                             forKey:kCSFSImgName];
                                                                    CSFS_LOG(@"v21 image #%ld %@ %@x%@ bytes=%lu",
                                                                             imgSeq,
                                                                             [info objectForKey:kCSFSImgExt],
                                                                             [info objectForKey:kCSFSImgPxW],
                                                                             [info objectForKey:kCSFSImgPxH],
                                                                             (unsigned long)[[info objectForKey:kCSFSImgData] length]);
                                                                    NSMutableDictionary *ip =
                                                                        [NSMutableDictionary dictionaryWithCapacity:1];
                                                                    [ip setObject:info forKey:kCSFSParaImage];
                                                                    // v22：手写类但没文字的图块先打标记，
                                                                    // 全文解析完再决定去留（见 kCSFSParaImgSuspect）。
                                                                    if (suspectHandwriteImg) {
                                                                        [ip setObject:[NSNumber numberWithBool:YES]
                                                                               forKey:kCSFSParaImgSuspect];
                                                                    }
                                                                    [styledParas addObject:ip];
                                                                }
                                                                continue;
                                                            }
                                                            // v22：只跳过 LINE（版式分隔线）。
                                                            // 其余块类型只要有 paras 就按文字处理 ——
                                                            // v16 的 `![bt isEqual:@"PARA"] continue`
                                                            // 是白名单，任何新类型（手写、表格、题注）
                                                            // 都会被整块吞掉，且没有任何日志痕迹。
                                                            if ([bt isEqualToString:@"LINE"]) {
                                                                continue;
                                                            }
                                                            id paras = CSFSValue(block, @"paras");
                                                            if (![paras isKindOfClass:[NSArray class]]) continue;

                                                            // v18：每个 para 生成一个独立段落，
                                                            // 并把每个 slice 的 style 一并带出来。
                                                            for (id para in paras) {
                                                                // v19：para 也可能是模型对象。
                                                                // 原写法先判 objectForKey: 再 continue，
                                                                // 非字典的 para 会被整段丢掉 —— 文字都留不下。
                                                                id slices = CSFSValue(para, @"slices");
                                                                if (![slices isKindOfClass:[NSArray class]]) continue;

                                                                // 只 dump 一次 para，用独立开关避免和 slice 的抢。
                                                                if (paraDiagDone == NO) {
                                                                    paraDiagDone = YES;
                                                                    CSFS_LOG(@"v21 DIAG para %@",
                                                                             CSFSDescribeShape(para));
                                                                }

                                                                NSMutableArray *runs =
                                                                    [NSMutableArray arrayWithCapacity:[(NSArray *)slices count]];
                                                                BOOL hasText = NO;
                                                                for (id sl in slices) {
                                                                    // ── v24：去印章 / 去手写（切片级）+ 切片隐藏
                                                                    //
                                                                    // 三处过滤统一放在最前面，理由：只要拦在
                                                                    // 「文字优先」之后，手写片段的 OCR 文字就已经
                                                                    // 进了 runs，再拦也删不掉了。
                                                                    {
                                                                        id stRaw = CSFSValue(sl, @"stype");
                                                                        NSString *stLow =
                                                                            [stRaw isKindOfClass:[NSString class]]
                                                                            ? [(NSString *)stRaw lowercaseString] : nil;
                                                                        // v25：slice 自己也带 image_category 时以它为准
                                                                        // （与 -[CSOcrPageSegment customImageCategoryType]
                                                                        //  同一套字符串），stype 只作为兜底。
                                                                        NSInteger slCat = CSFSCategoryType(sl);
                                                                        if (gCSFSHideStamp &&
                                                                            (slCat == 2 ||
                                                                             (stLow.length > 0 &&
                                                                              ([stLow containsString:@"stamp"] ||
                                                                               [stLow containsString:@"seal"])))) {
                                                                            stampSkipCount++;
                                                                            CSFS_LOG(@"v25 hideStamp: skip slice stype=%@ cat=%ld",
                                                                                     stLow ?: @"(nil)", (long)slCat);
                                                                            continue;
                                                                        }
                                                                        // ═══════════════════════════════════════════
                                                                        // v31：去除手写 —— 判据从「stype 含 handwrit」
                                                                        //      改成「确实是手写**笔迹图**」。
                                                                        //
                                                                        // 真机日志（CSFS.log，v30 版）：
                                                                        //   v27 stats: … stampSkip=1 handSkip=33 paras=21
                                                                        //   v21 stats: paras=21 runs=90
                                                                        // 而距上一版 runs 是 123 —— **正好少 33**，
                                                                        // 每一条都是这行删的。用户看到的两个现象：
                                                                        //   · 正文里 33 段文字凭空消失
                                                                        //   · 勾不勾「去除手写」结果一样（每行都 cat=0 却照样删）
                                                                        //
                                                                        // 为什么 stype 不能当判据：
                                                                        // OCR 引擎对**手写体文档**（比如手写合同、手写笔记）
                                                                        // 会把识别出的正文文字 slice 的 stype 也标成
                                                                        // "handwritten" —— 它描述的是「这段字的**来源笔迹**」，
                                                                        // 不是「这是个笔迹图片」。日志里全部 `cat=0`
                                                                        // （image_category 为空）就是铁证：
                                                                        // 真正的印章/手写**图**会带 image_category=STAMP/
                                                                        // HANDWRITTEN，而这 33 条一条都没有。
                                                                        //
                                                                        // 正确判据（三条同时满足才算手写图）：
                                                                        //   ① image_category == 1（HANDWRITTEN）
                                                                        //      —— App 自己的 -[CSOcrPageSegment
                                                                        //         customImageCategoryType] 的语义
                                                                        //   ② 没有识别文字（有文字就是正文，文字优先）
                                                                        //   ③ 或 stype 明确是图片族（含 image/img/pic/photo）
                                                                        // 只有 ② 单独成立不够：手写转文字后 stype 仍是
                                                                        // handwrite 但 text 已填好，那是正文。
                                                                        // ═══════════════════════════════════════════
                                                                        if (gCSFSHideWritten) {
                                                                            BOOL catSaysHW  = (slCat == 1);
                                                                            BOOL stypeSaysHW =
                                                                                (stLow.length > 0 &&
                                                                                 [stLow containsString:@"handwrit"]);
                                                                            // 有识别文字 → 这段是正文，绝不按手写删
                                                                            NSString *hwText = CSFSSliceText(sl);
                                                                            BOOL hasTextHW = (hwText != nil &&
                                                                                              !CSFSIsPureWhiteSpace(hwText));
                                                                            // ═══════════════════════════════════
                                                                            // v32：**v31 这里改错了，本轮纠正回来。**
                                                                            //
                                                                            // v31 的理由是「日志里 33 条全是 cat=0，
                                                                            // 而真手写图应该带 image_category=1」，
                                                                            // 于是把 stype 判据整个废掉。
                                                                            // 但真机日志（v31，三次导出）推翻了它：
                                                                            //
                                                                            //   v29 runs=123 （空格被丢，手写保留）
                                                                            //   v30 runs=90  + handSkip=33 = 123
                                                                            //   v31 runs=170 = 123 + spaceSlices47
                                                                            //   且 v31 handSkip=0 / handKeep=33
                                                                            //
                                                                            // 170 = 90 + 47 + 33 三版数字严丝合缝：
                                                                            // **那 33 条就是手写内容本身**，v30 删得对，
                                                                            // 错的是它「没勾也删」（OR 残留，v31 已修）。
                                                                            // v31 把判据废掉 → 手写开关彻底失效，
                                                                            // 用户原话「去除手写选择了不生效」。
                                                                            //
                                                                            // 另一个决定性事实：日志里
                                                                            //   v21 DIAG slice dict(11){mathml,img,height,
                                                                            //     style,break_line,position,preview_info,
                                                                            //     text,stype,add_tabstop,width}
                                                                            // **slice 层根本没有 image_category 字段**，
                                                                            // 所以 slCat==1 永远为假 ——
                                                                            // v31 的判据是「永远不成立」的死条件。
                                                                            //
                                                                            // 正确判据（任一成立即手写）：
                                                                            //   ① image_category == 1（有该字段时，权威）
                                                                            //   ② stype 含 handwrit（slice 层唯一的实证信号）
                                                                            // 但**都要求这段没有真正的正文文字**：
                                                                            // 手写转文字后 text 已填好、且用户没勾「手写保留成图」，
                                                                            // 那时文字优先，不算手写图。
                                                                            //
                                                                            // 例外：纯空白不算「正文文字」。
                                                                            // 手写填空处常被识别成空格 + 下划线，
                                                                            // 那是手写的痕迹而不是正文 —— 勾了去手写就该删。
                                                                            // ═══════════════════════════════════
                                                                            BOOL looksHW = (catSaysHW || stypeSaysHW);
                                                                            if (looksHW) {
                                                                                handHWCount++;
                                                                                // ═══════════════════════════════════
                                                                                // 勾了「去除手写」→ 这段就该消失，**不看它有没有
                                                                                // 识别文字**。这一点是本轮日志定死的：
                                                                                //
                                                                                // 那 33 条实战全是 hasText=1 的（手写填空被
                                                                                // 识别成了文字）。若在这里用「有文字就保留」，
                                                                                // 它们就会被全部 KEEP，开关等于没接 ——
                                                                                // 这正是 v31 的表现（handSkip=0, handKeep=33）。
                                                                                // 用户原话「去除手写选择了不生效」即此。
                                                                                //
                                                                                // 用户勾的语义是「把手写内容从结果里去掉」，
                                                                                // 不是「把手写换成文字」。文字优先是**不勾**时的
                                                                                // 默认行为（v22 的规则），不能盖过用户的显式选择。
                                                                                //
                                                                                // gCSFSHandToImage（手写保留成图）同样是要去掉文字，
                                                                                // 所以两种情况都删，只是日志里分开标。
                                                                                // ═══════════════════════════════════
                                                                                handSkipCount++;
                                                                                CSFS_LOG(@"v32 hideWritten: skip HW slice "
                                                                                         @"(stype=%@ cat=%ld hasText=%d "
                                                                                         @"handToImg=%d) —— 勾选即去除",
                                                                                         stLow ?: @"(nil)",
                                                                                         (long)slCat,
                                                                                         (int)hasTextHW,
                                                                                         (int)gCSFSHandToImage);
                                                                                continue;
                                                                            }
                                                                        }
                                                                        if (CSFSBoolValue(CSFSValue(sl, @"hiding"))) {
                                                                            hiddenBlockCount++;
                                                                            continue;
                                                                        }
                                                                    }
                                                                    // v21：图片片段单独成段。
                                                                    // 依据是 stype 这个类型字段（详见
                                                                    // CSFSSliceImageInfo 注释）。
                                                                    // v22：但文字优先 —— 这个 slice 只要有
                                                                    // 识别好的文字，就不许当图处理。
                                                                    // 手写转文字后 stype 仍是 handwrite，
                                                                    // 只靠 stype 判图会把文字连同格式一起丢掉。
                                                                    //
                                                                    // 单独取一次 slText 只为留一行日志：
                                                                    // 若下一轮手写还是图，这行能直接区分
                                                                    // 「App 压根没识别」和「我们判错了」。
                                                                    NSString *slText = CSFSSliceText(sl);
                                                                    // v22：这个切片「本来会被当成图片」吗？
                                                                    // 只有本来会当图片、却因为有文字而改判的，
                                                                    // 才是本次修复的真实战果，单独计数。
                                                                    if (slText != nil && CSFSSTypeLooksImage(sl)) {
                                                                        sliceTextWinCount++;
                                                                        if (!firstSliceImgSType) {
                                                                            id stv = CSFSValue(sl, @"stype");
                                                                            if ([stv isKindOfClass:[NSString class]]) {
                                                                                firstSliceImgSType = (NSString *)stv;
                                                                            }
                                                                        }
                                                                    }
                                                                    // v24：文字优先的适用条件改由面板开关决定。
                                                                    //   handWrittenToImage == NO  → 手写转文字，文字优先
                                                                    //                                （v22 的规则，实测可用）
                                                                    //   handWrittenToImage == YES → 用户要手写保留成图，
                                                                    //                                就不该由我们去抢它的图
                                                                    // 读不到开关时沿用文字优先，不改变已能工作的行为。
                                                                    BOOL textWins = (slText != nil) &&
                                                                                    (gCSFSOptKnown ? !gCSFSHandToImage : YES);
                                                                    NSDictionary *sliceImg =
                                                                        textWins ? nil : CSFSSliceImageInfo(sl);
                                                                    if (sliceImg) {
                                                                        imgSeq++;
                                                                        NSMutableDictionary *si =
                                                                            [NSMutableDictionary dictionaryWithDictionary:sliceImg];
                                                                        [si setObject:[NSNumber numberWithLong:imgSeq]
                                                                               forKey:kCSFSImgName];
                                                                        CSFS_LOG(@"v21 slice image #%ld %@ %@x%@ bytes=%lu",
                                                                                 imgSeq,
                                                                                 [si objectForKey:kCSFSImgExt],
                                                                                 [si objectForKey:kCSFSImgPxW],
                                                                                 [si objectForKey:kCSFSImgPxH],
                                                                                 (unsigned long)[[si objectForKey:kCSFSImgData] length]);
                                                                        NSMutableDictionary *ip =
                                                                            [NSMutableDictionary dictionaryWithCapacity:1];
                                                                        [ip setObject:si forKey:kCSFSParaImage];
                                                                        [styledParas addObject:ip];
                                                                        continue;
                                                                    }
                                                                    NSMutableDictionary *run = CSFSParseSlice(sl, &diagDone);
                                                                    if (!run) continue;
                                                                    NSString *tt = [run objectForKey:kCSFSRunText];
                                                                    // ═══════════════════════════════════════
                                                                    // v31：**纯空白 run 必须收下**。
                                                                    //
                                                                    // 原来这行是：
                                                                    //   if (trimmed.length == 0) continue;
                                                                    // 空格 / 带下划线的空格（填空横线）在这里被
                                                                    // 第二次丢掉 —— 就算 CSFSSliceText 已经把它
                                                                    // 取出来了，到这一步仍然进不了 runs。
                                                                    //
                                                                    // 两次丢掉的叠加效果正是用户说的：
                                                                    //   「文字之间有空格…你都没识别出来」
                                                                    // 而且「带下划线的空格」尤其明显：
                                                                    // 它是一条纯空白 + underline=1 的 run，
                                                                    // 被丢之后整条填空线消失，
                                                                    // 打印出来合同上的填空处就没有横线了。
                                                                    //
                                                                    // 判据改成：只有**真正的空串**才 continue。
                                                                    // 纯空白是内容，要进 runs。
                                                                    // ═══════════════════════════════════════
                                                                    if (tt.length == 0) continue;
                                                                    BOOL ttIsSpace = CSFSIsPureWhiteSpace(tt);
                                                                    if (ttIsSpace) {
                                                                        spaceSliceCount++;
                                                                        // 纯空白也要算「本段有内容」，
                                                                        // 否则整段会被下面的 if (!hasText) 丢掉
                                                                        hasText = YES;
                                                                        [runs addObject:run];
                                                                        continue;
                                                                    }
                                                                    hasText = YES;
                                                                    if ([[run objectForKey:kCSFSRunTab] boolValue]) tabRunCount++;
                                                                    [runs addObject:run];
                                                                }
                                                                // 全空白段落仍然丢掉 —— 但注意「全空白」在这里
                                                                // 指的是**一个 run 都没有**。
                                                                // 只含空格的段落（如填空行）已经通过上面
                                                                // spaceSliceCount 分支把 hasText 置 YES，
                                                                // 会正常保留。
                                                                if (!hasText) continue;

                                                                NSMutableDictionary *p =
                                                                    [NSMutableDictionary dictionaryWithCapacity:6];
                                                                [p setObject:runs forKey:kCSFSParaRuns];

                                                                // v24：把段落自身的版式字段带出来。
                                                                //
                                                                // 这些键名来自 CSOcrPageSegmentPara 的 ivar
                                                                // （JSON 键名与 ivar 同名，去掉下划线前缀）：
                                                                //   indent_first_line / indent_left / indent_right
                                                                //   tabs / line_gap / mostFrequentFontSize
                                                                // App 预览就是按这些渲染的，而 v23 一个都没读 ——
                                                                // 全靠自编规则，所以永远对不上。
                                                                {
                                                                    id fl = CSFSValue(para, @"indent_first_line");
                                                                    id il = CSFSValue(para, @"indent_left");
                                                                    id ir = CSFSValue(para, @"indent_right");
                                                                    id ih = CSFSValue(para, @"indent_hanging");
                                                                    id fb = CSFSValue(para, @"floating_box");
                                                                    id tb = CSFSValue(para, @"tabs");
                                                                    id lg = CSFSValue(para, @"line_gap");
                                                                    id bp = CSFSValue(para, @"mostFrequentFontSize");
                                                                    if (fl) [p setObject:fl forKey:kCSFSParaIndFL];
                                                                    if (il) [p setObject:il forKey:kCSFSParaIndL];
                                                                    if (ir) [p setObject:ir forKey:kCSFSParaIndR];
                                                                    if (ih) [p setObject:ih forKey:kCSFSParaIndH];
                                                                    if (fb) [p setObject:fb forKey:kCSFSParaFloat];
                                                                    if (tb) [p setObject:tb forKey:kCSFSParaTabs];
                                                                    if (lg) [p setObject:lg forKey:kCSFSParaLineGap];
                                                                    if (bp) [p setObject:bp forKey:kCSFSParaBasePt];

                                                                    // 只 dump 一次，把真实取值和量级打进日志。
                                                                    // 单位只能靠这个日志定死，静态分析做不到。
                                                                    if (layoutDiagDone == NO) {
                                                                        layoutDiagDone = YES;
                                                                        CSFS_LOG(@"v25 DIAG para layout: fl=%@ il=%@ ir=%@ ih=%@ fb=%@"
                                                                                 @" lg=%@ bp=%@ tabs=%@ shape=%@",
                                                                                 fl ?: @"(nil)", il ?: @"(nil)",
                                                                                 ir ?: @"(nil)", ih ?: @"(nil)",
                                                                                 fb ?: @"(nil)",
                                                                                 lg ?: @"(nil)",
                                                                                 bp ?: @"(nil)",
                                                                                 tb ? CSFSDescribeShape(tb) : @"(nil)",
                                                                                 CSFSDescribeShape(para));
                                                                    }
                                                                }

                                                                // 段落级对齐。
                                                                // App 渲染时读的是 para.horizontalTextAligment
                                                                // （NSTextAlignment 数值 0/1/2/3），
                                                                // justification 只是落盘用的别名。
                                                                // 两个都试，App 那个优先 —— 以渲染时为准。
                                                                id alignRaw = CSFSValue(para, @"horizontalTextAligment");
                                                                if (!alignRaw) alignRaw = CSFSValue(para, @"justification");
                                                                NSString *jc = CSFSMapJustification(alignRaw);
                                                                if (jc) [p setObject:jc forKey:kCSFSParaAlign];

                                                                // v22：记下这段文字，供 IMAGE 块去重。
                                                                // 手写区有时在相邻 PARA 块里也出现一遍，
                                                                // 不去重就是「文字 + 图片」各来一份。
                                                                {
                                                                    NSString *plain =
                                                                        [CSFSParasPlainText(@[p])
                                                                         stringByTrimmingCharactersInSet:CSFSWhiteSpaceSet()];
                                                                    if (plain.length > 0) [seenText addObject:plain];
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
                                        CSFS_LOG(@"v21 json parsed, %lu 段",
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
                                            // 频次表的键是 NSString（避免浮点做字典键），
                                            // 所以这里必须用 integerValue 把它转回来。
                                            // ⚠ 不能用 longValue：那是 NSNumber 的方法，
                                            //    NSString 只有 integerValue / longLongValue /
                                            //    intValue / doubleValue，没有 longValue。
                                            //    CI 第 3118 行就是这么报的：
                                            //    no visible @interface for 'NSString'
                                            //    declares the selector 'longValue'
                                            long key = (long)[k integerValue];
                                            // 同票时取更小的字号：正文通常是小的那个
                                            if (c > bestCnt || (c == bestCnt && key < bestKey)) {
                                                bestCnt = c; bestKey = key;
                                            }
                                        }
                                        if (bestCnt > 0) defaultPt = (double)bestKey;
                                        CSFS_LOG(@"v21 defaultPt=%.1f (样本 %ld 个 run)",
                                                 defaultPt, bestCnt);
                                        // v23：把完整字号分布打出来。
                                        // 只有众数看不出「有几档字号、各占多少」，
                                        // 而「同一篇里字大忽小」正是靠这个才能定位：
                                        //   只有一档 → 本来就是统一的，别动
                                        //   两档且差距 <20% → OCR 逐行度量抖动，归并
                                        //   两档且差距 >50% → 真的是标题/正文，保留
                                        {
                                            NSArray *ks = [[freq allKeys]
                                                sortedArrayUsingComparator:^NSComparisonResult(id a, id b) {
                                                    return [[NSNumber numberWithLong:(long)[(NSString *)a integerValue]]
                                                            compare:[NSNumber numberWithLong:(long)[(NSString *)b integerValue]]];
                                                }];
                                            NSMutableString *ds = [NSMutableString string];
                                            for (NSString *k in ks) {
                                                [ds appendFormat:@"%@pt×%ld ",
                                                 k, (long)[[freq objectForKey:k] longValue]];
                                            }
                                            CSFS_LOG(@"v23 font size histogram: %@", ds);
                                        }
                                    }

                                    // v22：延后判定「可疑手写图」的去留。
                                    //
                                    // 为什么不在遇到图块时就决定：那一刻还不知道
                                    // 整个文档有没有识别成果。等全文解析完，
                                    // 用「有没有识别出文字」反推用户开的模式，
                                    // 判定才有依据。
                                    //   imgText>0 或 sliceTextWin>0 → 开了手写转文字，
                                    //     抠不出文字的手写图就是与文字重复的底图 → 丢
                                    //   两者都是 0 → 没识别，图本身就是内容 → 留
                                    long imgSuspectDropped = 0;
                                    if (imgTextCount > 0 || sliceTextWinCount > 0) {
                                        NSMutableArray *kept =
                                            [NSMutableArray arrayWithCapacity:styledParas.count];
                                        for (NSDictionary *pp2 in styledParas) {
                                            if ([pp2 objectForKey:kCSFSParaImgSuspect]) {
                                                imgSuspectDropped++;
                                                continue;
                                            }
                                            [kept addObject:pp2];
                                        }
                                        if (imgSuspectDropped > 0) {
                                            CSFS_LOG(@"v22 dropped %ld duplicate handwrite images",
                                                     imgSuspectDropped);
                                            [styledParas setArray:kept];
                                        }
                                    }

                                    // v18：格式提取统计。
                                    // 这是判断「格式有没有真的提取到」的唯一直接依据：
                                    // 若这三个数都是 0，说明字段名对不上，需要看上面的 DIAG dump。
                                    {
                                        long nColor = 0, nBold = 0, nSize = 0, nRun = 0;
                                        NSDictionary *firstStyled = nil;
                                        for (NSDictionary *pp in styledParas) {
                                            id rs = [pp objectForKey:kCSFSParaRuns];
                                            if (![rs isKindOfClass:[NSArray class]]) continue;
                                            for (NSDictionary *rr in (NSArray *)rs) {
                                                nRun++;
                                                if ([rr objectForKey:kCSFSRunColor]) nColor++;
                                                if ([[rr objectForKey:kCSFSRunBold] boolValue]) nBold++;
                                                if ([rr objectForKey:kCSFSRunSize]) nSize++;
                                                // 留一个「确实带格式」的 run 当样本，
                                                // 一旦格式仍然丢失，这行日志能直接看出
                                                // 是「压根没提取到」还是「提取到了但没渲染」。
                                                if (!firstStyled && [rr count] > 1) {
                                                    firstStyled = rr;
                                                }
                                            }
                                        }
                                        CSFS_LOG(@"v21 stats: paras=%lu runs=%ld color=%ld bold=%ld size=%ld"
                                                 @" imgBlocks=%ld imgs=%ld",
                                                 (unsigned long)styledParas.count,
                                                 nRun, nColor, nBold, nSize,
                                                 imgBlockCount, imgSeq);
                                        // v22：手写转文字的关键三行。
                                        //   types   —— 文档里到底有哪几种块
                                        //   imgText —— 多少个 IMAGE 块因为有文字而没插图
                                        //   imgDup  —— 多少个 IMAGE 块的文字判定为重复被跳过
                                        // 若 imgText=0 且 imgBlocks>0，说明手写区没有被识别成文字，
                                        // 应当去看 "v22 new block type: ..." 与
                                        // "v22 IMAGE block category=..." 两行。
                                        CSFS_LOG(@"v22 stats: types=[%@] imgText=%ld imgDup=%ld"
                                                 @" sliceTextWin=%ld dropHW=%ld firstSliceImgSType=%@",
                                                 [[blockTypeSet allObjects]
                                                  componentsJoinedByString:@","],
                                                 imgTextCount, imgDupCount,
                                                 sliceTextWinCount, imgSuspectDropped,
                                                 firstSliceImgSType ?: @"(none)");
                                        // v24：开关判读的一行结论。
                                        // optKnown=0 说明面板状态压根没读到 ——
                                        // 那时 hideStamp/hideWritten 一定是 0，
                                        // 不能据此认为「用户没勾」，要单独看 opts 那行。
                                        CSFS_LOG(@"v33 stats: optKnown=%d src=%@ hideWritten=%d hideStamp=%d"
                                                 @" handToImage=%d seen(w/s/h)=%d%d%d | hiddenBlock=%ld"
                                                 @" stampSkip=%ld handHW=%ld handSkip=%ld"
                                                 @" spaceSlices=%ld"
                                                 @" tabRuns=%ld paras=%lu"
                                                 @"（空格展开数见 v33 space stats）",
                                                 (int)gCSFSOptKnown, gCSFSOptSrc ?: @"(none)",
                                                 (int)gCSFSHideWritten, (int)gCSFSHideStamp,
                                                 (int)gCSFSHandToImage,
                                                 (int)gCSFSSeenWritten, (int)gCSFSSeenStamp,
                                                 (int)gCSFSSeenHandTo,
                                                 hiddenBlockCount, stampSkipCount,
                                                 handHWCount, handSkipCount,
                                                 spaceSliceCount,
                                                 tabRunCount,
                                                 (unsigned long)styledParas.count);
                                        if (firstStyled) {
                                            CSFS_LOG(@"v21 sample run: %@", firstStyled);
                                        } else {
                                            // 一个带格式的 run 都没有 —— 字段名或层级对不上，
                                            // 去看上面的 "v21 DIAG slice / style" 两行。
                                            CSFS_LOG(@"v21 stats: NO styled run at all");
                                        }
                                        // 图片这块的三种失败要能一眼分开：
                                        //   imgBlocks>0 且 imgs=0  → 块找到了但没捞出图片字节，
                                        //                            说明图不在 block 的可见字段里
                                        //   imgBlocks=0             → 压根没有 IMAGE 块，
                                        //                            图可能在 PARA 块的 slice 里
                                        //   imgs>0 但文档没图        → 写入端问题
                                        if (imgBlockCount > 0 && imgSeq == 0) {
                                            CSFS_LOG(@"v21 WARN: 有 %ld 个 IMAGE 块但一张也没取到，"
                                                     @"图不在 block 的直接字段里",
                                                     imgBlockCount);
                                        }
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