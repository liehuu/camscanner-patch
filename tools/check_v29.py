#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_v29.py —— v29「开关真身在 CSImageToJsonManager，且属性名少一个 n」的静态判据。

为什么必须单独有这个检查器：
  v24～v28 五轮，每一轮都「改完 → 门禁 11/11 → CI 通过 → 装机 → 还是一样」。
  门禁全绿却连错五轮，说明**门禁本身对这类缺陷完全失明**。
  本轮用反汇编定死的真因是两条：

  【错一】属性名拼写不同（最要命）
      CSOcrPage / Document 用：hideWrittenImage   （Writ-t-en，完整）
      CSImageToJsonManager 用：hideWritteImage    （Writ-t-e，少一个 n）
      反汇编 -updateCategoryListViewItemsWith... 里并排出现：
          1012e4124: bl STUB[hideWrittenImage]      ; 读 Document
          1012e414c: bl STUB[setHideWritteImage:]   ; 写 Manager
      前五轮读的一直是完整拼写，落在 Manager 上恒为 nil，
      于是 optKnown=0 seen(w/s/h)=000 五个版本一字未变。

  【错二】读错了对象
      真正执行删除的是 Manager 自己的 -removeHandWritten:document: /
      -removeHiddenImagesInSegments:document: / -removeHandwrittenFormula:document:，
      入口 -jsonRemovedHiddenImage:document: 按开关决定调哪几个。

所以本检查器断言四件事，每一条都对应一个「会让它重新失效」的具体改法：

  L1 名字表里必须同时有 hideWritteImage（少 n）与 hideWrittenImage（完整）
     —— 只留完整拼写 = 退回 v24～v28 的失败态
  L2 必须有 CSImageToJsonManager 单例获取，且**排在 currentAIEditModel 之前**
     —— 顺序掉了就等于又去读那个恒为 nil 的对象
  L3 必须能按名字表回写（setter 由 getter 名自动派生，不许硬写 setHideWritteImage:）
     —— 硬写一个拼写就丢掉另一份
  L4 三个名字表的每一条都要在私有方法里被真正使用
     —— 定义了不调用 = 死代码，和 v25 那个「永远执行不到的分支」同类

用法：python3 tools/check_v29.py src/CamScannerSaveToFiles.m
"""

import re
import sys

fails = []
oks = []


def ok(m):
    oks.append(m)


def fail(m):
    fails.append(m)


def strip_comments(s):
    """只抹注释，保留字符串字面量 —— L1 判的正是字符串里的拼写。"""
    out = list(s)
    n = len(s)
    i = 0
    while i < n:
        if s[i] == '/' and i + 1 < n and s[i + 1] == '/':
            j = i
            while j < n and s[j] != '\n':
                j += 1
            for k in range(i, j):
                out[k] = ' '
            i = j
            continue
        if s[i] == '/' and i + 1 < n and s[i + 1] == '*':
            j = s.find('*/', i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, min(j, n)):
                if out[k] != '\n':
                    out[k] = ' '
            i = j
            continue
        if s[i] == '"' or s[i] == "'":
            q = s[i]
            j = i + 1
            while j < n:
                if s[j] == '\\':
                    j += 2
                    continue
                if s[j] == q:
                    j += 1
                    break
                if s[j] == '\n':
                    break
                j += 1
            i = j
            continue
        i += 1
    return ''.join(out)


def extract_table(src, name):
    """抠出 static const char *name[] = { "a", "b", NULL }; 里的所有字符串项。

    抠不到返回 None（表示这张表不存在），空表返回 []。
    """
    m = re.search(re.escape(name) + r'\s*\[\s*\]\s*=\s*\{(.*?)\}\s*;', src, re.S)
    if not m:
        return None
    body = m.group(1)
    return re.findall(r'"([^"]+)"', body)


def extract_func(src, name):
    """抠 static 函数定义（跳过前置声明），按大括号配平。"""
    pos = 0
    while True:
        idx = src.find(name + '(', pos)
        if idx < 0:
            return None
        p = src.find('(', idx)
        depth = 0
        i = p
        while i < len(src):
            if src[i] == '(':
                depth += 1
            elif src[i] == ')':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if i >= len(src):
            return None
        j = i + 1
        while j < len(src) and src[j] in ' \t\r\n':
            j += 1
        if j < len(src) and src[j] == ';':
            pos = j
            continue
        brace = src.find('{', i)
        if brace < 0:
            return None
        depth = 0
        i = brace
        while i < len(src):
            c = src[i]
            if c in '"\'':
                q = c
                i += 1
                while i < len(src):
                    if src[i] == '\\':
                        i += 2
                        continue
                    if src[i] == q:
                        break
                    i += 1
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return src[idx:i + 1]
            i += 1
        return None


def main():
    if len(sys.argv) < 2:
        print('用法: check_v29.py <file.m>')
        return 2
    raw = open(sys.argv[1], encoding='utf-8').read()
    src = strip_comments(raw)

    # ── L1 名字表必须两种拼写都在
    #
    # 这是整轮的核心。少 n 的 hideWritteImage 才是 Manager 上的真名；
    # 完整拼写的 hideWrittenImage 是 Document/CSOcrPage 上的名字。
    # 两个都要，因为单例的 getter 在不同版本可能被补齐拼写。
    tw = extract_table(src, 'kCSFSMgrHideWritten')
    ts = extract_table(src, 'kCSFSMgrHideStamp')
    th = extract_table(src, 'kCSFSMgrHasWritten')

    if tw is None:
        fail('L1 找不到 kCSFSMgrHideWritten 名字表 —— Manager 的开关名没有收口')
    elif 'hideWritteImage' not in tw:
        fail('L1 kCSFSMgrHideWritten 里缺 hideWritteImage（少一个 n 的那个）—— '
             '这正是 CSImageToJsonManager 上的真名，丢了就退回 v24～v28 的失败态：'
             '读完整拼写恒为 nil，optKnown 永远 0')
    elif 'hideWrittenImage' not in tw:
        fail('L1 kCSFSMgrHideWritten 里缺完整拼写 hideWrittenImage —— '
             '少了它，一旦某个版本把 getter 补成完整拼写就读不到')
    else:
        ok('L1 hideWritten 名字表两种拼写都在（少 n 的真名 + 完整拼写的兼容名）')

    if ts is None:
        fail('L1 找不到 kCSFSMgrHideStamp 名字表')
    elif 'hideStampImage' not in ts:
        fail('L1 kCSFSMgrHideStamp 里缺 hideStampImage')
    else:
        ok('L1 hideStamp 名字表就位')

    if th is None:
        fail('L1 找不到 kCSFSMgrHasWritten 名字表 —— has 标志与 hide 标志意义不同，'
             '要单独一张表，不能复用')
    elif 'hasWritteImage' not in th:
        fail('L1 kCSFSMgrHasWritten 里缺 hasWritteImage（同样少 n）')
    else:
        ok('L1 hasWritteImage 名字表就位（与 hide 分开，语义不同）')

    # ── L3 setter 必须由 getter 名派生，不许硬写
    #
    # 硬写 setHideWritteImage: 的后果：一旦要兼容完整拼写，
    # 就得多写一份硬编码字符串，两处拼写必然漂移。
    # 派生写法让「加一个兼容名」只改表、不改逻辑。
    wr = extract_func(src, 'CSFSWriteBoolTo')
    if wr is None:
        fail('L3 找不到 CSFSWriteBoolTo —— 没有回写能力，'
             '就只能自己解析 JSON 猜哪些是手写，回到前五轮的老路')
    else:
        w = strip_comments(wr)
        if 'stringWithFormat:@"set%@%@:"' not in w:
            fail('L3 CSFSWriteBoolTo 没有按 getter 名派生 setter 名 —— '
                 '硬编码 setter 字符串会让两个拼写各自漂移')
        elif 'uppercaseString' not in w:
            fail('L3 CSFSWriteBoolTo 派生 setter 时没做首字母大写 —— '
                 'setHideWritteImage: 需要大写的 H')
        else:
            ok('L3 setter 名由 getter 名派生（首字母大写），拼写只在一处收口')

    # ── L2 / L4 Manager 单例必须存在，且在来源顺序里排第一
    rd = extract_func(src, 'CSFSReadOptionsFromBottomView')
    if rd is None:
        fail('L2 找不到 CSFSReadOptionsFromBottomView，判据失效')
    else:
        body = strip_comments(rd)
        i_mgr = body.find('CSFSImageToJsonManager()')
        i_model = body.find('currentAIEditModel')
        if i_mgr < 0:
            fail('L2 读选项时没有获取 CSImageToJsonManager 单例 —— '
                 '前五轮失败的直接原因就是没看这个对象')
        elif i_model >= 0 and i_mgr > i_model:
            fail('L2 Manager 来源排在 currentAIEditModel 之后 —— '
                 '顺序掉了就等于又先去读那个只在点过 AI 美化后才非 nil 的对象')
        else:
            ok('L2 Manager 单例是读选项的第一来源（排在 model.ocrPage 之前）')

        # L4 三张表都要被真正用上
        for tbl, kw in (('kCSFSMgrHideWritten', '去除手写'),
                        ('kCSFSMgrHideStamp', '去除印章'),
                        ('kCSFSMgrHasWritten', '有手写图')):
            if tbl not in body:
                fail('L4 名字表 %s（%s）在 CSFSReadOptionsFromBottomView 里没被使用 —— '
                     '定义了不调用就是死代码' % (tbl, kw))
        if all(t in body for t in ('kCSFSMgrHideWritten',
                                   'kCSFSMgrHideStamp',
                                   'kCSFSMgrHasWritten')):
            ok('L4 三张名字表都在读选项时真正被使用')

        # L2 补充：合并必须是 OR，不许 Manager 的值被后来的来源覆盖掉
        #
        # Manager 是「当前生效值」，后面几个来源是「可能同步落后的副本」。
        # 若写成 gCSFSHideWritten = (从 model 读到的值)，向后兼容就成了倒退。
        #
        # 这里只认一种合法写法：`gCSFSHideWritten = YES;`
        # 第一版写了个排除名单（(?!...|mw|ms|w|s|fw|fs...)），结果注入
        # `gCSFSHideWritten = mw;` 时 mw 正好在排除名单里 → 判据放过它，
        # 反向验证当场报「期望命中却没报」。教训：**白名单写成黑名单就会漏**。
        # 合并语义下不存在「赋成某个来源的值」的合法场景，所以只放行 YES。
        bad = re.findall(r'gCSFS(?:HideWritten|HideStamp)\s*=\s*(?!YES\s*;)'
                         r'[\w(\["\']', body)
        if bad:
            fail('L2 gCSFSHideWritten / gCSFSHideStamp 被直接赋成了某个来源的值 —— '
                 'Manager 读到的 YES 会被同步落后的副本覆盖，'
                 '退回「勾了跟没勾一样」')
        else:
            ok('L2 hide* 合并仍是 OR 语义，Manager 的 YES 不会被覆盖')

    print('=== check_v29 ===')
    for m in oks:
        print('  [ OK ] ' + m)
    for m in fails:
        print('  [FAIL] ' + m)
    print('\nOK %d / FAIL %d' % (len(oks), len(fails)))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())