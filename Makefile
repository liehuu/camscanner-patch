# 本地（macOS）快捷构建。CI 走 .github/workflows/build.yml，两者逻辑一致。
#
# 用法：
#   make check          语法预检 + 崩宿主专项检查（不需要编译器，Windows 也能跑）
#   make dylib          只编译 dylib（最快，先确认能编过）
#   make lint           只跑崩宿主专项检查（需要产物）
#   make inject IPA=xxx 从 ipa 生成注入后的 ipa
#   make clean

DYLIB_NAME      := CamScannerSaveToFiles
INSTALL_NAME    := /usr/lib/CamScannerSaveToFiles.dylib
APP_BUNDLE_NAME := CamScanner_Lite.app
APP_EXECUTABLE  := CamScanner_Lite
SDK             := $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
MIN_IOS         := 13.0

# 允许覆盖 python 解释器（本机 Windows 用便携版 python.exe）
PYTHON          ?= python3

CC       := xcrun --sdk iphoneos clang
CFLAGS   := -isysroot $(SDK) -miphoneos-version-min=$(MIN_IOS) -fobjc-arc -fmodules \
            -Os -Wall -Wextra -Wno-unused-parameter -Wno-deprecated-declarations
LDFLAGS  := -dynamiclib -install_name $(INSTALL_NAME) \
            -compatibility_version 1.0.0 -current_version 1.0.0 \
            -framework Foundation -framework UIKit

BUILD    := build
SRC      := src/$(DYLIB_NAME).m
OUT_FAT  := $(BUILD)/$(DYLIB_NAME).dylib

.PHONY: all dylib lint presyntax inject clean check

all: presyntax dylib lint

$(BUILD):
	@mkdir -p $(BUILD)

# 纯文本语法闸门，不需要 clang / Xcode，Windows 也能跑
presyntax:
	@echo "=== 语法预检 ==="
	$(PYTHON) tools/presyntax.py $(SRC)

# 连崩宿主检查一起跑。注意 lint 的产物层检查需要 build 出来的 dylib，
# 没有 macOS 时它会自动跳过（只做源码层检查）。
check:
	$(PYTHON) tools/presyntax.py $(SRC)
	@SRC_FILE=$(SRC) $(PYTHON) tools/lint_dylib.py

dylib: presyntax $(BUILD)
	@echo "=== 编译 arm64 ==="
	$(CC) -arch arm64 $(CFLAGS) $(LDFLAGS) -o $(BUILD)/$(DYLIB_NAME).arm64.dylib $(SRC)
	@echo "=== 编译 arm64e ==="
	$(CC) -arch arm64e $(CFLAGS) $(LDFLAGS) -o $(BUILD)/$(DYLIB_NAME).arm64e.dylib $(SRC)
	@echo "=== 合并 fat ==="
	xcrun lipo -create $(BUILD)/$(DYLIB_NAME).arm64.dylib \
	                      $(BUILD)/$(DYLIB_NAME).arm64e.dylib \
	                      -output $(OUT_FAT)
	xcrun lipo -info $(OUT_FAT)

lint:
	@SRC_FILE=$(SRC) $(PYTHON) tools/lint_dylib.py $(OUT_FAT)

# 需要 IPA=path/to/input.ipa
inject: dylib lint
	@if [ -z "$(IPA)" ]; then echo "用法: make inject IPA=path/to/original.ipa"; exit 1; fi
	@echo "=== 解包 ==="
	rm -rf work && mkdir -p work out
	unzip -q "$(IPA)" -d work
	@test -d work/Payload/$(APP_BUNDLE_NAME) || { echo "Payload 下无 $(APP_BUNDLE_NAME)"; exit 1; }
	@echo "=== 注入 ==="
	$(PYTHON) tools/inject_dylib.py work/Payload/$(APP_BUNDLE_NAME)/$(APP_EXECUTABLE) "$(INSTALL_NAME)"
	@echo "=== 嵌入 dylib ==="
	mkdir -p work/Payload/$(APP_BUNDLE_NAME)/Frameworks
	cp $(OUT_FAT) work/Payload/$(APP_BUNDLE_NAME)/Frameworks/$(DYLIB_NAME).dylib
	xcrun install_name_tool -id "@executable_path/Frameworks/$(DYLIB_NAME).dylib" \
	  work/Payload/$(APP_BUNDLE_NAME)/Frameworks/$(DYLIB_NAME).dylib
	xcrun install_name_tool -change "$(INSTALL_NAME)" \
	  "@executable_path/Frameworks/$(DYLIB_NAME).dylib" \
	  work/Payload/$(APP_BUNDLE_NAME)/$(APP_EXECUTABLE)
	@echo "=== 签名 ==="
	codesign -f -s - --timestamp=none work/Payload/$(APP_BUNDLE_NAME)/Frameworks/$(DYLIB_NAME).dylib
	codesign -f -s - --timestamp=none --entitlements tools/entitlements.plist \
	  work/Payload/$(APP_BUNDLE_NAME)/$(APP_EXECUTABLE)
	rm -rf work/Payload/$(APP_BUNDLE_NAME)/_CodeSignature
	codesign -f -s - --timestamp=none --entitlements tools/entitlements.plist \
	  --deep work/Payload/$(APP_BUNDLE_NAME)
	@echo "=== 重打包 ==="
	( cd work && zip -qry "../out/$(DYLIB_NAME).ipa" Payload )
	@ls -la out/$(DYLIB_NAME).ipa

check:
	@SRC_FILE=$(SRC) $(PYTHON) tools/lint_dylib.py

clean:
	rm -rf $(BUILD) work out