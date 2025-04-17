#!/bin/bash
set -e

RAW_DIR="output/raw"
SRC_DIR="output/src"

# 路径统一
OBJC_SYMBOLS="$RAW_DIR/objc_symbols.txt"
LIEF_EXPORT="$RAW_DIR/lief_export.txt"
HEADER_FILE="$SRC_DIR/WechatPushMsgPage.h"
TWEAK_FILE="$SRC_DIR/Tweak.xm"
MAKEFILE_FILE="$SRC_DIR/Makefile"

# 1. 生成头文件
python3 scripts/generate_headers.py "$OBJC_SYMBOLS" "$HEADER_FILE"

# 2. 生成 Makefile
python3 scripts/generate_makefile.py "$OBJC_SYMBOLS" "$MAKEFILE_FILE"

# 3. 从 lief_export 生成 Tweak.xm
python3 scripts/generate_hooks_from_lief.py "$LIEF_EXPORT" "$TWEAK_FILE"
