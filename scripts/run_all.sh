#!/bin/bash
set -e

RAW_DIR="output/raw"
SRC_DIR="output/src"

mkdir -p "$SRC_DIR"

# 1. 生成 Tweak.xm
python3 scripts/generate_hooks_from_lief.py \
    "$RAW_DIR/lief_export.txt" \
    "$SRC_DIR/Tweak.xm"

# 2. 生成头文件（带参数）
python3 scripts/generate_headers.py \
    --dylib "$RAW_DIR/WechatPushMsgPage.dylib" \
    --symbols "$RAW_DIR/objc_symbols.txt" \
    --output "$SRC_DIR/WechatPushMsgPage.h"

# 3. 生成 Makefile
python3 scripts/generate_makefile.py \
    "$RAW_DIR/objc_symbols.txt" \
    "$SRC_DIR/Makefile"
