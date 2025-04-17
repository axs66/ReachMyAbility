#!/usr/bin/env bash
set -e

DEB_FILE=$1
if [ -z "$DEB_FILE" ]; then
  echo "Usage: run_all.sh <path_to_deb>"
  exit 1
fi

WORK_DIR="work"
RAW_DIR="output/raw"
SRC_DIR="output/src"

mkdir -p "$WORK_DIR" "$RAW_DIR" "$SRC_DIR"

echo "🎯 开始解包..."
bash scripts/extract_deb.sh "$DEB_FILE" "$WORK_DIR"

echo "🔍 分析 dylib..."
python3 scripts/analyze_dylib.py "$WORK_DIR/data" "$RAW_DIR"

echo "🛠 Swift 符号 demangle..."
python3 scripts/demangle_swift.py "$RAW_DIR/objc_symbols.txt" "$RAW_DIR/objc_symbols_demangled.txt"

echo "⚙️ 生成头文件..."
python3 scripts/generate_headers.py --symbols "$RAW_DIR/objc_symbols.txt" --output "$SRC_DIR/Plugin.h"

echo "🔌 生成 Tweak.xm..."
python3 scripts/generate_hooks.py --lief "$RAW_DIR/lief_export.txt" \
                                  --objc "$RAW_DIR/objc_symbols.txt" \
                                  --output "$SRC_DIR/Tweak.xm"

echo "📦 生成 Makefile..."
python3 scripts/generate_makefile.py --name Plugin --output "$SRC_DIR"

echo "✅ 全部完成！请查看 output/raw 与 output/src"
