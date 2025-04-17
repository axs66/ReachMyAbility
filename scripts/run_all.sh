#!/usr/bin/env bash
set -e

RAW_ARG=$1
WORK_DIR="work"
RAW_DEB="$WORK_DIR/tmp.deb"
RAW_DIR="output/raw"
SRC_DIR="output/src"

if [[ -z "$RAW_ARG" ]]; then
  echo "Usage: run_all.sh <path_or_url_to_deb>"
  exit 1
fi

# 如果第一个参数是 URL，则先下载到本地
if [[ "$RAW_ARG" =~ ^https?:// ]]; then
  mkdir -p "$WORK_DIR"
  echo "🌐 检测到 URL，开始下载: $RAW_ARG"
  wget -q -O "$RAW_DEB" "$RAW_ARG" \
    || { echo "❌ 下载失败，请检查 URL 或网络"; exit 1; }
  DEB_FILE="$RAW_DEB"
else
  DEB_FILE="$RAW_ARG"
fi

# 创建输出目录
mkdir -p "$WORK_DIR/data" "$WORK_DIR/control" "$RAW_DIR" "$SRC_DIR"

echo "🎯 开始解包 .deb..."
bash scripts/extract_deb.sh "$DEB_FILE" "$WORK_DIR"

echo "🔍 分析 dylib..."
python3 scripts/analyze_dylib.py "$WORK_DIR/data" "$RAW_DIR"

echo "🛠 Swift 符号 demangle..."
python3 scripts/demangle_swift.py "$RAW_DIR/objc_symbols.txt" "$RAW_DIR/objc_symbols_demangled.txt"

echo "⚙️ 生成头文件..."
python3 scripts/generate_headers.py \
  --symbols "$RAW_DIR/objc_symbols.txt" \
  --output "$SRC_DIR/Plugin.h"

echo "🔌 生成 Tweak.xm..."
python3 scripts/generate_hooks.py \
  --lief "$RAW_DIR/lief_export.txt" \
  --objc "$RAW_DIR/objc_symbols.txt" \
  --output "$SRC_DIR/Tweak.xm"

echo "📦 生成 Makefile..."
python3 scripts/generate_makefile.py \
  --name Plugin \
  --output "$SRC_DIR"

echo "✅ 全部完成！请查看 output/raw 与 output/src"
