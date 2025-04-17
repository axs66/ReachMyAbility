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

# 1. 如果传入的是 URL，则先下载到本地
if [[ "$RAW_ARG" =~ ^https?:// ]]; then
  mkdir -p "$WORK_DIR"
  echo "🌐 检测到 URL，下载: $RAW_ARG"
  wget -q -O "$RAW_DEB" "$RAW_ARG" \
    || { echo "❌ 下载失败，请检查 URL"; exit 1; }
  DEB_FILE="$RAW_DEB"
else
  DEB_FILE="$RAW_ARG"
fi

# 2. 创建目录
mkdir -p "$WORK_DIR/data" "$WORK_DIR/control" "$RAW_DIR" "$SRC_DIR"

# 3. 解包 .deb
echo "🎯 开始解包 .deb..."
bash scripts/extract_deb.sh "$DEB_FILE" "$WORK_DIR"

# 4. 分析 dylib（拷贝、file、nm、LIEF、objc 符号）
echo "🔍 分析 dylib..."
python3 scripts/analyze_dylib.py "$WORK_DIR/data" "$RAW_DIR"

# 5. 提取 Objective‑C 类名和方法名
#    - __objc_classname 包含所有类名
#    - __objc_methname 包含所有方法选择器
DYLIB_PATH=$(find "$WORK_DIR/data" -name "*.dylib" -print -quit)
echo "📑 提取 ObjC 类名／方法..."
otool -v -s __TEXT __objc_classname "$DYLIB_PATH" > "$RAW_DIR/classlist.txt"
otool -v -s __TEXT __objc_methname  "$DYLIB_PATH" > "$RAW_DIR/methname.txt"

# 6. Swift 符号 demangle（可选）
echo "🛠 Swift 符号 demangle..."
python3 scripts/demangle_swift.py \
  "$RAW_DIR/objc_symbols.txt" \
  "$RAW_DIR/objc_symbols_demangled.txt"

# 7. 生成头文件（classes + methods）
echo "⚙️ 生成头文件..."
python3 scripts/generate_headers.py \
  --symbols "$RAW_DIR/objc_symbols.txt" \
  --output "$SRC_DIR/Plugin.h"

# 8. 生成精准 Hooks（根据 classlist.txt + methname.txt）
echo "🔌 生成 Tweak.xm..."
python3 scripts/generate_hooks.py \
  --classlist "$RAW_DIR/classlist.txt" \
  --methods   "$RAW_DIR/methname.txt" \
  --headers   "" \
  --output    "$SRC_DIR/Tweak.xm"

# 9. 生成 Makefile
echo "📦 生成 Makefile..."
python3 scripts/generate_makefile.py \
  --name Plugin \
  --output "$SRC_DIR"

echo "✅ 全部完成！请查看 output/raw 与 output/src"
