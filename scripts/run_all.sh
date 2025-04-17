#!/bin/bash
set -e

DEB_PATH="$1"
WORK_DIR="work"
RAW_DIR="output/raw"
SRC_DIR="output/src"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🎯 开始解包 .deb..."
rm -rf "$WORK_DIR" && mkdir -p "$WORK_DIR"
dpkg-deb -x "$DEB_PATH" "$WORK_DIR"
echo "✅ .deb 提取完成：$WORK_DIR"

echo "🔍 分析 dylib..."
mkdir -p "$RAW_DIR"
python3 scripts/lief_analysis.py "$WORK_DIR" > "$RAW_DIR/lief_output.txt"
echo "✅ Dylib 深度分析完成，结果在: $RAW_DIR"

# 自动查找 Dylib 并使用 Frida 分析
TARGET_DYLIB=$(find "$WORK_DIR" -name "*.dylib" | head -n 1)
if [ -n "$TARGET_DYLIB" ]; then
  echo "🎯 自动识别到目标 Dylib: $TARGET_DYLIB"
  echo "🚀 启动 Frida 分析（自动 attach）..."
  timeout 10s frida -n SpringBoard -l "$SCRIPT_DIR/frida_script.js" --runtime=v8 || echo "⚠️ Frida 分析失败或超时"
else
  echo "⚠️ 未找到目标 Dylib，跳过 Frida 分析"
fi

# 生成 Hook 源码
echo "⚙️ 正在生成 Hook 源码..."
mkdir -p "$SRC_DIR"
python3 scripts/generate_hooks_from_lief.py "$RAW_DIR/lief_output.txt" "$SRC_DIR/Tweak.xm"
python3 scripts/generate_makefile.py "$SRC_DIR/Makefile"
cp scripts/Plugin.h "$SRC_DIR/Plugin.h"
echo "✅ Hook 源码已生成: $SRC_DIR"
