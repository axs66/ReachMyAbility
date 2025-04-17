#!/bin/bash

# 获取 deb 文件路径（来自 GitHub Actions 传递的参数）
DEB_FILE=$1

# 解包 .deb 文件
echo "🎯 开始解包 .deb..."
dpkg-deb -x "$DEB_FILE" work

# 分析 dylib 文件
echo "🔍 分析 dylib..."
# 假设 dylib 文件位于解包目录中的某个位置
DYLIB_PATH="work/usr/lib/your_target.dylib"

# 使用 Frida 进行动态分析
echo "📑 使用 Frida 执行脚本..."
frida -U -f "$DYLIB_PATH" -l scripts/frida_script.js --no-pause

# 将分析结果保存到 output/raw 目录
echo "✅ Dylib 深度分析完成，结果在: output/raw"

# 提取 ObjC 类名／方法等其他操作
echo "📑 提取 ObjC 类名／方法..."
python3 scripts/lief_analysis.py "$DYLIB_PATH"

# 将分析结果保存到 output/src 目录
echo "✅ 分析结果已保存至 output/src"
