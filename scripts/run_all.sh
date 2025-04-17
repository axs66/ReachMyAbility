#!/bin/bash

DEB_FILE=$1
WORK_DIR="work"

# 1. 解包 .deb 文件
echo "🎯 开始解包 .deb..."
dpkg-deb -x "$DEB_FILE" "$WORK_DIR"
dpkg-deb -e "$DEB_FILE" "$WORK_DIR/DEBIAN"
echo "✅ .deb 提取完成：$WORK_DIR"

# 2. 提取 dylib 文件路径
echo "🔍 提取 dylib 文件路径..."
find "$WORK_DIR" -type f -name "*.dylib" > dylibs.txt
echo "✅ dylib 文件路径提取完成"

# 3. 使用 frida 动态分析 dylib
echo "📑 使用 frida 动态分析 dylib 文件..."
while IFS= read -r dylib; do
    echo "🔍 分析 dylib: $dylib"
    # 假设你有一个 `frida_script.js` 脚本，执行动态分析
    frida -U -f /path/to/target_app -l frida_script.js --no-pause
done < dylibs.txt

echo "✅ Dylib 动态分析完成"
