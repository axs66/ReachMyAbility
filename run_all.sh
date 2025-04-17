#!/bin/bash

set -e

DEB_FILE=$1

if [ -z "$DEB_FILE" ]; then
  echo "❗ 使用方法: ./run_all.sh path/to/your.deb"
  exit 1
fi

echo "🎯 解包 .deb..."
bash scripts/extract_deb.sh "$DEB_FILE"

echo "🔍 分析 WeChat 二进制..."
python3 scripts/analyze_deb.py

echo "⚙️ 生成代码..."
python3 scripts/generate_hooks.py output/raw/objc_symbols.txt output/src/Tweak.xm
python3 scripts/generate_makefile.py output/raw/objc_symbols.txt Makefile
python3 scripts/generate_headers.py output/raw/objc_symbols.txt output/src/WechatPushMsgPage.h

echo "✅ 全部完成！请检查 output/src 和 Makefile"
