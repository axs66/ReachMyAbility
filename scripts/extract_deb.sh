#!/usr/bin/env bash
set -e

DEB_FILE=$1
WORK_DIR=${2:-work}

if [ -z "$DEB_FILE" ]; then
  echo "Usage: extract_deb.sh <deb_file> [work_dir]"
  exit 1
fi

mkdir -p "$WORK_DIR/data" "$WORK_DIR/control"

# 解包 data 部分
dpkg-deb -x "$DEB_FILE" "$WORK_DIR/data"

# 解包 control 部分
dpkg-deb -e "$DEB_FILE" "$WORK_DIR/control"

echo "✅ .deb 提取完成：$WORK_DIR"
