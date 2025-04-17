#!/usr/bin/env python3
import os
import argparse

parser = argparse.ArgumentParser(description="生成 Makefile")
parser.add_argument('--name', required=True, help="Tweak 名称，如 Plugin")
parser.add_argument('--output', required=True, help="输出目录 (e.g. output/src)")
args = parser.parse_args()

content = f"""ARCHS = arm64
TARGET = iphone:latest:13.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = {args.name}

{args.name}_FILES = Tweak.xm
{args.name}_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
"""

os.makedirs(args.output, exist_ok=True)
makefile_path = os.path.join(args.output, "Makefile")
with open(makefile_path, 'w') as f:
    f.write(content)

print("✅ Makefile 已生成:", makefile_path)
