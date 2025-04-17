import sys
import os

output_path = sys.argv[1]

makefile_template = """
THEOS_DEVICE_PLATFORM = iphone:latest:12.0
INSTALL_TARGET_PROCESSES = SpringBoard
ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:12.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MyTweak
MyTweak_FILES = Tweak.xm
MyTweak_FRAMEWORKS = UIKit Foundation
MyTweak_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
"""

# 写入 Makefile
os.makedirs(os.path.dirname(output_path), exist_ok=True)
with open(output_path, "w") as f:
    f.write(makefile_template.strip())

print(f"✅ Makefile 已生成: {output_path}")
