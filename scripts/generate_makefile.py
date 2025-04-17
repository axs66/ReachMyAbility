#!/usr/bin/env python3
import argparse

THEOS_TEMPLATE = """ARCHS = arm64
TARGET = iphone:latest:13.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = {name}

{name}_FILES = Tweak.xm
{name}_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
"""

def generate_makefile(name, output_path):
    with open(f"{output_path}/Makefile", 'w') as f:
        f.write(THEOS_TEMPLATE.format(name=name))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    
    generate_makefile(args.name, args.output)
