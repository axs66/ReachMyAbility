import os
import sys
import re

def parse_lief_output(file_path):
    with open(file_path, "r") as f:
        content = f.read()

    classnames = re.findall(r"(?<=🔍 ObjC Class Names:\n)([\s\S]*?)\n🔍 Exported Symbols:", content)
    symbols = re.findall(r"(?<=🔍 Exported Symbols:\n)([\s\S]*)", content)

    class_list = classnames[0].strip().splitlines() if classnames else []
    symbol_list = symbols[0].strip().splitlines() if symbols else []

    return class_list, symbol_list

def generate_tweak_xm(classes, symbols):
    lines = []
    lines.append("// 自动生成 Hook 模板")
    lines.append("#import <substrate.h>")
    lines.append("")

    for class_name in classes:
        lines.append(f"// Hook {class_name}")
        lines.append(f"%hook {class_name}")
        lines.append("")

        # 示例方法 hook 模板
        lines.append("/* 示例方法（请根据真实方法签名替换）")
        lines.append("- (void)someMethod {")
        lines.append("    %log;")
        lines.append("    %orig;")
        lines.append("}")
        lines.append("*/")

        lines.append(f"%end\n")

    if not classes:
        lines.append("// ⚠️ 未发现 ObjC 类名，可能不是标准 Tweak 插件")

    return "\n".join(lines)

def generate_plugin_h():
    return "// 自动生成 Plugin.h\n#pragma once\n"

def generate_makefile():
    return """ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:latest
include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AutoTweak
AutoTweak_FILES = Tweak.xm
include $(THEOS_MAKE_PATH)/tweak.mk
"""

def main():
    raw_dir = "output/raw"
    src_dir = "output/src"
    os.makedirs(src_dir, exist_ok=True)

    txt_files = [f for f in os.listdir(raw_dir) if f.endswith(".txt")]
    if not txt_files:
        print("❌ 未找到分析结果 txt 文件")
        sys.exit(1)

    latest_file = max([os.path.join(raw_dir, f) for f in txt_files], key=os.path.getmtime)
    print(f"✅ 使用最新分析文件: {latest_file}")

    classes, symbols = parse_lief_output(latest_file)

    tweak_code = generate_tweak_xm(classes, symbols)
    with open(os.path.join(src_dir, "Tweak.xm"), "w") as f:
        f.write(tweak_code)

    with open(os.path.join(src_dir, "Plugin.h"), "w") as f:
        f.write(generate_plugin_h())

    makefile_path = "Makefile"
    if not os.path.exists(makefile_path):
        with open(makefile_path, "w") as f:
            f.write(generate_makefile())

    print("✅ 源码生成完毕：output/src/")

if __name__ == "__main__":
    main()
