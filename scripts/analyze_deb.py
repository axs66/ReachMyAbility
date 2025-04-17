import os
import subprocess
import re

TARGET_BINARY = "work/Applications/WeChat.app/WeChat"  # 替换为实际路径

def run_cmd(cmd, outfile):
    with open(outfile, 'w') as f:
        subprocess.run(cmd, shell=True, stdout=f, stderr=subprocess.DEVNULL)

def main():
    os.makedirs("output/raw", exist_ok=True)

    # 1. nm 导出符号
    run_cmd(f"nm -nm {TARGET_BINARY}", "output/raw/nm_output.txt")

    # 2. otool 分析结构
    run_cmd(f"otool -l {TARGET_BINARY}", "output/raw/file_info.txt")

    # 3. class-dump 导出 ObjC 方法名（需 class-dump 安装）
    run_cmd(f"class-dump {TARGET_BINARY}", "output/raw/objc_symbols.txt")

    # 4. Swift 符号 demangle（可选）
    run_cmd(f"swift-demangle < output/raw/objc_symbols.txt", "output/raw/objc_symbols_demangled.txt")

    print("✅ 分析完成，结果保存在 output/raw/")

if __name__ == '__main__':
    main()
