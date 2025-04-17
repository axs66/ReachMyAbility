#!/usr/bin/env python3
import sys
import os
import subprocess
import lief

def main():
    if len(sys.argv) != 3:
        print("Usage: analyze_dylib.py <data_dir> <raw_output_dir>", file=sys.stderr)
        sys.exit(1)

    data_dir = sys.argv[1]
    raw_dir = sys.argv[2]

    # 查找第一个 .dylib
    dylib_path = None
    for root, dirs, files in os.walk(data_dir):
        for f in files:
            if f.endswith(".dylib"):
                dylib_path = os.path.join(root, f)
                break
        if dylib_path:
            break

    if not dylib_path:
        print("❌ 未找到任何 .dylib 文件！", file=sys.stderr)
        sys.exit(1)

    os.makedirs(raw_dir, exist_ok=True)
    plugin_name = os.path.basename(dylib_path)

    # 拷贝原始 dylib
    subprocess.run(["cp", dylib_path, os.path.join(raw_dir, plugin_name)], check=True)

    # 文件类型信息
    with open(os.path.join(raw_dir, "file_info.txt"), "w") as f:
        subprocess.run(["file", dylib_path], stdout=f, check=True)

    # 符号导出（demangle）
    with open(os.path.join(raw_dir, "nm_output.txt"), "w") as f:
        subprocess.run(["llvm-nm", "--demangle", dylib_path],
                       stdout=f, stderr=subprocess.DEVNULL, check=False)

    # LIEF 分析
    binary = lief.parse(dylib_path)
    with open(os.path.join(raw_dir, "lief_export.txt"), "w") as f:
        f.write(f"Architecture: {binary.header.cpu_type.name}\n\n")
        f.write("Linked Libraries:\n")
        for cmd in binary.commands:
            if isinstance(cmd, lief.MachO.DylibCommand):
                f.write(f"  {cmd.name}\n")
        f.write("\nExported Functions:\n")
        for sym in binary.exported_functions:
            f.write(f"  {sym}\n")

    # ObjC/Swift 符号提取
    with open(os.path.join(raw_dir, "objc_symbols.txt"), "w") as f:
        subprocess.run(
            f"strings {dylib_path} | grep -E 'OBJC_CLASS_|_TTS|_OBJC_'",
            shell=True, stdout=f, check=False
        )

    print("✅ Dylib 深度分析完成，结果在:", raw_dir)

if __name__ == "__main__":
    main()
