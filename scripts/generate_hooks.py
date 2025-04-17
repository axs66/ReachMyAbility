#!/usr/bin/env python3
import os
import re
import argparse

parser = argparse.ArgumentParser(description="根据 LIEF & objc 符号生成 Tweak.xm")
parser.add_argument('--lief', required=True, help="Path to lief_export.txt")
parser.add_argument('--objc', required=True, help="Path to objc_symbols.txt")
parser.add_argument('--output', required=True, help="Output Tweak.xm path")
args = parser.parse_args()

symbols = set()

# 从 LIEF 导出中提取函数名
with open(args.lief, 'r') as f:
    for line in f:
        m = re.match(r'\s+(\S+)', line)
        if m:
            symbols.add(m.group(1))

# 从 objc 符号中提取类名和方法
with open(args.objc, 'r') as f:
    for line in f:
        text = line.strip()
        if '_OBJC_CLASS_$_' in text:
            symbols.add(text.split('_OBJC_CLASS_$_')[-1])
        elif text.startswith('-['):
            symbols.add(text)

os.makedirs(os.path.dirname(args.output), exist_ok=True)

with open(args.output, 'w') as f:
    f.write("// Auto-generated Tweak.xm\n\n")
    for sym in sorted(symbols):
        f.write(f"%hook {sym}\n")
        f.write("    %orig;\n")
        f.write(f"    NSLog(@\"[Tweak] Hooked {sym}\");\n")
        f.write("%end\n\n")

print("✅ Tweak.xm 生成:", args.output)
