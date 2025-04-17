#!/usr/bin/env python3
import os
import argparse

parser = argparse.ArgumentParser(description="根据 objc_symbols.txt 生成头文件")
parser.add_argument('--symbols', required=True, help="Path to objc_symbols.txt")
parser.add_argument('--output', required=True, help="Path to output header file (e.g. output/src/Plugin.h)")
args = parser.parse_args()

def parse_symbols(path):
    classes = set()
    methods = set()
    with open(path, 'r') as f:
        for line in f:
            if '_OBJC_CLASS_$_' in line:
                cls = line.strip().split('_OBJC_CLASS_$_')[-1]
                classes.add(cls)
            elif line.startswith('-['):
                methods.add(line.strip())
    return sorted(classes), sorted(methods)

classes, methods = parse_symbols(args.symbols)
os.makedirs(os.path.dirname(args.output), exist_ok=True)

with open(args.output, 'w') as f:
    f.write("// Auto-generated header\n#import <Foundation/Foundation.h>\n\n")
    for cls in classes:
        f.write(f"@interface {cls} : NSObject\n@end\n\n")
    if methods:
        f.write("// Possible selectors:\n")
        for m in methods:
            f.write(f"// {m}\n")

print("✅ Header 文件生成:", args.output)
