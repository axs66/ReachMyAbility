#!/usr/bin/env python3
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--symbols", required=True, help="Path to objc_symbols.txt")
parser.add_argument("--output", required=True, help="Path to output header file")
parser.add_argument("--dylib", required=True, help="Path to dylib")  # 保留这个以防你后面要加功能
args = parser.parse_args()

def parse_symbols(path):
    classes = set()
    methods = set()
    with open(path, 'r') as f:
        for line in f:
            if 'OBJC_CLASS_' in line:
                class_name = line.strip().split('_OBJC_CLASS_$_')[-1]
                classes.add(class_name)
            elif 'OBJC_METH_VAR_NAME' in line or 'OBJC_SELECTOR_REFERENCES_' in line:
                method_name = line.strip().split('_')[-1]
                methods.add(method_name)
    return sorted(classes), sorted(methods)

def generate_header(classes, methods, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        f.write("#import <Foundation/Foundation.h>\n\n")
        for cls in classes:
            f.write(f"@interface {cls} : NSObject\n")
            f.write("@end\n\n")
        f.write("// Possible Selectors:\n")
        for method in methods:
            f.write(f"// - {method}\n")

classes, methods = parse_symbols(args.symbols)
generate_header(classes, methods, args.output)
