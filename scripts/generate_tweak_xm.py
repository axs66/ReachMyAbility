#!/usr/bin/env python3
import argparse
import re

def generate_tweak(strings_file, output_path):
    with open(strings_file, 'r') as f:
        strings = f.read()
    
    # 启发式检测常见方法
    hook_targets = []
    if 'viewDidLoad' in strings:
        hook_targets.append(('UIViewController', 'viewDidLoad'))
    if 'applicationDidFinishLaunching' in strings:
        hook_targets.append(('UIApplication', 'applicationDidFinishLaunching:'))
    
    with open(f"{output_path}/Tweak.xm", 'w') as f:
        f.write("// Auto-generated Tweak.xm\n\n")
        f.write("%hook ClassName // Replace with actual class\n")
        for cls, method in hook_targets:
            f.write(f"%hook {cls}\n")
            f.write(f"- (void){method} {{\n")
            f.write(f"    %orig;\n    NSLog(@\"Hooked {method}\");\n}}\n")
            f.write("%end\n\n")
        f.write("// Add more hooks below based on analysis\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--strings', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    
    generate_tweak(args.strings, args.output)
