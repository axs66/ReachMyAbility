#!/usr/bin/env python3
import argparse
import os

def generate_tweak(symbols_file, output_path):
    os.makedirs(output_path, exist_ok=True)
    with open(symbols_file, 'r') as f:
        symbols = f.read()
    
    with open(os.path.join(output_path, "Tweak.xm"), 'w') as f:
        f.write("// Auto-generated Tweak.xm (Mach-O compatible)\n\n")
        f.write("#import \"WechatPushMsgPage.h\"\n\n")
        
        if '_OBJC_CLASS_$_' in symbols:
            f.write("%hook ClassName // Replace with actual class name\n")
            f.write("{\n")
            f.write("    %orig;\n    NSLog(@\"[WechatPushMsgPage] Hooked method\");\n")
            f.write("}\n")
            f.write("%end\n\n")
        
        f.write("/* \n")
        f.write("Suggested hooks based on symbols:\n")
        for line in symbols.split('\n'):
            if '_OBJC_CLASS_$_' in line:
                class_name = line.split('_OBJC_CLASS_$_')[-1].strip()
                f.write(f"%hook {class_name}\n// Add methods here\n%end\n\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--strings', required=True, help='Path to symbols file')
    parser.add_argument('--output', required=True, help='Output directory')
    args = parser.parse_args()
    
    generate_tweak(args.strings, args.output)
