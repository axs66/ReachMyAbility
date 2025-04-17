#!/usr/bin/env python3
import re, os, argparse

parser = argparse.ArgumentParser()
parser.add_argument('--classlist', required=True, help='otool -s __TEXT __objc_classname 输出')
parser.add_argument('--methods', required=True, help='otool -s __TEXT __objc_methname 输出')
parser.add_argument('--headers',   required=False, help='class-dump 生成的 headers 目录')
parser.add_argument('--output',    required=True, help='输出 Tweak.xm 路径')
args = parser.parse_args()

# 1. 解析类名
classes = set()
for line in open(args.classlist):
    m = re.search(rb'_OBJC_CLASS_\\$_(.+)', line.encode('utf-8'))
    if m: classes.add(m.group(1).decode())

# 2. 解析方法名
methods = {}
for line in open(args.methods):
    sel = line.strip()
    # 简化：按第一个冒号分割类名与方法名，可更精细地从 headers 中读签名
    if sel.startswith(b'-[') and b']' in sel:
        text = sel.decode()
        cls, rest = text[2:].split(' ',1)
        methods.setdefault(cls, []).append(rest.rstrip(']'))

# 3. 可选：从 class-dump 头文件中加载完整签名（略）

# 4. 生成 Tweak.xm
os.makedirs(os.path.dirname(args.output), exist_ok=True)
with open(args.output, 'w') as f:
    f.write('// Auto-generated Tweak.xm\n\n')
    for cls in sorted(classes):
        if cls not in methods: continue
        f.write(f'%hook {cls}\n')
        for m in methods[cls]:
            # 默认 void 返回，id 或参数需要手动修正
            f.write(f'- (void){m} {{\n    %orig;\n    NSLog(@"[Tweak] {cls} {m}");\n}}\n')
        f.write('%end\n\n')
print(f'✅ Hooks generated at {args.output}')
