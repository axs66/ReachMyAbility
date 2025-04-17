import re
import sys

def generate_hooks(symbol_file, output_file):
    with open(symbol_file, 'r') as infile:
        symbols = infile.readlines()

    # 假设解析类名和方法名
    hooks = []
    for symbol in symbols:
        # 识别类和方法
        if re.match(r"^(.*) (.*)$", symbol.strip()):
            class_name, method_name = symbol.strip().split(' ')
            hook_code = f"""
%hook {class_name}
    {method_name} {{
        %orig;
        NSLog(@"Hooked method: {method_name} in class {class_name}");
    }}
%end
"""
            hooks.append(hook_code)

    # 将生成的 hook 代码写入文件
    with open(output_file, 'w') as outfile:
        for hook in hooks:
            outfile.write(hook)

if __name__ == '__main__':
    symbol_file = sys.argv[1]
    output_file = sys.argv[2]
    generate_hooks(symbol_file, output_file)
