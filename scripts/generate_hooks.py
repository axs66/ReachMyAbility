import re

def parse_lief_export(lief_file):
    symbols = []
    with open(lief_file, 'r') as f:
        content = f.read()
    
    # 假设导入库、符号、函数等信息有特定的格式
    symbol_pattern = r"- \[([^\]]+)\]"
    matches = re.findall(symbol_pattern, content)
    
    symbols = [match.strip() for match in matches]
    return symbols

def generate_tweak(symbols, output_file):
    hooks = []
    for symbol in symbols:
        if symbol.startswith('_OBJC_CLASS_'):
            class_name = symbol.split('_')[-1]
            hooks.append(f"""
%hook {class_name}
    // Example hook for {class_name}
    NSLog(@"Hooked class: {class_name}");
%end
""")
        elif symbol.startswith('-'):
            method_name = symbol.split(' ')[-1]
            hooks.append(f"""
%hook {method_name}
    %orig;
    NSLog(@"Hooked method: {method_name}");
%end
""")
    
    with open(output_file, 'w') as f:
        f.writelines(hooks)

if __name__ == '__main__':
    lief_file = 'output/raw/lief_export.txt'
    output_file = 'output/src/Tweak.xm'
    symbols = parse_lief_export(lief_file)
    generate_tweak(symbols, output_file)
