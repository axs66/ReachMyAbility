import subprocess
import sys

def demangle_symbol(symbol):
    """使用 swift-demangle 工具解码 Swift 符号"""
    result = subprocess.run(['swift-demangle', symbol], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode('utf-8').strip()

def main(input_file, output_file):
    with open(input_file, 'r') as infile:
        symbols = infile.readlines()

    with open(output_file, 'w') as outfile:
        for symbol in symbols:
            if symbol.startswith('_Tt'):  # Swift 编译符号
                demangled = demangle_symbol(symbol.strip())
                outfile.write(f"{demangled}\n")
            else:
                outfile.write(symbol)  # 对于非 Swift 符号，不做处理

if __name__ == '__main__':
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    main(input_file, output_file)
