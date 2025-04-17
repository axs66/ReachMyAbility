#!/usr/bin/env python3
import subprocess
import sys

def main():
    if len(sys.argv) != 3:
        print("Usage: demangle_swift.py <input_symbols.txt> <output_demangled.txt>")
        sys.exit(1)

    infile, outfile = sys.argv[1], sys.argv[2]

    with open(infile, 'r') as fin, open(outfile, 'w') as fout:
        for line in fin:
            symbol = line.strip()
            if symbol.startswith('_Tt'):
                result = subprocess.run(
                    ['swift-demangle', symbol],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL
                )
                fout.write(result.stdout.decode('utf-8') + "\n")
            else:
                fout.write(symbol + "\n")

    print("✅ Swift 符号 demangle 完成，结果在:", outfile)

if __name__ == "__main__":
    main()
