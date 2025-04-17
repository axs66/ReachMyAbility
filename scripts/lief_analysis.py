#!/usr/bin/env python3
import lief
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--dylib", required=True, help="Path to dylib")
parser.add_argument("--output", required=True, help="Path to output text file")
args = parser.parse_args()

binary = lief.parse(args.dylib)

with open(args.output, "w") as f:
    f.write(f"Architecture: {binary.header.cpu_type.name}\n")
    f.write("Imported Libraries:\n")
    for lib in binary.imported_libraries:
        f.write(f"  {lib}\n")

    f.write("\nExported Functions:\n")
    for symbol in binary.exported_functions:
        f.write(f"  {symbol}\n")
