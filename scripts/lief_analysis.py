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

    f.write("\nLinked Libraries:\n")
    for command in binary.commands:
        if isinstance(command, lief.MachO.DylibCommand):
            f.write(f"  {command.name}\n")

    f.write("\nExported Functions:\n")
    for symbol in binary.exported_functions:
        f.write(f"  {symbol}\n")
