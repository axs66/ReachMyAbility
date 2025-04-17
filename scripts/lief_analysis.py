import lief
import sys
import os

def extract_classnames(binary):
    classnames = []
    for section in binary.sections:
        if "__objc_classname" in section.name:
            data = section.content
            string = bytes(data).split(b'\x00')
            for s in string:
                try:
                    decoded = s.decode("utf-8")
                    if decoded:
                        classnames.append(decoded)
                except:
                    continue
    return classnames

def extract_exported_symbols(binary):
    exports = []
    for symbol in binary.exported_symbols:
        exports.append(symbol.name)
    return exports

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 lief_analysis.py <dylib_path>")
        sys.exit(1)

    dylib_path = sys.argv[1]
    output_dir = "output/raw"
    os.makedirs(output_dir, exist_ok=True)

    try:
        binary = lief.parse(dylib_path)
    except Exception as e:
        print(f"❌ Failed to parse {dylib_path}: {e}")
        sys.exit(1)

    result = []
    result.append(f"📦 File: {dylib_path}")
    result.append("\n🔍 ObjC Class Names:")
    result += extract_classnames(binary)

    result.append("\n🔍 Exported Symbols:")
    result += extract_exported_symbols(binary)

    base_name = os.path.basename(dylib_path).replace(".dylib", "")
    output_file = os.path.join(output_dir, f"{base_name}_lief.txt")

    with open(output_file, "w") as f:
        f.write("\n".join(result))

    print(f"✅ Analysis result saved to: {output_file}")

if __name__ == "__main__":
    main()
