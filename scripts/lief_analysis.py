import lief
import os
import sys

def extract_classnames(binary):
    if not binary:
        raise ValueError("无法加载二进制文件，binary 为 None。")
    class_names = []
    for section in binary.sections:
        if section.name.startswith('__objc_classlist'):
            data = section.content
            class_names += extract_classnames_from_data(data)
    return class_names

def extract_classnames_from_data(data):
    class_names = []
    # 假设数据中是以某种方式存储的类名，具体解析方式要根据具体的二进制结构决定
    # 这里是一个占位符解析示例
    for i in range(0, len(data), 4):
        class_name = data[i:i+4].decode('utf-8', errors='ignore')
        if class_name:
            class_names.append(class_name)
    return class_names

def analyze_binary(binary_path):
    try:
        binary = lief.parse(binary_path)
        if not binary:
            raise ValueError(f"无法解析文件 {binary_path}，返回的 binary 为 None。")
        return extract_classnames(binary)
    except Exception as e:
        print(f"分析文件 {binary_path} 时发生错误: {e}")
        return []

def main():
    if len(sys.argv) != 2:
        print("使用方法: python lief_analysis.py <binary_file>")
        sys.exit(1)

    binary_file = sys.argv[1]
    if not os.path.exists(binary_file):
        print(f"文件 {binary_file} 不存在！")
        sys.exit(1)

    print(f"开始分析: {binary_file}")
    class_names = analyze_binary(binary_file)
    
    if class_names:
        print(f"提取到的类名: {class_names}")
    else:
        print("未能提取到任何类名")

if __name__ == '__main__':
    main()
