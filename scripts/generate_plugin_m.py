import os

def generate_plugin_m(src_dir, lief_output_file):
    # 打开 Lief 输出文件读取数据
    with open(lief_output_file, 'r') as f:
        lief_data = f.readlines()

    # 创建 Plugin.m 文件
    plugin_m_file_path = os.path.join(src_dir, 'Plugin.m')

    with open(plugin_m_file_path, 'w') as plugin_m_file:
        # 生成 Plugin.m 文件的基本框架
        plugin_m_file.write("""#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// 插件的核心类
@interface Plugin : NSObject
- (void)hookMethods;
@end

@implementation Plugin

- (void)hookMethods {
    // 在这里根据分析结果生成代码
""")

        # 根据 lief_output.txt 数据生成代码块（这里可以根据实际需求调整）
        for line in lief_data:
            if "function" in line:  # 例如，假设每行包含 "function" 关键字表示一个函数
                function_name = line.split()[-1]  # 假设函数名在行的末尾
                plugin_m_file.write(f"""    // Hook {function_name}
    [self hookFunction:@"{function_name}"];
""")
        
        # 结束代码
        plugin_m_file.write("""
}

- (void)hookFunction:(NSString *)functionName {
    // 这里可以使用 Frida 等工具进行实际 hook 的操作
    NSLog(@"Hooking function: %@", functionName);
}

@end
""")
    
    print(f"✅ Plugin.m 文件已生成: {plugin_m_file_path}")

if __name__ == "__main__":
    # 使用命令行参数提供 src_dir 和 lief_output.txt 文件路径
    src_dir = "output/src"  # 根据实际路径修改
    lief_output_file = "output/raw/lief_output.txt"  # 根据实际路径修改
    
    # 生成 Plugin.m
    generate_plugin_m(src_dir, lief_output_file)
