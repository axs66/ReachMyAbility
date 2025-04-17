# scripts/generate_plugin_h.py

import sys
import os

output_path = sys.argv[1] if len(sys.argv) > 1 else "output/src/Plugin.h"

plugin_h_content = '''\
#ifndef PLUGIN_H
#define PLUGIN_H

// 插件相关声明，可根据实际情况扩展

#endif /* PLUGIN_H */
'''

with open(output_path, 'w') as f:
    f.write(plugin_h_content)

print(f"✅ Plugin.h 已生成: {output_path}")
