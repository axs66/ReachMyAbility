#!/bin/bash

# 传入 .deb 文件路径
deb_file="$1"

# 创建工作目录
work_dir="work"
output_raw="output/raw"
output_src="output/src"

mkdir -p "$work_dir"
mkdir -p "$output_raw"
mkdir -p "$output_src"

echo "🎯 开始解包 .deb..."
# 解包 .deb 文件
dpkg-deb -x "$deb_file" "$work_dir"

echo "✅ .deb 提取完成：$work_dir"

echo "🔍 分析 dylib..."
# 深度分析 dylib 文件
find "$work_dir" -type f -name "*.dylib" | while read dylib_file; do
  echo "分析文件: $dylib_file"
  
  # 使用 jtool 进行分析
  jtool -L "$dylib_file" >> "$output_raw/dylib_analysis.txt"
done

echo "✅ Dylib 深度分析完成，结果在: $output_raw"

echo "📑 提取 ObjC 类名／方法..."
# 提取 ObjC 类名和方法 (仅为示例，可根据需求进一步优化)
find "$work_dir" -type f -name "*.dylib" | while read dylib_file; do
  echo "分析文件: $dylib_file"
  
  # 使用 jtool 提取类名
  jtool -objc -l "$dylib_file" >> "$output_raw/objc_classes.txt"
done

echo "✅ ObjC 类名/方法提取完成，结果在: $output_raw"

# 生成源代码文件
echo "🎯 生成 Makefile 和 Tweak.xm..."

# 创建 Makefile
cat <<EOL > "$output_src/Makefile"
ARCHS = arm64
TARGET = iphone:latest:13.0

include \$(THEOS)/makefiles/common.mk

TWEAK_NAME = Plugin

Plugin_FILES = Tweak.xm
Plugin_CFLAGS = -fobjc-arc

include \$(THEOS_MAKE_PATH)/tweak.mk
EOL

# 创建 Plugin.h
cat <<EOL > "$output_src/Plugin.h"
// Auto-generated header
#import <Foundation/Foundation.h>

@interface OS_dispatch_queue : NSObject
@end

@interface _TtCs12_SwiftObject : NSObject
@end
EOL

# 创建 Tweak.xm
cat <<EOL > "$output_src/Tweak.xm"
// Auto-generated Tweak.xm

%hook /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
    %orig;
    NSLog(@"[Tweak] Hooked /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
%end

%hook /System/Library/Frameworks/Foundation.framework/Foundation
    %orig;
    NSLog(@"[Tweak] Hooked /System/Library/Frameworks/Foundation.framework/Foundation");
%end

%hook /usr/lib/libSystem.B.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/libSystem.B.dylib");
%end

%hook /usr/lib/libc++.1.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/libc++.1.dylib");
%end

%hook /usr/lib/libobjc.A.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/libobjc.A.dylib");
%end

%hook /usr/lib/swift/libswiftCore.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftCore.dylib");
%end

%hook /usr/lib/swift/libswiftCoreFoundation.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftCoreFoundation.dylib");
%end

%hook /usr/lib/swift/libswiftCoreGraphics.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftCoreGraphics.dylib");
%end

%hook /usr/lib/swift/libswiftCoreImage.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftCoreImage.dylib");
%end

%hook /usr/lib/swift/libswiftDarwin.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftDarwin.dylib");
%end

%hook /usr/lib/swift/libswiftDataDetection.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftDataDetection.dylib");
%end

%hook /usr/lib/swift/libswiftDispatch.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftDispatch.dylib");
%end

%hook /usr/lib/swift/libswiftFileProvider.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftFileProvider.dylib");
%end

%hook /usr/lib/swift/libswiftFoundation.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftFoundation.dylib");
%end

%hook /usr/lib/swift/libswiftMetal.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftMetal.dylib");
%end

%hook /usr/lib/swift/libswiftObjectiveC.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftObjectiveC.dylib");
%end

%hook /usr/lib/swift/libswiftQuartzCore.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftQuartzCore.dylib");
%end

%hook /usr/lib/swift/libswiftUIKit.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftUIKit.dylib");
%end

%hook 0x0000010ba0:
    %orig;
    NSLog(@"[Tweak] Hooked 0x0000010ba0:");
%end

%hook @rpath/Orion.framework/Orion
    %orig;
    NSLog(@"[Tweak] Hooked @rpath/Orion.framework/Orion");
%end

%hook @rpath/WechatPushMsgPage.dylib
    %orig;
    NSLog(@"[Tweak] Hooked @rpath/WechatPushMsgPage.dylib");
%end

%hook OS_dispatch_queue
    %orig;
    NSLog(@"[Tweak] Hooked OS_dispatch_queue");
%end

%hook _TtCs12_SwiftObject
    %orig;
    NSLog(@"[Tweak] Hooked _TtCs12_SwiftObject");
%end
EOL

echo "✅ 源代码生成完成：Makefile, Plugin.h, Tweak.xm"
